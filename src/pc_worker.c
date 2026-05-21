#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>

#include "pc_worker.h"
#include "log_parser.h"
#include "event_classifier.h"
#include "worker.h"   /* LogFmt, FMT_* */

/* =========================================================================
 * Deteção de formato (igual à Fase 1)
 * ========================================================================= */
static LogFmt detect_fmt(const char *line)
{
    if (!line || !line[0]) return FMT_UNKNOWN;
    if (line[0] == '{')    return FMT_JSON;
    if (isdigit((unsigned char)line[0]) && isdigit((unsigned char)line[1]) &&
        isdigit((unsigned char)line[2]) && isdigit((unsigned char)line[3]) &&
        line[4] == '/')
        return FMT_NGINX;
    if (line[0] == '<') return FMT_SYSLOG;
    const char *months[] = {"Jan","Feb","Mar","Apr","May","Jun",
                             "Jul","Aug","Sep","Oct","Nov","Dec"};
    for (int i = 0; i < 12; i++)
        if (strncmp(line, months[i], 3) == 0) return FMT_SYSLOG;
    if (isdigit((unsigned char)line[0])) return FMT_APACHE;
    return FMT_UNKNOWN;
}

/* =========================================================================
 * PRODUTOR — lê ficheiros linha a linha e insere no buffer
 * ========================================================================= */
void *producer_run(void *arg)
{
    ProducerArg *pa = (ProducerArg *)arg;
    pa->lines_produced = 0;

    /* Atualizar estado no dashboard */
    pthread_mutex_lock(pa->status_mutex);
    pa->status->state = STATE_WORKING;
    pthread_mutex_unlock(pa->status_mutex);

    char rbuf[8192];
    char line[MAX_LINE_LENGTH];
    int  lpos;

    /* Processar todos os ficheiros atribuídos a este produtor */
    for (int i = 0; i < pa->fl->count; i++) {
        if (pa->assignment[i] != pa->producer_id) continue;

        int fd = open(pa->fl->paths[i], O_RDONLY);
        if (fd < 0) { perror("open"); continue; }

        lpos = 0;
        ssize_t nread;

        while (1) {
            nread = read(fd, rbuf, sizeof(rbuf));
            if (nread < 0) {
                if (errno == EINTR) continue;
                perror("read"); break;
            }
            if (nread == 0) {
                /* EOF: linha pendente */
                if (lpos > 0) {
                    line[lpos] = '\0';
                    bb_put(pa->bb, line, pa->producer_id);
                    pa->lines_produced++;

                    pthread_mutex_lock(pa->status_mutex);
                    pa->status->lines_processed = pa->lines_produced;
                    if (pa->status->total_lines > 0)
                        pa->status->progress_pct =
                            (float)pa->lines_produced /
                            pa->status->total_lines * 100.0f;
                    pthread_mutex_unlock(pa->status_mutex);
                }
                break;
            }

            for (ssize_t j = 0; j < nread; j++) {
                char c = rbuf[j];
                if (c == '\n' || c == '\r') {
                    if (lpos > 0) {
                        line[lpos] = '\0';
                        lpos = 0;
                        bb_put(pa->bb, line, pa->producer_id);
                        pa->lines_produced++;

                        /* Atualizar progresso a cada 500 linhas */
                        if (pa->lines_produced % 500 == 0) {
                            pthread_mutex_lock(pa->status_mutex);
                            pa->status->lines_processed = pa->lines_produced;
                            if (pa->status->total_lines > 0)
                                pa->status->progress_pct =
                                    (float)pa->lines_produced /
                                    pa->status->total_lines * 100.0f;
                            pthread_mutex_unlock(pa->status_mutex);
                        }
                    }
                } else if (lpos < MAX_LINE_LENGTH - 1) {
                    line[lpos++] = c;
                }
            }
        }

        close(fd);
    }

    /* Marcar produtor como concluído */
    pthread_mutex_lock(pa->status_mutex);
    pa->status->state        = STATE_DONE;
    pa->status->progress_pct = 100.0f;
    pthread_mutex_unlock(pa->status_mutex);

    return NULL;
}

/* =========================================================================
 * Deteção de brute-force
 * Retorna 1 se este IP ultrapassou o limiar na janela de tempo
 * ========================================================================= */
static int check_brute_force(ConsumerArg *ca, const char *ip, time_t ts)
{
    if (!ip || !ip[0]) return 0;

    /* Procurar entrada existente */
    for (int i = 0; i < ca->bf_used; i++) {
        if (strcmp(ca->bf_table[i].ip, ip) == 0) {
            BruteForceEntry *e = &ca->bf_table[i];

            /* Resetar janela se expirou */
            if (ts - e->window_start > BRUTE_FORCE_WINDOW_SEC) {
                e->window_start = ts;
                e->fail_count   = 1;
                return 0;
            }

            e->fail_count++;
            if (e->fail_count == BRUTE_FORCE_THRESHOLD) {
                ca->brute_alerts++;
                return 1;
            }
            return 0;
        }
    }

    /* IP novo */
    if (ca->bf_used < BF_TABLE_SIZE) {
        BruteForceEntry *e = &ca->bf_table[ca->bf_used++];
        snprintf(e->ip, sizeof(e->ip), "%s", ip);
        e->fail_count          = 1;
        e->window_start        = ts;
    }
    return 0;
}

static void ip_add(ConsumerArg *ca, const char *ip)
{
    if (!ip || !ip[0]) return;
    for (int i = 0; i < ca->ip_used; i++) {
        if (strcmp(ca->ip_table[i].ip, ip) == 0) {
            ca->ip_table[i].count++;
            return;
        }
    }
    if (ca->ip_used < PC_IP_TABLE) {
        snprintf(ca->ip_table[ca->ip_used].ip,
                 sizeof(ca->ip_table[ca->ip_used].ip), "%s", ip);
        ca->ip_table[ca->ip_used].count = 1;
        ca->ip_used++;
    }
}

static void ip_top10(ConsumerArg *ca)
{
    int used[PC_IP_TABLE];
    memset(used, 0, sizeof(used));

    for (int rank = 0; rank < TOP_IPS; rank++) {
        int best = -1;
        for (int i = 0; i < ca->ip_used; i++) {
            if (used[i]) continue;
            if (best < 0 || ca->ip_table[i].count > ca->ip_table[best].count)
                best = i;
        }
        if (best < 0) break;
        used[best] = 1;
        strncpy(ca->result.top_ips[rank], ca->ip_table[best].ip, MAX_IP_LEN - 1);
        ca->result.top_ips[rank][MAX_IP_LEN - 1] = '\0';
        ca->result.top_ip_counts[rank] = ca->ip_table[best].count;
    }
    if (ca->result.top_ips[0][0]) {
        strncpy(ca->result.top_ip, ca->result.top_ips[0], MAX_IP_LEN - 1);
        ca->result.top_ip[MAX_IP_LEN - 1] = '\0';
        ca->result.top_ip_count = ca->result.top_ip_counts[0];
    }
}

/* =========================================================================
 * Processar uma LogLine já retirada do buffer
 * ========================================================================= */
static void consume_line(ConsumerArg *ca, const char *line)
{
    LogFmt fmt = detect_fmt(line);
    if (fmt == FMT_UNKNOWN) return;

    ClassifiedEvent ev;
    int types = 0;
    const char *ip = NULL;
    int status_code = 0;
    time_t ts = 0;

    switch (fmt) {
        case FMT_APACHE: {
            ApacheLogEntry e;
            if (parse_apache_log(line, &e) != 0) return;
            types       = classify_apache_event(&e, &ev);
            ip          = e.ip;
            status_code = e.status_code;
            ts          = mktime(&e.timestamp);
            ca->result.lines_parsed++;
            if (e.status_code >= 400 && e.status_code < 500) ca->result.errors_4xx++;
            if (e.status_code >= 500 && e.status_code < 600) ca->result.errors_5xx++;
            break;
        }
        case FMT_JSON: {
            JSONLogEntry e;
            if (parse_json_log(line, &e) != 0) return;
            types = classify_json_event(&e, &ev);
            ip    = e.ip;
            ts    = mktime(&e.timestamp);
            ca->result.lines_parsed++;
            break;
        }
        case FMT_SYSLOG: {
            SyslogEntry e;
            if (parse_syslog(line, &e) != 0) return;
            types = classify_syslog_event(&e, &ev);
            ts    = mktime(&e.timestamp);
            ca->result.lines_parsed++;

            /* Deteção de brute-force em syslog */
            if (e.is_auth_failure) {
                /* Extrair IP da mensagem */
                static char syslog_ip[MAX_IP_LEN];
                syslog_ip[0] = '\0';
                const char *from = strstr(e.message, "from ");
                if (from) {
                    from += 5;
                    int k = 0;
                    while (*from && *from != ' ' && k < MAX_IP_LEN - 1)
                        syslog_ip[k++] = *from++;
                    syslog_ip[k] = '\0';
                }
                ip = syslog_ip[0] ? syslog_ip : NULL;
            }
            break;
        }
        case FMT_NGINX: {
            NginxErrorEntry e;
            if (parse_nginx_error(line, &e) != 0) return;
            types       = classify_nginx_event(&e, &ev);
            ip          = e.client_ip;
            status_code = (e.level >= NGINX_ERROR) ? 502 : 0;
            ts          = mktime(&e.timestamp);
            ca->result.lines_parsed++;
            break;
        }
        default: return;
    }

    if (types == 0) return;
    if (!event_matches_mode(&ev, ca->cfg->mode)) return;

    ca->result.lines_total++;
    ip_add(ca, ip);

    /* Contadores de severidade */
    switch (ev.severity) {
        case 0: case 1: ca->result.count_info++;     break;
        case 2:         ca->result.count_warn++;     break;
        case 3:         ca->result.count_error++;    break;
        default:        ca->result.count_critical++; break;
    }
    if (types & EVENT_SECURITY)    ca->result.security_events++;
    if (types & EVENT_PERFORMANCE) ca->result.perf_events++;

    /* -------------------------------------------------------------------
     * Deteção de padrões (Req 2-C obrigatório)
     * ------------------------------------------------------------------- */

    /* 1. Brute-force: falhas de autenticação do mesmo IP */
    if ((types & EVENT_SECURITY) && ev.severity >= 3 && ip && ts > 0)
        check_brute_force(ca, ip, ts);

    /* 2. Erros 5xx consecutivos */
    if (status_code >= 500 && status_code < 600) {
        ca->consec_5xx++;
        if (ca->consec_5xx >= CONSEC_5XX_THRESHOLD) {
            ca->consec_alerts++;
            ca->consec_5xx = 0;   /* reset após alerta */
        }
    } else {
        ca->consec_5xx = 0;       /* resetar se não for 5xx */
    }
}

/* =========================================================================
 * CONSUMIDOR — retira linhas do buffer e processa
 * ========================================================================= */
void *consumer_run(void *arg)
{
    ConsumerArg *ca = (ConsumerArg *)arg;
    memset(&ca->result, 0, sizeof(ca->result));
    ca->result.pid     = (pid_t)ca->consumer_id;
    ca->bf_used        = 0;
    ca->consec_5xx     = 0;
    ca->brute_alerts   = 0;
    ca->consec_alerts  = 0;
    ca->ip_used        = 0;

    LogLine entry;

    /* Loop principal: retirar entradas do buffer até receber sinal de fim */
    while (bb_get(ca->bb, &entry) == 0) {
        consume_line(ca, entry.line);
    }

    ip_top10(ca);

    return NULL;
}

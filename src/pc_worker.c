#define _GNU_SOURCE                               /* Ativa extensões GNU (getenv, useconds_t). */
#include <stdio.h>                                /* perror, snprintf. */
#include <stdlib.h>                               /* getenv, atol. */
#include <string.h>                               /* memset, strncpy, strcmp, strstr, strncmp. */
#include <unistd.h>                               /* read, close, usleep. */
#include <fcntl.h>                                /* open, O_RDONLY. */
#include <errno.h>                                /* errno, EINTR. */
#include <ctype.h>                                /* isdigit. */
#include <time.h>                                 /* mktime, time_t. */

#include "../include/pc_worker.h"                 /* ProducerArg, ConsumerArg, protótipos. */
#include "../include/log_parser.h"                /* Parsers dos formatos de log. */
#include "../include/event_classifier.h"          /* Classificação de eventos. */
#include "../include/worker.h"                    /* LogFmt, FMT_*. */

#define DEFAULT_DEMO_DELAY_US 50000               /* Atraso opcional p/ visualizar o dashboard. */

/* Lê LOG_ANALYZER_SLOW_US para abrandar artificialmente os produtores
 * (apenas para demonstração do dashboard em tempo real). */
static useconds_t demo_delay_us(void)
{
    const char *env = getenv("LOG_ANALYZER_SLOW_US");
    long delay = env ? atol(env) : DEFAULT_DEMO_DELAY_US;
    return delay > 0 ? (useconds_t)delay : 0;
}

/* ==========================================================================
 * Deteção de formato (idêntica às outras fases)
 * ========================================================================== */
static LogFmt detect_fmt(const char *line)
{
    if (!line || !line[0]) return FMT_UNKNOWN;    /* Vazia/NULL: desconhecido. */
    if (line[0] == '{')    return FMT_JSON;       /* '{': JSON. */
    if (isdigit((unsigned char)line[0]) && isdigit((unsigned char)line[1]) &&
        isdigit((unsigned char)line[2]) && isdigit((unsigned char)line[3]) &&
        line[4] == '/')                           /* "YYYY/": Nginx. */
        return FMT_NGINX;
    if (line[0] == '<') return FMT_SYSLOG;         /* '<prio>': Syslog. */
    const char *months[] = {"Jan","Feb","Mar","Apr","May","Jun",
                             "Jul","Aug","Sep","Oct","Nov","Dec"};
    for (int i = 0; i < 12; i++)
        if (strncmp(line, months[i], 3) == 0) return FMT_SYSLOG;   /* Mês: Syslog. */
    if (isdigit((unsigned char)line[0])) return FMT_APACHE;        /* Dígito: Apache. */
    return FMT_UNKNOWN;
}

/* ==========================================================================
 * REQUISITO 2-C — PRODUTOR: lê ficheiros linha a linha e insere no buffer
 *
 * Cada thread produtora processa os ficheiros que lhe foram atribuídos,
 * reconstrói as linhas a partir de blocos lidos com read() e insere cada
 * linha no bounded buffer com bb_put() (que bloqueia se o buffer encher).
 * ========================================================================== */
void *producer_run(void *arg)
{
    ProducerArg *pa = (ProducerArg *)arg;         /* Converte o argumento genérico. */
    pa->lines_produced = 0;                       /* Contador local de linhas produzidas. */

    /* Marca o produtor como "a trabalhar" no dashboard (sob mutex). */
    if (pthread_mutex_lock(pa->status_mutex) != 0) perror("pthread_mutex_lock");
    pa->status->state = STATE_WORKING;
    if (pthread_mutex_unlock(pa->status_mutex) != 0) perror("pthread_mutex_unlock");

    char rbuf[8192];                              /* Buffer de leitura (8 KB). */
    char line[MAX_LINE_LENGTH];                   /* Linha em construção. */
    int  lpos = 0;                                /* Posição atual na linha. */

    /* Percorre todos os ficheiros atribuídos a este produtor. */
    for (int i = 0; i < pa->fl->count; i++) {
        if (pa->assignment[i] != pa->producer_id) continue;   /* Não é meu: salta. */

        int fd = open(pa->fl->paths[i], O_RDONLY);            /* Abre o ficheiro. */
        if (fd < 0) { perror("open"); continue; }             /* Erro: passa ao seguinte. */

        lpos = 0;                                 /* Reinicia a linha por ficheiro. */
        ssize_t nread;

        while (1) {
            nread = read(fd, rbuf, sizeof(rbuf)); /* Lê um bloco. */
            if (nread < 0) {
                if (errno == EINTR) continue;     /* Sinal: repete. */
                perror("read");
                break;
            }
            if (nread == 0) break;                /* EOF. */

            for (ssize_t j = 0; j < nread; j++) { /* Percorre o bloco byte a byte. */
                char c = rbuf[j];
                if (c == '\n' || c == '\r') {     /* Fim de linha? */
                    if (lpos > 0) {
                        line[lpos] = '\0';        /* Fecha a linha. */
                        lpos = 0;
                        bb_put(pa->bb, line, pa->producer_id);   /* INSERE no buffer. */
                        pa->lines_produced++;

                        /* Atualiza o progresso a cada 500 linhas (reduz contenção). */
                        if (pa->lines_produced % 500 == 0) {
                            if (pthread_mutex_lock(pa->status_mutex) == 0) {
                                pa->status->lines_processed = pa->lines_produced;
                                if (pa->status->total_lines > 0)
                                    pa->status->progress_pct =
                                        (float)pa->lines_produced /
                                        pa->status->total_lines * 100.0f;
                                pthread_mutex_unlock(pa->status_mutex);
                            }
                            useconds_t delay = demo_delay_us();   /* Atraso de demonstração. */
                            if (delay > 0)
                                usleep(delay);
                        }
                    }
                } else if (lpos < MAX_LINE_LENGTH - 1) {   /* Caráter normal: acumula. */
                    line[lpos++] = c;
                }
            }
        }

        /* Linha residual (ficheiro sem '\n' no fim): também é inserida. */
        if (lpos > 0) {
            line[lpos] = '\0';
            lpos = 0;
            bb_put(pa->bb, line, pa->producer_id);
            pa->lines_produced++;
        }

        close(fd);                                /* Fecha o ficheiro. */
    }

    /* Marca o produtor como concluído (100%) no dashboard. */
    if (pthread_mutex_lock(pa->status_mutex) == 0) {
        pa->status->lines_processed = pa->lines_produced;
        pa->status->state           = STATE_DONE;
        pa->status->progress_pct    = 100.0f;
        pthread_mutex_unlock(pa->status_mutex);
    }

    return NULL;
}

/* ==========================================================================
 * REQUISITO 2-C — Deteção de brute-force (5+ falhas/min do mesmo IP)
 *
 * Cada consumidor mantém uma tabela local de IPs com falhas de autenticação.
 * Conta as falhas dentro de uma janela deslizante de 60 s; ao atingir o
 * limiar (5) regista um alerta. A janela reinicia se expirar.
 * ========================================================================== */
static int check_brute_force(ConsumerArg *ca, const char *ip, time_t ts)
{
    if (!ip || !ip[0]) return 0;                  /* IP inválido: ignora. */

    /* Procura o IP na tabela local do consumidor. */
    for (int i = 0; i < ca->bf_used; i++) {
        if (strcmp(ca->bf_table[i].ip, ip) == 0) {
            BruteForceEntry *e = &ca->bf_table[i];

            /* Janela expirou? Reinicia a contagem. */
            if (ts - e->window_start > BRUTE_FORCE_WINDOW_SEC) {
                e->window_start = ts;
                e->fail_count   = 1;
                return 0;
            }

            e->fail_count++;                      /* Mais uma falha dentro da janela. */
            if (e->fail_count == BRUTE_FORCE_THRESHOLD) {   /* Atingiu o limiar? */
                ca->brute_alerts++;               /* Regista o alerta. */
                return 1;
            }
            return 0;
        }
    }

    /* IP ainda não registado: adiciona-o se houver espaço. */
    if (ca->bf_used < BF_TABLE_SIZE) {
        BruteForceEntry *e = &ca->bf_table[ca->bf_used++];
        snprintf(e->ip, sizeof(e->ip), "%s", ip); /* Copia o IP. */
        e->fail_count          = 1;               /* Primeira falha. */
        e->window_start        = ts;              /* Início da janela. */
    }
    return 0;
}

/* REQUISITO 2-C: adicionar/incrementar um IP na tabela de tráfego do consumidor. */
static void ip_add(ConsumerArg *ca, const char *ip)
{
    if (!ip || !ip[0]) return;                    /* Ignora IP inválido. */
    for (int i = 0; i < ca->ip_used; i++) {       /* Já existe? Incrementa. */
        if (strcmp(ca->ip_table[i].ip, ip) == 0) {
            ca->ip_table[i].count++;
            return;
        }
    }
    if (ca->ip_used < PC_IP_TABLE) {              /* Novo IP: insere se houver espaço. */
        snprintf(ca->ip_table[ca->ip_used].ip,
                 sizeof(ca->ip_table[ca->ip_used].ip), "%s", ip);
        ca->ip_table[ca->ip_used].count = 1;
        ca->ip_used++;
    }
}

/* REQUISITO 2-C: calcular o top-10 de IPs deste consumidor (seleção do máximo). */
static void ip_top10(ConsumerArg *ca)
{
    int used[PC_IP_TABLE];                        /* Marca os IPs já escolhidos. */
    memset(used, 0, sizeof(used));

    for (int rank = 0; rank < TOP_IPS; rank++) {  /* Para cada posição do top-10... */
        int best = -1;
        for (int i = 0; i < ca->ip_used; i++) {   /* Procura o mais frequente não usado. */
            if (used[i]) continue;
            if (best < 0 || ca->ip_table[i].count > ca->ip_table[best].count)
                best = i;
        }
        if (best < 0) break;                      /* Não há mais IPs. */
        used[best] = 1;
        strncpy(ca->result.top_ips[rank], ca->ip_table[best].ip, MAX_IP_LEN - 1);
        ca->result.top_ips[rank][MAX_IP_LEN - 1] = '\0';
        ca->result.top_ip_counts[rank] = ca->ip_table[best].count;
    }
    if (ca->result.top_ips[0][0]) {               /* Define o top_ip principal. */
        strncpy(ca->result.top_ip, ca->result.top_ips[0], MAX_IP_LEN - 1);
        ca->result.top_ip[MAX_IP_LEN - 1] = '\0';
        ca->result.top_ip_count = ca->result.top_ip_counts[0];
    }
}

/* ==========================================================================
 * REQUISITO 2-C — consume_line: classifica uma linha retirada do buffer
 *
 * É o "trabalho" do consumidor: parse → classificação → filtro de modo →
 * atualização de contadores → deteção de padrões (brute-force e 5xx).
 * ========================================================================== */
static void consume_line(ConsumerArg *ca, const char *line)
{
    LogFmt fmt = detect_fmt(line);                /* Deteta o formato. */
    if (fmt == FMT_UNKNOWN) return;

    ClassifiedEvent ev;
    int types = 0;                                /* Bitmask de tipos. */
    const char *ip = NULL;                        /* IP associado (se houver). */
    int status_code = 0;                          /* Código HTTP (para 5xx). */
    time_t ts = 0;                                /* Timestamp (para brute-force). */

    switch (fmt) {
        case FMT_APACHE: {                                       /* --- Apache --- */
            ApacheLogEntry e;
            if (parse_apache_log(line, &e) != 0) return;
            types       = classify_apache_event(&e, &ev);
            ip          = e.ip;
            status_code = e.status_code;
            ts          = mktime(&e.timestamp);                  /* Converte struct tm → time_t. */
            ca->result.lines_parsed++;
            if (e.status_code >= 400 && e.status_code < 500) ca->result.errors_4xx++;
            if (e.status_code >= 500 && e.status_code < 600) ca->result.errors_5xx++;
            break;
        }
        case FMT_JSON: {                                         /* --- JSON --- */
            JSONLogEntry e;
            if (parse_json_log(line, &e) != 0) return;
            types = classify_json_event(&e, &ev);
            ip    = e.ip;
            ts    = mktime(&e.timestamp);
            ca->result.lines_parsed++;
            break;
        }
        case FMT_SYSLOG: {                                       /* --- Syslog --- */
            SyslogEntry e;
            if (parse_syslog(line, &e) != 0) return;
            types = classify_syslog_event(&e, &ev);
            ts    = mktime(&e.timestamp);
            ca->result.lines_parsed++;

            /* Para brute-force: extrai o IP da mensagem ("... from 1.2.3.4 ..."). */
            if (e.is_auth_failure) {
                static char syslog_ip[MAX_IP_LEN];
                syslog_ip[0] = '\0';
                const char *from = strstr(e.message, "from ");
                if (from) {
                    from += 5;                    /* Salta "from ". */
                    int k = 0;
                    while (*from && *from != ' ' && k < MAX_IP_LEN - 1)
                        syslog_ip[k++] = *from++;
                    syslog_ip[k] = '\0';
                }
                ip = syslog_ip[0] ? syslog_ip : NULL;
            }
            break;
        }
        case FMT_NGINX: {                                        /* --- Nginx --- */
            NginxErrorEntry e;
            if (parse_nginx_error(line, &e) != 0) return;
            types       = classify_nginx_event(&e, &ev);
            ip          = e.client_ip;
            status_code = (e.level >= NGINX_ERROR) ? 502 : 0;    /* Erro Nginx ≈ 5xx. */
            ts          = mktime(&e.timestamp);
            ca->result.lines_parsed++;
            break;
        }
        default: return;
    }

    if (types == 0) return;                       /* Sem tipo: ignora. */
    if (!event_matches_mode(&ev, ca->cfg->mode)) return;   /* Filtro de modo. */

    ca->result.lines_total++;                     /* Conta o evento. */
    ip_add(ca, ip);                               /* Regista o IP para o top-10. */

    /* Contadores por severidade. */
    switch (ev.severity) {
        case 0: case 1: ca->result.count_info++;     break;
        case 2:         ca->result.count_warn++;     break;
        case 3:         ca->result.count_error++;    break;
        default:        ca->result.count_critical++; break;
    }
    if (types & EVENT_SECURITY)    ca->result.security_events++;
    if (types & EVENT_PERFORMANCE) ca->result.perf_events++;

    /* -------------------------------------------------------------------
     * Deteção de padrões obrigatória do Requisito 2-C
     * ------------------------------------------------------------------- */

    /* 1. Brute-force: falhas de segurança graves (severidade ≥ HIGH) do mesmo IP. */
    if ((types & EVENT_SECURITY) && ev.severity >= 3 && ip && ts > 0)
        check_brute_force(ca, ip, ts);

    /* 2. Erros 5xx consecutivos: conta seguidos e alerta ao atingir o limiar. */
    if (status_code >= 500 && status_code < 600) {
        ca->consec_5xx++;
        if (ca->consec_5xx >= CONSEC_5XX_THRESHOLD) {
            ca->consec_alerts++;
            ca->consec_5xx = 0;                   /* Reinicia após o alerta. */
        }
    } else {
        ca->consec_5xx = 0;                       /* Quebra a sequência de 5xx. */
    }
}

/* ==========================================================================
 * REQUISITO 2-C — CONSUMIDOR: retira linhas do buffer e processa-as
 *
 * Loop simples: bb_get() bloqueia até haver uma linha; quando devolve -1
 * (sinal de fim, propagado em cadeia), o consumidor sai e calcula o top-10.
 * ========================================================================== */
void *consumer_run(void *arg)
{
    ConsumerArg *ca = (ConsumerArg *)arg;         /* Converte o argumento. */
    memset(&ca->result, 0, sizeof(ca->result));   /* Zera o resultado. */
    ca->result.pid     = (pid_t)ca->consumer_id;  /* ID do consumidor. */
    ca->bf_used        = 0;                       /* Tabela de brute-force vazia. */
    ca->consec_5xx     = 0;                       /* Sem 5xx consecutivos ainda. */
    ca->brute_alerts   = 0;                       /* Sem alertas ainda. */
    ca->consec_alerts  = 0;
    ca->ip_used        = 0;                       /* Tabela de IPs vazia. */

    LogLine entry;                                /* Linha retirada do buffer. */

    /* Consome até ao sinal de fim (bb_get devolve -1). */
    while (bb_get(ca->bb, &entry) == 0) {
        consume_line(ca, entry.line);
    }

    ip_top10(ca);                                 /* Calcula o top-10 de IPs no fim. */

    return NULL;
}
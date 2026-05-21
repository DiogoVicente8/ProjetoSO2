#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
 
#include "thread_worker.h"
#include "log_parser.h"
#include "event_classifier.h"
#include "ipc.h"
#include "files.h"
 
/* =========================================================================
 * Tabela de IPs local à thread (sem partilha — cada thread tem a sua)
 * ========================================================================= */
typedef struct {
    ThreadIPEntry e[THREAD_IP_TABLE];
    int           used;
} LocalIPTable;
 
static void ip_add(LocalIPTable *t, const char *ip)
{
    if (!ip || !ip[0]) return;
    for (int i = 0; i < t->used; i++) {
        if (strcmp(t->e[i].ip, ip) == 0) { t->e[i].count++; return; }
    }
    if (t->used < THREAD_IP_TABLE) {
        strncpy(t->e[t->used].ip, ip, MAX_IP_LEN - 1);
        t->e[t->used].ip[MAX_IP_LEN - 1] = '\0';
        t->e[t->used].count = 1;
        t->used++;
    }
}
 
static void ip_top(const LocalIPTable *t, char *out_ip, long *out_count)
{
    *out_count = 0;
    out_ip[0]  = '\0';
    for (int i = 0; i < t->used; i++) {
        if (t->e[i].count > *out_count) {
            *out_count = t->e[i].count;
            strncpy(out_ip, t->e[i].ip, MAX_IP_LEN - 1);
            out_ip[MAX_IP_LEN - 1] = '\0';
        }
    }
}

static void ip_top10(const LocalIPTable *t, WorkerResult *res)
{
    int used[THREAD_IP_TABLE];
    memset(used, 0, sizeof(used));

    for (int rank = 0; rank < TOP_IPS; rank++) {
        int best = -1;
        for (int i = 0; i < t->used; i++) {
            if (used[i]) continue;
            if (best < 0 || t->e[i].count > t->e[best].count)
                best = i;
        }
        if (best < 0) break;
        used[best] = 1;
        strncpy(res->top_ips[rank], t->e[best].ip, MAX_IP_LEN - 1);
        res->top_ips[rank][MAX_IP_LEN - 1] = '\0';
        res->top_ip_counts[rank] = t->e[best].count;
    }
    if (res->top_ips[0][0]) {
        strncpy(res->top_ip, res->top_ips[0], MAX_IP_LEN - 1);
        res->top_ip[MAX_IP_LEN - 1] = '\0';
        res->top_ip_count = res->top_ip_counts[0];
    } else {
        ip_top(t, res->top_ip, &res->top_ip_count);
    }
}
 
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
    if (line[0] == '<')    return FMT_SYSLOG;
    const char *months[] = {"Jan","Feb","Mar","Apr","May","Jun",
                             "Jul","Aug","Sep","Oct","Nov","Dec"};
    for (int i = 0; i < 12; i++)
        if (strncmp(line, months[i], 3) == 0) return FMT_SYSLOG;
    if (isdigit((unsigned char)line[0])) return FMT_APACHE;
    return FMT_UNKNOWN;
}
 
/* =========================================================================
 * Processar uma linha e atualizar resultado
 * ========================================================================= */
static void process_line(const char *line, WorkerResult *res,
                          LocalIPTable *ipt, const Config *cfg)
{
    (void)cfg; /* reservado para filtro por modo no futuro */
 
    LogFmt fmt = detect_fmt(line);
    if (fmt == FMT_UNKNOWN) return;
 
    ClassifiedEvent ev;
    int types = 0;
 
    switch (fmt) {
        case FMT_APACHE: {
            ApacheLogEntry e;
            if (parse_apache_log(line, &e) != 0) return;
            types = classify_apache_event(&e, &ev);
            res->lines_parsed++;
            ip_add(ipt, e.ip);
            if (e.status_code >= 400 && e.status_code < 500) res->errors_4xx++;
            if (e.status_code >= 500 && e.status_code < 600) res->errors_5xx++;
            break;
        }
        case FMT_JSON: {
            JSONLogEntry e;
            if (parse_json_log(line, &e) != 0) return;
            types = classify_json_event(&e, &ev);
            res->lines_parsed++;
            ip_add(ipt, e.ip);
            break;
        }
        case FMT_SYSLOG: {
            SyslogEntry e;
            if (parse_syslog(line, &e) != 0) return;
            types = classify_syslog_event(&e, &ev);
            res->lines_parsed++;
            break;
        }
        case FMT_NGINX: {
            NginxErrorEntry e;
            if (parse_nginx_error(line, &e) != 0) return;
            types = classify_nginx_event(&e, &ev);
            res->lines_parsed++;
            ip_add(ipt, e.client_ip);
            break;
        }
        default: return;
    }
 
    if (types == 0) return;
    if (!event_matches_mode(&ev, cfg->mode)) return;
 
    /* Contadores de severidade */
    switch (ev.severity) {
        case 0: case 1: res->count_info++;     break;
        case 2:         res->count_warn++;     break;
        case 3:         res->count_error++;    break;
        default:        res->count_critical++; break;
    }
    if (types & EVENT_SECURITY)    res->security_events++;
    if (types & EVENT_PERFORMANCE) res->perf_events++;
}
 
/* =========================================================================
 * Processar um ficheiro completo (usando open/read POSIX, sem fopen)
 * ========================================================================= */
static void process_file(const char *path, WorkerResult *res,
                          LocalIPTable *ipt, const Config *cfg,
                          WorkerStatus *status, pthread_mutex_t *status_mutex)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) { perror("open"); return; }
 
    char    rbuf[8192];
    char    line[MAX_LINE_LENGTH];
    int     lpos  = 0;
    ssize_t nread;
 
    while (1) {
        nread = read(fd, rbuf, sizeof(rbuf));
        if (nread < 0) {
            if (errno == EINTR) continue;
            perror("read"); break;
        }
        if (nread == 0) {
            /* EOF: processar linha pendente */
            if (lpos > 0) {
                line[lpos] = '\0';
                res->lines_total++;
                process_line(line, res, ipt, cfg);
            }
            break;
        }
 
        for (ssize_t i = 0; i < nread; i++) {
            char c = rbuf[i];
            if (c == '\n' || c == '\r') {
                if (lpos > 0) {
                    line[lpos] = '\0';
                    lpos = 0;
                    res->lines_total++;
                    process_line(line, res, ipt, cfg);
 
                    /* Atualizar progresso no status (com mutex) */
                    pthread_mutex_lock(status_mutex);
                    status->lines_processed = res->lines_total;
                    if (status->total_lines > 0)
                        status->progress_pct =
                            (float)res->lines_total / status->total_lines * 100.0f;
                    pthread_mutex_unlock(status_mutex);
                }
            } else if (lpos < MAX_LINE_LENGTH - 1) {
                line[lpos++] = c;
            }
        }
    }
 
    close(fd);
}
 
/* =========================================================================
 * thread_worker_run — entry point de cada worker thread
 *
 * Recebe um ThreadArg*, processa todos os ficheiros que lhe foram
 * atribuídos e escreve o resultado em arg->result.
 * ========================================================================= */
void *thread_worker_run(void *arg)
{
    ThreadArg *ta = (ThreadArg *)arg;
 
    memset(&ta->result, 0, sizeof(ta->result));
    ta->result.pid = (pid_t)ta->thread_id; /* identificador desta thread */
 
    LocalIPTable ipt;
    memset(&ipt, 0, sizeof(ipt));
 
    /* Marcar como em execução */
    pthread_mutex_lock(ta->status_mutex);
    ta->status->state = STATE_WORKING;
    pthread_mutex_unlock(ta->status_mutex);
 
    /* Processar todos os ficheiros atribuídos a esta thread */
    for (int i = 0; i < ta->fl->count; i++) {
        if (ta->assignment[i] != ta->thread_id) continue;
        process_file(ta->fl->paths[i], &ta->result, &ipt,
                     ta->cfg, ta->status, ta->status_mutex);
    }
 
    /* Top IP */
    ip_top10(&ipt, &ta->result);
 
    /* Marcar como concluído */
    pthread_mutex_lock(ta->status_mutex);
    ta->status->state          = STATE_DONE;
    ta->status->progress_pct   = 100.0f;
    ta->status->lines_processed = ta->result.lines_total;
    pthread_mutex_unlock(ta->status_mutex);
 
    return NULL;
}

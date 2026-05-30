#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>

#include "../include/worker.h"
#include "../include/log_parser.h"
#include "../include/event_classifier.h"
#include "../include/ipc.h"
#include "../include/files.h"

/* ==========================================================================
 * REQUISITO B / C — Tabela de IPs (hash simples para top-IP por worker)
 *
 * Cada worker mantém a sua própria IPTable local durante o processamento.
 * No final, o top10 é serializado e enviado ao pai via pipe/socket.
 * ========================================================================== */
#define IP_TABLE 512

typedef struct { char ip[MAX_IP_LEN]; long count; } IPEntry;
typedef struct { IPEntry e[IP_TABLE]; int used; } IPTable;

/* REQUISITO B: adicionar ou incrementar a contagem de um IP na tabela local */
static void ip_add(IPTable *t, const char *ip)
{
    if (!ip || !ip[0]) return;
    for (int i = 0; i < t->used; i++) {
        if (strcmp(t->e[i].ip, ip) == 0) { t->e[i].count++; return; }
    }
    if (t->used < IP_TABLE) {
        strncpy(t->e[t->used].ip, ip, MAX_IP_LEN - 1);
        t->e[t->used].count = 1;
        t->used++;
    }
}

/* REQUISITO B: encontrar o IP mais frequente (fallback se top10 vazio) */
static void ip_top(const IPTable *t, char *out_ip, long *out_count)
{
    *out_count = 0; out_ip[0] = '\0';
    for (int i = 0; i < t->used; i++) {
        if (t->e[i].count > *out_count) {
            *out_count = t->e[i].count;
            strncpy(out_ip, t->e[i].ip, MAX_IP_LEN - 1);
        }
    }
}

/* REQUISITO B / C: seleccionar os TOP_IPS mais frequentes da tabela
 * e copiá-los para o WorkerResult (enviado ao pai via pipe/socket) */
static void ip_top10(const IPTable *t, WorkerResult *res)
{
    int used[IP_TABLE];
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

/* ==========================================================================
 * REQUISITO D — Envio de progresso em tempo real ao pai
 *
 * O worker envia mensagens PROGRESS a cada 500 linhas processadas.
 * O pai usa estas mensagens para actualizar as barras do dashboard.
 * Protocolo: PROGRESS;PID:<pid>;LINES:<n>\n
 * ========================================================================== */

/* REQUISITO D: envia uma mensagem de progresso ao pai via pipe ou socket */
static void send_progress(int fd, long lines)
{
    if (fd < 0) return;

    char msg[128];
    int len = snprintf(msg, sizeof(msg),
                       "PROGRESS;PID:%d;LINES:%ld\n", (int)getpid(), lines);
    if (len > 0 && len < (int)sizeof(msg))
        writen(fd, msg, (size_t)len);
}

/* ==========================================================================
 * REQUISITO B — Detecção de formato do ficheiro de log
 * ========================================================================== */

/* REQUISITO B: deteta automaticamente o formato da linha de log.
 * Suporta Apache Combined, JSON estruturado, Syslog e Nginx Error. */
LogFmt detect_format(const char *line)
{
    if (!line || !line[0]) return FMT_UNKNOWN;
    if (line[0] == '{') return FMT_JSON;
    /* Nginx: "YYYY/MM/DD ..." */
    if (isdigit(line[0]) && isdigit(line[1]) && isdigit(line[2]) &&
        isdigit(line[3]) && line[4] == '/')
        return FMT_NGINX;
    /* Syslog: começa com '<' (prioridade) */
    if (line[0] == '<') return FMT_SYSLOG;
    /* Syslog sem prioridade: começa com mês em 3 letras */
    const char *months[] = {"Jan","Feb","Mar","Apr","May","Jun",
                             "Jul","Aug","Sep","Oct","Nov","Dec"};
    for (int i = 0; i < 12; i++)
        if (strncmp(line, months[i], 3) == 0) return FMT_SYSLOG;
    /* Apache: começa com IP (dígito) */
    if (isdigit(line[0])) return FMT_APACHE;
    return FMT_UNKNOWN;
}

/* ==========================================================================
 * REQUISITO D — Envio de eventos verbose em tempo real
 *
 * Em modo --verbose, cada evento HIGH ou CRITICAL é enviado imediatamente
 * ao pai pelo pipe/socket para impressão em tempo real.
 * Protocolo: VERBOSE;PID:<pid>;TS:<ts>;TYPE:<t>;SEV:<s>;MSG:<m>;IP:<ip>\n
 * ========================================================================== */

/* REQUISITO D: transmite eventos críticos ao pai em tempo real.
 * Só envia severity >= 3 (HIGH e CRITICAL). */
static void send_verbose(int fd, const ClassifiedEvent *ev,
                          const char *ip, int event_types)
{
    if (fd < 0 || ev->severity < 3) return;

    char ts[32] = "N/A";
    struct tm *tm_info = localtime(&ev->timestamp);
    if (tm_info) strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S", tm_info);

    char msg[640];
    int len = snprintf(msg, sizeof(msg),
        "VERBOSE;PID:%d;TS:%s;TYPE:%s;SEV:%s;MSG:%.300s;IP:%s\n",
        (int)getpid(), ts,
        get_event_type_name(event_types),
        get_severity_name(ev->severity),
        ev->description,
        ip ? ip : "N/A");

    if (len > 0 && len < (int)sizeof(msg))
        writen(fd, msg, (size_t)len);
}

/* ==========================================================================
 * REQUISITO B — Processar um único ficheiro de log
 *
 * Usa open/read/close (syscalls POSIX) — sem fopen/fread/fwrite.
 * Reconstrói linhas completas a partir de blocos lidos com read().
 * Para cada linha: detecta formato → parseia → classifica → acumula métricas.
 * ========================================================================== */

/* REQUISITO B / C / D: processa um ficheiro de log linha a linha.
 * Envia PROGRESS a cada 500 linhas (Req. D) e VERBOSE para eventos
 * críticos se --verbose (Req. D). Resultado acumulado em *res (Req. C). */
static void process_one_file(const char *path, const Config *cfg,
                              int comm_fd, WorkerResult *res, IPTable *ipt)
{
    /* REQUISITO B: abrir o ficheiro com syscall open (sem fopen) */
    int fd = open(path, O_RDONLY);
    if (fd < 0) { perror("open"); return; }

    char read_buf[8192];
    char line[4096];
    int  line_pos = 0;
    ssize_t nread;

    while (1) {
        /* REQUISITO B: ler blocos com syscall read (sem fread) */
        nread = read(fd, read_buf, sizeof(read_buf));
        if (nread < 0) {
            if (errno == EINTR) continue;   /* sinal interrompeu — repetir */
            perror("read"); break;
        }
        if (nread == 0) {
            /* EOF: processar linha pendente se existir */
            if (line_pos > 0) {
                line[line_pos] = '\0';
                goto process_line;
            }
            break;
        }

        for (ssize_t i = 0; i < nread; i++) {
            char c = read_buf[i];
            if (c == '\n' || c == '\r') {
                if (line_pos > 0) {
                    line[line_pos] = '\0';
                    line_pos = 0;
                    goto process_line;
                }
                continue;
            }
            if (line_pos < (int)sizeof(line) - 1)
                line[line_pos++] = c;
            continue;

        process_line:;
            if (!line[0]) continue;
            res->lines_total++;

            /* REQUISITO D: enviar progresso ao pai a cada 500 linhas */
            if (!cfg->verbose && comm_fd >= 0 && (res->lines_total % 500 == 0))
                send_progress(comm_fd, res->lines_total);

            /* REQUISITO B: detectar formato e parsear a linha */
            LogFmt fmt = detect_format(line);
            ClassifiedEvent ev;
            int types = 0;
            const char *ip = NULL;

            switch (fmt) {
                case FMT_APACHE: {
                    ApacheLogEntry e;
                    if (parse_apache_log(line, &e) == 0) {
                        types = classify_apache_event(&e, &ev);
                        res->lines_parsed++;
                        ip = e.ip;
                        ip_add(ipt, e.ip);
                        if (e.status_code >= 400 && e.status_code < 500) res->errors_4xx++;
                        if (e.status_code >= 500 && e.status_code < 600) res->errors_5xx++;
                    }
                    break;
                }
                case FMT_JSON: {
                    JSONLogEntry e;
                    if (parse_json_log(line, &e) == 0) {
                        types = classify_json_event(&e, &ev);
                        res->lines_parsed++;
                        ip = e.ip;
                        ip_add(ipt, e.ip);
                    }
                    break;
                }
                case FMT_SYSLOG: {
                    SyslogEntry e;
                    if (parse_syslog(line, &e) == 0) {
                        types = classify_syslog_event(&e, &ev);
                        res->lines_parsed++;
                    }
                    break;
                }
                case FMT_NGINX: {
                    NginxErrorEntry e;
                    if (parse_nginx_error(line, &e) == 0) {
                        types = classify_nginx_event(&e, &ev);
                        res->lines_parsed++;
                        ip = e.client_ip;
                        ip_add(ipt, e.client_ip);
                    }
                    break;
                }
                default: break;
            }

            if (types == 0) continue;

            /* REQUISITO A: filtrar eventos pelo modo de análise configurado */
            if (!event_matches_mode(&ev, cfg->mode)) continue;

            /* REQUISITO B: acumular contadores de severidade */
            switch (ev.severity) {
                case 0: case 1: res->count_info++;     break;
                case 2:         res->count_warn++;     break;
                case 3:         res->count_error++;    break;
                default:        res->count_critical++; break;
            }
            if (types & EVENT_SECURITY)    res->security_events++;
            if (types & EVENT_PERFORMANCE) res->perf_events++;

            /* REQUISITO D: enviar evento crítico ao pai em modo verbose */
            if (cfg->verbose && comm_fd >= 0)
                send_verbose(comm_fd, &ev, ip, types);
        }
    }

    /* REQUISITO D: enviar progresso final ao terminar o ficheiro */
    if (!cfg->verbose && comm_fd >= 0)
        send_progress(comm_fd, res->lines_total);

    /* REQUISITO B: fechar o ficheiro com syscall close */
    close(fd);
}

/* ==========================================================================
 * REQUISITO B — Entry point do worker (processa todos os ficheiros atribuídos)
 *
 * Chamado por run_worker() após o fork(). Determina o intervalo de ficheiros
 * deste worker com split_files() e processa-os sequencialmente.
 * ========================================================================== */

/* REQUISITO B / C: processa os ficheiros atribuídos a este worker e
 * devolve o WorkerResult com as métricas acumuladas ao processo pai. */
WorkerResult process_files(int worker_id, const FileList *fl,
                            const Config *cfg, int comm_fd)
{
    WorkerResult res;
    memset(&res, 0, sizeof(res));
    res.pid = getpid();

    IPTable ipt;
    memset(&ipt, 0, sizeof(ipt));

    /* REQUISITO B: determinar quais os ficheiros deste worker */
    int start, end;
    split_files(fl, worker_id, cfg->num_procs, &start, &end);

    for (int i = start; i < end; i++)
        process_one_file(fl->paths[i], cfg, comm_fd, &res, &ipt);

    /* REQUISITO C: calcular top IPs para incluir no resultado serializado */
    ip_top10(&ipt, &res);
    return res;
}
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ipc.h"

/* ==========================================================================
 * readn / writen  — leitura e escrita garantidas (Requisito C obrigatório)
 * ========================================================================== */

ssize_t readn(int fd, void *ptr, size_t n)
{
    size_t  nleft = n;
    ssize_t nread;
    char   *p = (char *)ptr;

    while (nleft > 0) {
        nread = read(fd, p, nleft);
        if (nread < 0) {
            if (errno == EINTR) continue;   /* sinal interrompeu — repetir */
            return -1;
        }
        if (nread == 0) break;              /* EOF */
        nleft -= (size_t)nread;
        p     += nread;
    }
    return (ssize_t)(n - nleft);
}

ssize_t writen(int fd, const void *ptr, size_t n)
{
    size_t      nleft = n;
    ssize_t     nwritten;
    const char *p = (const char *)ptr;

    while (nleft > 0) {
        nwritten = write(fd, p, nleft);
        if (nwritten < 0) {
            if (errno == EINTR) continue;   /* sinal interrompeu — repetir */
            return -1;
        }
        nleft -= (size_t)nwritten;
        p     += nwritten;
    }
    return (ssize_t)n;
}

/* ==========================================================================
 * Serialização do WorkerResult em texto (uma linha terminada em '\n')
 *
 * Formato:
 *   RESULT;PID:<n>;LINES:<n>;PARSED:<n>;INFO:<n>;WARN:<n>;ERROR:<n>;
 *   CRIT:<n>;4XX:<n>;5XX:<n>;SEC:<n>;PERF:<n>;TOP_IP:<ip>;TOP_N:<n>
 * ========================================================================== */

void worker_result_serialize(const WorkerResult *r, char *buf, size_t bufsz)
{
    int len = snprintf(buf, bufsz,
        "RESULT;"
        "PID:%d;"
        "LINES:%ld;"
        "PARSED:%ld;"
        "INFO:%ld;"
        "WARN:%ld;"
        "ERROR:%ld;"
        "CRIT:%ld;"
        "4XX:%ld;"
        "5XX:%ld;"
        "SEC:%ld;"
        "PERF:%ld;"
        "TOP_IP:%s;"
        "TOP_N:%ld",
        (int)r->pid,
        r->lines_total,
        r->lines_parsed,
        r->count_info,
        r->count_warn,
        r->count_error,
        r->count_critical,
        r->errors_4xx,
        r->errors_5xx,
        r->security_events,
        r->perf_events,
        r->top_ip[0] ? r->top_ip : "N/A",
        r->top_ip_count);

    for (int i = 0; i < TOP_IPS && len > 0 && (size_t)len < bufsz; i++) {
        if (!r->top_ips[i][0]) break;
        len += snprintf(buf + len, bufsz - (size_t)len,
                        ";IP%d:%s;IP%d_N:%ld",
                        i + 1, r->top_ips[i], i + 1, r->top_ip_counts[i]);
    }

    if (len > 0 && (size_t)len < bufsz - 1) {
        buf[len++] = '\n';
        buf[len] = '\0';
    } else if (bufsz > 0) {
        buf[bufsz - 1] = '\0';
    }
}

/* Extrai um campo long de "KEY:<valor>;" dentro de uma string */
static long extract_long(const char *line, const char *key)
{
    char search[64];
    snprintf(search, sizeof(search), "%s:", key);
    const char *p = strstr(line, search);
    if (!p) return 0;
    p += strlen(search);
    return atol(p);
}

static void extract_str(const char *line, const char *key,
                         char *out, size_t outsz)
{
    char search[64];
    snprintf(search, sizeof(search), "%s:", key);
    const char *p = strstr(line, search);
    if (!p) { out[0] = '\0'; return; }
    p += strlen(search);
    size_t i = 0;
    while (*p && *p != ';' && *p != '\n' && i < outsz - 1)
        out[i++] = *p++;
    out[i] = '\0';
}

int worker_result_parse(const char *line, WorkerResult *r)
{
    if (strncmp(line, "RESULT;", 7) != 0) return -1;
    memset(r, 0, sizeof(WorkerResult));

    r->pid            = (pid_t)extract_long(line, "PID");
    r->lines_total    = extract_long(line, "LINES");
    r->lines_parsed   = extract_long(line, "PARSED");
    r->count_info     = extract_long(line, "INFO");
    r->count_warn     = extract_long(line, "WARN");
    r->count_error    = extract_long(line, "ERROR");
    r->count_critical = extract_long(line, "CRIT");
    r->errors_4xx     = extract_long(line, "4XX");
    r->errors_5xx     = extract_long(line, "5XX");
    r->security_events = extract_long(line, "SEC");
    r->perf_events    = extract_long(line, "PERF");
    r->top_ip_count   = extract_long(line, "TOP_N");
    extract_str(line, "TOP_IP", r->top_ip, sizeof(r->top_ip));
    for (int i = 0; i < TOP_IPS; i++) {
        char key[16];
        snprintf(key, sizeof(key), "IP%d", i + 1);
        extract_str(line, key, r->top_ips[i], sizeof(r->top_ips[i]));
        snprintf(key, sizeof(key), "IP%d_N", i + 1);
        r->top_ip_counts[i] = extract_long(line, key);
    }
    return 0;
}

/* ==========================================================================
 * Agregação global
 * ========================================================================== */

static void global_ip_add(GlobalResult *gr, const char *ip, long count)
{
    if (!ip || !ip[0] || strcmp(ip, "N/A") == 0 || count <= 0) return;

    for (int i = 0; i < TOP_IPS; i++) {
        if (strcmp(gr->top_ips[i], ip) == 0) {
            gr->top_ip_counts[i] += count;
            goto sort;
        }
    }

    for (int i = 0; i < TOP_IPS; i++) {
        if (!gr->top_ips[i][0]) {
            strncpy(gr->top_ips[i], ip, MAX_IP_LEN - 1);
            gr->top_ips[i][MAX_IP_LEN - 1] = '\0';
            gr->top_ip_counts[i] = count;
            goto sort;
        }
    }

    for (int i = 0; i < TOP_IPS; i++) {
        if (count > gr->top_ip_counts[i]) {
            strncpy(gr->top_ips[i], ip, MAX_IP_LEN - 1);
            gr->top_ips[i][MAX_IP_LEN - 1] = '\0';
            gr->top_ip_counts[i] = count;
            break;
        }
    }

sort:
    for (int i = 0; i < TOP_IPS - 1; i++) {
        for (int j = i + 1; j < TOP_IPS; j++) {
            if (gr->top_ip_counts[j] > gr->top_ip_counts[i]) {
                long c = gr->top_ip_counts[i];
                char ipbuf[MAX_IP_LEN];
                snprintf(ipbuf, sizeof(ipbuf), "%s", gr->top_ips[i]);
                gr->top_ip_counts[i] = gr->top_ip_counts[j];
                snprintf(gr->top_ips[i], MAX_IP_LEN, "%s", gr->top_ips[j]);
                gr->top_ip_counts[j] = c;
                snprintf(gr->top_ips[j], MAX_IP_LEN, "%s", ipbuf);
            }
        }
    }
}

void aggregate(const WorkerResult *results, int n, GlobalResult *gr)
{
    memset(gr, 0, sizeof(GlobalResult));
    for (int i = 0; i < n; i++) {
        gr->total_lines    += results[i].lines_total;
        gr->total_parsed   += results[i].lines_parsed;
        gr->total_info     += results[i].count_info;
        gr->total_warn     += results[i].count_warn;
        gr->total_error    += results[i].count_error;
        gr->total_critical += results[i].count_critical;
        gr->total_4xx      += results[i].errors_4xx;
        gr->total_5xx      += results[i].errors_5xx;
        gr->total_security += results[i].security_events;
        gr->total_perf     += results[i].perf_events;
        for (int j = 0; j < TOP_IPS; j++)
            global_ip_add(gr, results[i].top_ips[j], results[i].top_ip_counts[j]);
        if (!results[i].top_ips[0][0])
            global_ip_add(gr, results[i].top_ip, results[i].top_ip_count);
    }
}

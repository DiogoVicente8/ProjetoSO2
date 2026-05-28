#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include "../include/report.h"
#include "../include/ipc.h"

/* ==========================================================================
 * Relatório no terminal
 * ========================================================================== */
void print_report(const GlobalResult *gr, const WorkerResult *workers,
                  int n_workers, const Config *cfg, double elapsed)
{
    double throughput = elapsed > 0 ? (double)gr->total_lines / elapsed : 0;
    double parse_rate = gr->total_lines > 0
        ? 100.0 * gr->total_parsed / gr->total_lines : 0;

    printf("\n");
    printf("╔══════════════════════════════════════════════════╗\n");
    printf("║          LOG ANALYZER  —  Relatorio Final        ║\n");
    printf("╠══════════════════════════════════════════════════╣\n");
    printf("║  Modo    : %-10s   Workers : %-3d                ║\n",mode_to_string(cfg->mode), cfg->num_procs);
    printf("╠══════════════════════════════════════════════════╣\n");
    printf("║  PROCESSAMENTO                                   ║\n");
    printf("║  Linhas totais  : %-10ld                         ║\n", gr->total_lines);
    printf("║  Linhas parsed  : %-10ld  (%.1f%%)               ║\n",gr->total_parsed, parse_rate);
    printf("║  Throughput     : %-10.0f linhas/s               ║\n", throughput);
    printf("║  Tempo total    : %-10.3f s                      ║\n", elapsed);
    printf("╠══════════════════════════════════════════════════╣\n");
    printf("║  SEVERIDADE                                      ║\n");
    printf("║  INFO/LOW  : %-10ld                              ║\n", gr->total_info);
    printf("║  WARN      : %-10ld                              ║\n", gr->total_warn);
    printf("║  ERROR     : %-10ld                              ║\n", gr->total_error);
    printf("║  CRITICAL  : %-10ld                              ║\n", gr->total_critical);
    printf("╠══════════════════════════════════════════════════╣\n");

    if (cfg->mode == MODE_SECURITY || cfg->mode == MODE_FULL) {
        printf("║  SEGURANCA                                       ║\n");
        printf("║  Eventos       : %-10ld                          ║\n", gr->total_security);
        printf("║  Erros 4xx     : %-10ld                          ║\n", gr->total_4xx);
        printf("╠══════════════════════════════════════════════════╣\n");
    }
    if (cfg->mode == MODE_PERFORMANCE || cfg->mode == MODE_FULL) {
        printf("║  PERFORMANCE                                     ║\n");
        printf("║  Eventos       : %-10ld                          ║\n", gr->total_perf);
        printf("║  Erros 5xx     : %-10ld                          ║\n", gr->total_5xx);
        printf("╠══════════════════════════════════════════════════╣\n");
    }

    if (cfg->mode == MODE_TRAFFIC || cfg->mode == MODE_FULL) {
        printf("║  TOP IPs                                         ║\n");
        for (int i = 0; i < TOP_IPS && gr->top_ips[i][0]; i++) {
            printf("║  %2d. %-22s %10ld req                        ║\n",i + 1, gr->top_ips[i], gr->top_ip_counts[i]);
        }
        printf("╠══════════════════════════════════════════════════╣\n");
    }

    printf("║  RESULTADOS POR WORKER                           ║\n");
    for (int i = 0; i < n_workers; i++) {
        printf("║  W%-2d PID:%-6d  Linhas:%-7ld  SEC:%-5ld      ║\n",
               i + 1,
               (int)workers[i].pid,
               workers[i].lines_total,
               workers[i].security_events);
    }
    printf("╚══════════════════════════════════════════════════╝\n");
}

/* ==========================================================================
 * Relatório em JSON  (--output=<ficheiro>)
 * ========================================================================== */
void write_report_json(const GlobalResult *gr, const Config *cfg,
                       double elapsed, const char *path)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { perror("open (output)"); return; }

    char buf[2048];
    int len = snprintf(buf, sizeof(buf),
        "{\n"
        "  \"mode\": \"%s\",\n"
        "  \"workers\": %d,\n"
        "  \"elapsed_s\": %.3f,\n"
        "  \"throughput_lines_s\": %.0f,\n"
        "  \"lines\": { \"total\": %ld, \"parsed\": %ld },\n"
        "  \"severity\": {\n"
        "    \"info\": %ld, \"warn\": %ld,\n"
        "    \"error\": %ld, \"critical\": %ld\n"
        "  },\n"
        "  \"http\": { \"4xx\": %ld, \"5xx\": %ld },\n"
        "  \"events\": { \"security\": %ld, \"performance\": %ld },\n"
        "  \"top_ips\": [\n",
        mode_to_string(cfg->mode), cfg->num_procs,
        elapsed,
        elapsed > 0 ? (double)gr->total_lines / elapsed : 0.0,
        gr->total_lines, gr->total_parsed,
        gr->total_info, gr->total_warn,
        gr->total_error, gr->total_critical,
        gr->total_4xx, gr->total_5xx,
        gr->total_security, gr->total_perf);

    if (len > 0) writen(fd, buf, (size_t)len);

    for (int i = 0; i < TOP_IPS && gr->top_ips[i][0]; i++) {
        len = snprintf(buf, sizeof(buf),
                       "    { \"ip\": \"%s\", \"count\": %ld }%s\n",
                       gr->top_ips[i], gr->top_ip_counts[i],
                       (i + 1 < TOP_IPS && gr->top_ips[i + 1][0]) ? "," : "");
        if (len > 0) writen(fd, buf, (size_t)len);
    }

    len = snprintf(buf, sizeof(buf), "  ]\n}\n");
    if (len > 0) writen(fd, buf, (size_t)len);
    close(fd);
    printf("Relatorio JSON guardado: %s\n", path);
}

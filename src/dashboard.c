#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "dashboard.h"
#include "ipc.h"

/* Quantas linhas ocupa o dashboard (calculado em dashboard_init) */
static int g_dash_lines = 0;

/* Cores ANSI */
#define C_RESET  "\033[0m"
#define C_BOLD   "\033[1m"
#define C_CYAN   "\033[36m"
#define C_GREEN  "\033[32m"
#define C_YELLOW "\033[33m"
#define C_RED    "\033[31m"
#define C_WHITE  "\033[37m"

/* Escreve sem buffering (usa write diretamente) */
static void out(const char *s) { writen(STDOUT_FILENO, s, strlen(s)); }

/* Barra de progresso em UTF-8 (█ = bloco cheio, ░ = bloco vazio) */
static void make_bar(char *buf, size_t bufsz, float pct, int width)
{
    if (pct < 0)   pct = 0;
    if (pct > 100) pct = 100;
    int filled = (int)(pct / 100.0f * width);
    int empty  = width - filled;
    int pos = 0;
    /* █  U+2588  → UTF-8: E2 96 88 */
    for (int i = 0; i < filled && pos + 3 < (int)bufsz; i++) {
        buf[pos++] = (char)0xE2; buf[pos++] = (char)0x96; buf[pos++] = (char)0x88;
    }
    /* ░  U+2591  → UTF-8: E2 96 91 */
    for (int i = 0; i < empty  && pos + 3 < (int)bufsz; i++) {
        buf[pos++] = (char)0xE2; buf[pos++] = (char)0x96; buf[pos++] = (char)0x91;
    }
    buf[pos] = '\0';
}

/* ==========================================================================
 * dashboard_init
 * ========================================================================== */
void dashboard_init(int n_workers)
{
    /*  Cabeçalho(3) + 1 linha/worker + separador(1) + rodapé(3) + fecho(1) = n+8 */
    g_dash_lines = n_workers + 8;
    for (int i = 0; i < g_dash_lines; i++) out("\n");
}

/* ==========================================================================
 * dashboard_draw
 * ========================================================================== */
void dashboard_draw(WorkerStatus *st, int n, double elapsed,
                    long events_sec, long total_errors)
{
    char line[256];
    char bar[128];

    /* Subir o cursor para o topo do dashboard */
    snprintf(line, sizeof(line), "\033[%dA\r", g_dash_lines);
    out(line);

    /* Calcular progresso total */
    long total_proc = 0, total_lines = 0;
    for (int i = 0; i < n; i++) {
        total_proc  += st[i].lines_processed;
        total_lines += st[i].total_lines;
    }
    float total_pct = total_lines > 0
        ? (float)total_proc / total_lines * 100.0f : 0.0f;

    /* ETA */
    double eta = 0;
    if (total_pct > 0.5f && total_pct < 99.5f)
        eta = elapsed / (total_pct / 100.0) - elapsed;

    /* Cabeçalho */
    out(C_CYAN C_BOLD
        "╔══════════════════════════════════════════╗\n"
        "║" C_RESET C_WHITE C_BOLD
        "     LOG ANALYZER - Real-time Monitor     "
        C_CYAN C_BOLD "║\n"
        "╠══════════════════════════════════════════╣\n"
        C_RESET);

    /* Linha por worker */
    for (int i = 0; i < n; i++) {
        float pct = st[i].progress_pct;
        make_bar(bar, sizeof(bar), pct, 18);
        const char *col = (st[i].state == STATE_DONE)    ? C_GREEN  :
                          (st[i].state == STATE_WORKING)  ? C_YELLOW : C_WHITE;
        snprintf(line, sizeof(line),
            C_CYAN C_BOLD "║ " C_RESET
            C_WHITE "Worker %-2d " C_RESET
            "%s[%s]" C_RESET " %s%3.0f%%" C_RESET
            " " C_CYAN C_BOLD "║\n" C_RESET,
            i + 1, col, bar, col, pct);
        out(line);
    }

    /* Separador + total */
    out(C_CYAN C_BOLD "╠══════════════════════════════════════════╣\n" C_RESET);

    make_bar(bar, sizeof(bar), total_pct, 18);
    snprintf(line, sizeof(line),
        C_CYAN C_BOLD "║ " C_RESET C_BOLD "Total     " C_RESET
        C_GREEN "[%s]" C_RESET C_BOLD " %3.0f%%" C_RESET
        " " C_CYAN C_BOLD "║\n" C_RESET,
        bar, total_pct);
    out(line);

    /* Eventos/sec e erros */
    snprintf(line, sizeof(line),
        C_CYAN C_BOLD "║ " C_RESET
        "Events/sec: " C_YELLOW "%-8ld" C_RESET
        " Errors: " C_RED "%-5ld" C_RESET
        C_CYAN C_BOLD "║\n" C_RESET,
        events_sec, total_errors);
    out(line);

    /* Tempo decorrido e ETA */
    int eh = (int)elapsed / 3600, em = ((int)elapsed % 3600) / 60, es = (int)elapsed % 60;
    int rh = (int)eta    / 3600, rm = ((int)eta    % 3600) / 60, rs = (int)eta    % 60;
    snprintf(line, sizeof(line),
        C_CYAN C_BOLD "║ " C_RESET
        "Elapsed: " C_GREEN "%02d:%02d:%02d" C_RESET
        "  ETA: " C_YELLOW "%02d:%02d:%02d" C_RESET
        "   " C_CYAN C_BOLD "║\n" C_RESET,
        eh, em, es, rh, rm, rs);
    out(line);

    out(C_CYAN C_BOLD "╚══════════════════════════════════════════╝\n" C_RESET);
}


void dashboard_done(int n_workers)
{
    (void)n_workers;
    out("\n");
}

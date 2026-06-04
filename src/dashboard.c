#define _GNU_SOURCE
#include <stdio.h>      /* fprintf, snprintf */
#include <string.h>     /* strlen */
#include <unistd.h>     /* STDOUT_FILENO */
#include "../include/dashboard.h" /* Definições do estado do dashboard */
#include "../include/ipc.h"       /* WorkerStatus e enums de estado */

/* ==========================================================================
 * REQUISITO D — Dashboard de progresso em tempo real (ANSI)
 *
 * Usa escape codes ANSI para redesenhar o dashboard no lugar sem limpar
 * o ecrã inteiro. Escreve directamente com write() (via writen) para evitar
 * buffering do stdio que atrasaria as actualizações visuais.
 * ========================================================================== */

/* Quantas linhas ocupa o dashboard (calculado em dashboard_init) */
static int g_dash_lines = 0;

/* REQUISITO D: códigos de escape ANSI para cores */
#define C_RESET  "\033[0m"
#define C_BOLD   "\033[1m"
#define C_CYAN   "\033[36m"
#define C_GREEN  "\033[32m"
#define C_YELLOW "\033[33m"
#define C_RED    "\033[31m"
#define C_WHITE  "\033[37m"

/* REQUISITO D: escreve no stdout sem buffering (syscall write directa) */
static void out(const char *s) { writen(STDOUT_FILENO, s, strlen(s)); }

/* REQUISITO D: gera a barra de progresso usando caracteres ASCII.
 * # = bloco cheio  →  progresso feito
 * - = bloco vazio  →  progresso restante */
static void make_bar(char *buf, size_t bufsz, float pct, int width)
{
    if (pct < 0)   pct = 0;          /* Normaliza para 0% mínimo */
    if (pct > 100) pct = 100;        /* Normaliza para 100% máximo */
    int filled = (int)(pct / 100.0f * width); /* Blocos preenchidos */
    int empty  = width - filled;     /* Blocos vazios */
    int pos = 0;                     /* Posição de escrita no buffer */
    for (int i = 0; i < filled && pos + 1 < (int)bufsz; i++) {
        buf[pos++] = '#';            /* Bloco cheio */
    }
    for (int i = 0; i < empty && pos + 1 < (int)bufsz; i++) {
        buf[pos++] = '-';            /* Bloco vazio */
    }
    buf[pos] = '\0';                /* Termina a string da barra */
}

/* REQUISITO D: reserva linhas no terminal para o dashboard.
 * Deve ser chamado uma vez antes do primeiro dashboard_draw().
 * Fórmula: cabeçalho(3) + 1 linha/worker + separador(1) + rodapé(3) + fecho(1) */
void dashboard_init(int n_workers)
{
    g_dash_lines = n_workers + 8;    /* Calcula linhas totais do dashboard */
    for (int i = 0; i < g_dash_lines; i++) out("\n"); /* Faz scroll com linhas em branco */
}

/* REQUISITO D: redesenha o dashboard no lugar usando escape ANSI \033[nA.
 * Chamado periodicamente pelo pai durante a recolha de dados.
 * Mostra: barra por worker, barra total, eventos/sec, erros e ETA. */
void dashboard_draw(WorkerStatus *st, int n, double elapsed,
                    long events_sec, long total_errors)
{
    char line[256];                  /* Buffer de formatação de linha */
    char bar[128];                   /* Buffer da barra de progresso */

    /* REQUISITO D: subir o cursor para o topo do dashboard */
    snprintf(line, sizeof(line), "\033[%dA\r", g_dash_lines);
    out(line);

    /* REQUISITO D: calcular progresso global a partir de todos os workers */
    long total_proc = 0, total_lines = 0;
    for (int i = 0; i < n; i++) {
        total_proc  += st[i].lines_processed; /* Total processado */
        total_lines += st[i].total_lines;     /* Total esperado */
    }
    float total_pct = total_lines > 0
        ? (float)total_proc / total_lines * 100.0f : 0.0f; /* Percentagem global */

    /* REQUISITO D: calcular ETA a partir do progresso actual */
    double eta = 0;
    if (total_pct > 0.5f && total_pct < 99.5f)
        eta = elapsed / (total_pct / 100.0) - elapsed;

    /* Cabeçalho do dashboard */
    out(C_CYAN C_BOLD
        "+------------------------------------------+\n"
        "|" C_RESET C_WHITE C_BOLD
        "     LOG ANALYZER - Real-time Monitor     "
           C_CYAN C_BOLD "|\n"
        "+------------------------------------------+\n"
        C_RESET);

    /* Linha de cada worker com cor e barra de progresso */
    for (int i = 0; i < n; i++) {
        float pct = st[i].progress_pct;  /* Percentagem do worker */
        make_bar(bar, sizeof(bar), pct, 18); /* Cria barra ASCII */
        const char *col = (st[i].state == STATE_DONE)    ? C_GREEN  :
                          (st[i].state == STATE_WORKING)  ? C_YELLOW : C_WHITE;
        snprintf(line, sizeof(line),
            C_CYAN C_BOLD "| " C_RESET
            C_WHITE "Worker %-2d " C_RESET
            "%s[%s]" C_RESET " %s%3.0f%%" C_RESET
            "      " C_CYAN C_BOLD "|\n" C_RESET,
            i + 1, col, bar, col, pct);
        out(line);
    }

    /* Separador e barra de progresso total */
    out(C_CYAN C_BOLD "+------------------------------------------+\n" C_RESET);

    make_bar(bar, sizeof(bar), total_pct, 18); /* Barra total */
    snprintf(line, sizeof(line),
        C_CYAN C_BOLD "| " C_RESET C_BOLD "Total     " C_RESET
        C_GREEN "[%s]" C_RESET C_BOLD " %3.0f%%" C_RESET
        "      " C_CYAN C_BOLD "|\n" C_RESET,
        bar, total_pct);
    out(line);

    /* Linha de eventos por segundo e total de erros */
    snprintf(line, sizeof(line),
        C_CYAN C_BOLD "| " C_RESET
        "Events/sec: " C_YELLOW "%-8ld" C_RESET
        " Errors: " C_RED "%-5ld" C_RESET
        "      " C_CYAN C_BOLD "|\n" C_RESET,
        events_sec, total_errors);
    out(line);

    /* Linha de tempo decorrido e ETA */
    long elapsed_ms = elapsed > 0.0 ? (long)(elapsed * 1000.0) : 0;
    long eta_ms     = eta     > 0.0 ? (long)(eta     * 1000.0) : 0;
    int eh = (int)(elapsed_ms / 3600000);           /* Horas decorrido */
    int em = (int)((elapsed_ms % 3600000) / 60000); /* Minutos decorrido */
    int es = (int)((elapsed_ms % 60000) / 1000);     /* Segundos decorrido */
    int e_ms = (int)(elapsed_ms % 1000);             /* Milissegundos decorrido */
    int rh = (int)(eta_ms / 3600000);                /* Horas restantes */
    int rm = (int)((eta_ms % 3600000) / 60000);      /* Minutos restantes */
    int rs = (int)((eta_ms % 60000) / 1000);          /* Segundos restantes */
    int r_ms = (int)(eta_ms % 1000);                  /* Milissegundos restantes */
    snprintf(line, sizeof(line),
        C_CYAN C_BOLD "| " C_RESET
        "Elapsed: " C_GREEN "%02d:%02d:%02d.%03d" C_RESET
        " ETA: " C_YELLOW "%02d:%02d:%02d.%03d" C_RESET
        "  " C_CYAN C_BOLD "|\n" C_RESET,
        eh, em, es, e_ms, rh, rm, rs, r_ms);
    out(line);

    /* Rodapé do dashboard */
    out(C_CYAN C_BOLD "+------------------------------------------+\n" C_RESET);
}

/* REQUISITO D: imprime uma linha em branco após o dashboard final */
void dashboard_done(int n_workers)
{
    (void)n_workers; /* Parâmetro não usado */
    out("\n"); /* Adiciona linha de separação final */
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/config.h"

/* ==========================================================================
 * REQUISITO A — Interface de linha de comandos
 *
 * Valida:
 *   ./logAnalyzer <diretorio_logs> <num_processos> <modo> [opcoes]
 * e interpreta --verbose e --output=<ficheiro>. Esta configuração é
 * reutilizada pelas versões com processos, threads e produtor-consumidor.
 * ========================================================================== */

/* REQUISITO A: imprime as instruções de uso no stderr */
void print_usage(const char *prog)
{
    fprintf(stderr,
        "Uso: %s <diretorio_logs> <num_processos> <modo> [opcoes]\n"
        "\n"
        "Parametros obrigatorios:\n"
        "  <diretorio_logs>   Pasta com ficheiros .log / .json\n"
        "  <num_processos>    Numero de processos worker (>= 1, max %d)\n"
        "  <modo>             security | performance | traffic | full\n"
        "\n"
        "Opcoes facultativas:\n"
        "  --verbose            Modo verboso (eventos criticos em tempo real)\n"
        "  --output=<ficheiro>  Ficheiro de saida do relatorio (formato JSON)\n"
        "\n"
        "Exemplos:\n"
        "  %s /var/log/apache2 4 security --verbose\n"
        "  %s ./datasets 2 full --output=report.json\n"
        "  %s ./logs 1 performance --verbose --output=perf.json\n",
        prog, MAX_WORKERS, prog, prog, prog);
}

/* REQUISITO A: converte enum AnalysisMode para string legível */
const char *mode_to_string(AnalysisMode mode)
{
    switch (mode) {
        case MODE_SECURITY:    return "security";
        case MODE_PERFORMANCE: return "performance";
        case MODE_TRAFFIC:     return "traffic";
        case MODE_FULL:        return "full";
        default:               return "desconhecido";
    }
}

/* REQUISITO A: parseia o argumento <modo> e preenche o enum */
static int parse_mode(const char *str, AnalysisMode *mode)
{
    if (strcmp(str, "security")    == 0) { *mode = MODE_SECURITY;    return 0; }
    if (strcmp(str, "performance") == 0) { *mode = MODE_PERFORMANCE; return 0; }
    if (strcmp(str, "traffic")     == 0) { *mode = MODE_TRAFFIC;     return 0; }
    if (strcmp(str, "full")        == 0) { *mode = MODE_FULL;        return 0; }
    return -1;
}

/* REQUISITO A: valida e parseia o argumento <num_processos>
 * — rejeita não-numéricos, < 1 e limita ao MAX_WORKERS */
static int parse_num_procs(const char *str, int *out)
{
    for (int i = 0; str[i] != '\0'; i++) {
        if (str[i] < '0' || str[i] > '9') {
            fprintf(stderr,
                "Erro: num_processos deve ser um inteiro positivo (recebido: '%s')\n",
                str);
            return -1;
        }
    }
    int n = atoi(str);
    if (n < 1) {
        fprintf(stderr, "Erro: num_processos deve ser >= 1 (recebido: %d)\n", n);
        return -1;
    }
    if (n > MAX_WORKERS) {
        fprintf(stderr, "Aviso: num_processos limitado a %d\n", MAX_WORKERS);
        n = MAX_WORKERS;
    }
    *out = n;
    return 0;
}

/* REQUISITO A: parseia opções facultativas --verbose e --output=<ficheiro> */
static int parse_option(const char *opt, Config *cfg)
{
    if (strcmp(opt, "--verbose") == 0) {
        cfg->verbose = true;
        return 0;
    }
    if (strncmp(opt, "--output=", 9) == 0) {
        const char *val = opt + 9;
        if (val[0] == '\0') {
            fprintf(stderr, "Erro: --output= requer um nome de ficheiro\n");
            return -1;
        }
        strncpy(cfg->output_file, val, MAX_PATH_LEN - 1);
        cfg->output_file[MAX_PATH_LEN - 1] = '\0';
        cfg->has_output = true;
        return 0;
    }
    if (strncmp(opt, "--consumers=", 12) == 0) {
        return 0;
    }
    fprintf(stderr, "Aviso: opcao desconhecida '%s' (ignorada)\n", opt);
    return 0;
}

/* REQUISITO A: função principal de parse — valida argc mínimo e
 * delega cada argumento posicional e opção às funções acima */
int parse_args(int argc, char *argv[], Config *cfg)
{
    memset(cfg, 0, sizeof(Config));

    if (argc < 4) {
        fprintf(stderr, "Erro: sao necessarios pelo menos 3 argumentos.\n\n");
        print_usage(argv[0]);
        return -1;
    }

    /* REQUISITO A: arg 1 — directório de logs */
    strncpy(cfg->log_dir, argv[1], MAX_PATH_LEN - 1);
    cfg->log_dir[MAX_PATH_LEN - 1] = '\0';

    /* REQUISITO A: arg 2 — número de processos worker */
    if (parse_num_procs(argv[2], &cfg->num_procs) < 0)
        return -1;

    /* REQUISITO A: arg 3 — modo de análise */
    if (parse_mode(argv[3], &cfg->mode) < 0) {
        fprintf(stderr,
            "Erro: modo invalido '%s'. Use: security | performance | traffic | full\n",
            argv[3]);
        return -1;
    }

    /* REQUISITO A: arg 4+ — opções facultativas */
    for (int i = 4; i < argc; i++) {
        if (parse_option(argv[i], cfg) < 0)
            return -1;
    }

    return 0;
}

/* REQUISITO A: imprime a configuração carregada (usado com --verbose) */
void print_config(const Config *cfg)
{
    printf("[Configuracao]\n");
    printf("  Diretorio : %s\n", cfg->log_dir);
    printf("  Workers   : %d\n", cfg->num_procs);
    printf("  Modo      : %s\n", mode_to_string(cfg->mode));
    printf("  Verbose   : %s\n", cfg->verbose    ? "sim" : "nao");
    printf("  Output    : %s\n", cfg->has_output ? cfg->output_file : "(nenhum)");
    printf("\n");
}
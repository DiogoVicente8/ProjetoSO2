#include <stdio.h>      /* printf, fprintf */
#include <stdlib.h>     /* atoi, malloc, free */
#include <string.h>     /* strcmp, strncmp, strncpy, memset */
#include "../include/config.h"  /* Definições de Config, AnalysisMode e constantes */

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
        case MODE_SECURITY:    return "security";   /* Retorna nome para modo security */
        case MODE_PERFORMANCE: return "performance";/* Retorna nome para modo performance */
        case MODE_TRAFFIC:     return "traffic";    /* Retorna nome para modo traffic */
        case MODE_FULL:        return "full";       /* Retorna nome para modo full */
        default:               return "desconhecido"; /* Valor inválido */
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
            return -1; /* Caractere inválido encontrado na string */
        }
    }
    int n = atoi(str); /* Converte a string em inteiro */
    if (n < 1) {
        fprintf(stderr, "Erro: num_processos deve ser >= 1 (recebido: %d)\n", n);
        return -1; /* Valor menor do que 1 */
    }
    if (n > MAX_WORKERS) {
        fprintf(stderr, "Aviso: num_processos limitado a %d\n", MAX_WORKERS);
        n = MAX_WORKERS; /* Limita o número de workers */
    }
    *out = n; /* Armazena valor validado */
    return 0; /* Sucesso */
}

/* REQUISITO A: parseia opções facultativas --verbose e --output=<ficheiro> */
static int parse_option(const char *opt, Config *cfg)
{
    if (strcmp(opt, "--verbose") == 0) {
        cfg->verbose = true; /* Ativa o modo verboso */
        return 0;
    }
    if (strncmp(opt, "--output=", 9) == 0) {
        const char *val = opt + 9; /* Valor do caminho do ficheiro */
        if (val[0] == '\0') {
            fprintf(stderr, "Erro: --output= requer um nome de ficheiro\n");
            return -1; /* Ficheiro de saída inválido */
        }
        strncpy(cfg->output_file, val, MAX_PATH_LEN - 1); /* Copia nome do ficheiro */
        cfg->output_file[MAX_PATH_LEN - 1] = '\0'; /* Garante terminação */
        cfg->has_output = true; /* Marca saída para ficheiro */
        return 0;
    }
    if (strncmp(opt, "--consumers=", 12) == 0) {
        return 0; /* Aceita sem ação nesta versão */
    }
    fprintf(stderr, "Aviso: opcao desconhecida '%s' (ignorada)\n", opt);
    return 0; /* Ignora opções desconhecidas */
}

/* REQUISITO A: função principal de parse — valida argc mínimo e
 * delega cada argumento posicional e opção às funções acima */
int parse_args(int argc, char *argv[], Config *cfg)
{
    memset(cfg, 0, sizeof(Config)); /* Inicializa a struct de configuração */

    if (argc < 4) {
        fprintf(stderr, "Erro: sao necessarios pelo menos 3 argumentos.\n\n");
        print_usage(argv[0]); /* Mostra instruções de uso */
        return -1; /* Falha por número insuficiente de argumentos */
    }

    /* REQUISITO A: arg 1 — directório de logs */
    strncpy(cfg->log_dir, argv[1], MAX_PATH_LEN - 1); /* Copia diretório de logs */
    cfg->log_dir[MAX_PATH_LEN - 1] = '\0'; /* Evita overflow */

    /* REQUISITO A: arg 2 — número de processos worker */
    if (parse_num_procs(argv[2], &cfg->num_procs) < 0)
        return -1; /* Erro de validação numérica */

    /* REQUISITO A: arg 3 — modo de análise */
    if (parse_mode(argv[3], &cfg->mode) < 0) {
        fprintf(stderr,
            "Erro: modo invalido '%s'. Use: security | performance | traffic | full\n",
            argv[3]);
        return -1; /* Modo inválido */
    }

    /* REQUISITO A: arg 4+ — opções facultativas */
    for (int i = 4; i < argc; i++) {
        if (parse_option(argv[i], cfg) < 0)
            return -1; /* Erro ao parsear opção */
    }

    return 0; /* Sucesso */
}

/* REQUISITO A: imprime a configuração carregada (usado com --verbose) */
void print_config(const Config *cfg)
{
    printf("[Configuracao]\n");
    printf("  Diretorio : %s\n", cfg->log_dir); /* Diretório de logs */
    printf("  Workers   : %d\n", cfg->num_procs); /* Número de workers */
    printf("  Modo      : %s\n", mode_to_string(cfg->mode)); /* Modo de análise */
    printf("  Verbose   : %s\n", cfg->verbose    ? "sim" : "nao"); /* Flag verbose */
    printf("  Output    : %s\n", cfg->has_output ? cfg->output_file : "(nenhum)"); /* Ficheiro de saída */
    printf("\n");
}
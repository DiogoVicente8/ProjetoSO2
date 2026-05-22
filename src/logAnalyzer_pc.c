/*
 * logAnalyzer_pc.c  —  Fase 2, Requisito C (Versão Otimizada e Segura)
 *
 * Arquitetura Produtor-Consumidor com Bounded Buffer:
 * P threads produtoras — leem ficheiros e inserem linhas no buffer
 * C threads consumidoras — retiram do buffer, classificam e detetam padrões
 * 1 thread de dashboard — atualiza progresso em tempo real com usleep (sem busy waiting)
 *
 * Uso:
 * ./logAnalyzer_pc <dir> <num_produtores> <modo> [--consumers=C] [--verbose] [--output=f]
 *
 * Syscalls/funções POSIX utilizadas:
 * open, read, close                        — I/O sem fopen
 * pthread_create, pthread_join             — criação e espera de threads
 * pthread_mutex_init/lock/unlock/destroy   — exclusão mútua
 * sem_init, sem_wait, sem_post, sem_destroy — sincronização do buffer
 * gettimeofday                             — medição de tempo
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/time.h>
#include <errno.h>

#include "config.h"
#include "files.h"
#include "ipc.h"
#include "dashboard.h"
#include "dashboard_thread.h"
#include "report.h"
#include "bounded_buffer.h"
#include "pc_worker.h"

/* Número padrão de consumidores se não especificado */
#define DEFAULT_CONSUMERS 4

/* -------------------------------------------------------------------------
 * Helper de tempo
 * ------------------------------------------------------------------------- */
static double now_secs(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (double)tv.tv_sec + (double)tv.tv_usec / 1e6;
}

/* -------------------------------------------------------------------------
 * Parse de --consumers=N da linha de comandos
 * ------------------------------------------------------------------------- */
static int parse_consumers(int argc, char *argv[], int default_val)
{
    for (int i = 4; i < argc; i++) {
        if (strncmp(argv[i], "--consumers=", 12) == 0) {
            int n = atoi(argv[i] + 12);
            return (n >= 1) ? n : default_val;
        }
    }
    return default_val;
}

/* =========================================================================
 * MAIN
 * ========================================================================= */
int main(int argc, char *argv[])
{
    /* ------------------------------------------------------------------
     * Parse de argumentos
     * ------------------------------------------------------------------ */
    Config cfg;
    if (parse_args(argc, argv, &cfg) < 0)
        return EXIT_FAILURE;

    int n_consumers = parse_consumers(argc, argv, DEFAULT_CONSUMERS);

    if (cfg.verbose) {
        print_config(&cfg);
        printf("  Consumidores: %d\n\n", n_consumers);
    }

    /* ------------------------------------------------------------------
     * Descoberta de ficheiros
     * ------------------------------------------------------------------ */
    FileList *fl = calloc(1, sizeof(FileList));
    if (!fl) { perror("calloc"); return EXIT_FAILURE; }

    if (discover_files(cfg.log_dir, fl) <= 0) {
        fprintf(stderr, "Erro: nenhum ficheiro .log/.json em '%s'\n",
                cfg.log_dir);
        free(fl); return EXIT_FAILURE;
    }

    int P = cfg.num_procs;   /* produtores */
    int C = n_consumers;     /* consumidores */

    if (P > fl->count) P = fl->count;

    fprintf(stderr, "[INFO] %d ficheiro(s) | %d produtor(es) | %d consumidor(es)\n",
            fl->count, P, C);

    /* ------------------------------------------------------------------
     * Divisão balanceada de ficheiros pelos produtores
     * ------------------------------------------------------------------ */
    int *assignment = malloc((size_t)fl->count * sizeof(int));
    if (!assignment) { perror("malloc"); free(fl); return EXIT_FAILURE; }
    split_files_balanced(fl, P, assignment);

    /* ------------------------------------------------------------------
     * Bounded Buffer
     * ------------------------------------------------------------------ */
    BoundedBuffer *bb = calloc(1, sizeof(BoundedBuffer));
    if (!bb) { perror("calloc"); free(assignment); free(fl); return EXIT_FAILURE; }
    bb_init(bb, C);

    /* ------------------------------------------------------------------
     * Alocar estruturas de controlo
     * ------------------------------------------------------------------ */
    pthread_t    *prod_tids = malloc((size_t)P * sizeof(pthread_t));
    pthread_t    *cons_tids = malloc((size_t)C * sizeof(pthread_t));
    ProducerArg  *prod_args = calloc((size_t)P, sizeof(ProducerArg));
    ConsumerArg  *cons_args = calloc((size_t)C, sizeof(ConsumerArg));
    WorkerStatus *statuses  = calloc((size_t)P, sizeof(WorkerStatus));

    if (!prod_tids || !cons_tids || !prod_args || !cons_args || !statuses) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    pthread_mutex_t status_mutex;
    if (pthread_mutex_init(&status_mutex, NULL) != 0) {
        perror("pthread_mutex_init (status)");
        exit(EXIT_FAILURE);
    }

    /* Estimar linhas por produtor para o dashboard */
    for (int i = 0; i < P; i++) {
        long est = 0;
        for (int j = 0; j < fl->count; j++)
            if (assignment[j] == i) est += count_lines(fl->paths[j]);
        statuses[i].total_lines = est > 0 ? est : 1;
        statuses[i].state       = STATE_IDLE;
        statuses[i].pid         = (pid_t)(i + 1);
    }

    /* ------------------------------------------------------------------
     * Inicializar dashboard + thread dedicada
     * ------------------------------------------------------------------ */
    if (!cfg.verbose)
        dashboard_init(P);

    double t0 = now_secs();

    pthread_t    dash_tid;
    DashboardArg dash_arg;

    if (!cfg.verbose) {
        dashboard_arg_init(&dash_arg, statuses, P, &status_mutex, t0);
        if (pthread_create(&dash_tid, NULL, dashboard_thread_run, &dash_arg) != 0) {
            perror("pthread_create (dashboard)"); 
            exit(EXIT_FAILURE);
        }
    }

    /* ------------------------------------------------------------------
     * Criar C threads CONSUMIDORAS (antes dos produtores para estarem
     * prontas a receber quando o buffer começar a ser preenchido)
     * ------------------------------------------------------------------ */
    for (int i = 0; i < C; i++) {
        cons_args[i].consumer_id = i;
        cons_args[i].bb          = bb;
        cons_args[i].cfg         = &cfg;

        if (pthread_create(&cons_tids[i], NULL, consumer_run, &cons_args[i]) != 0) {
            perror("pthread_create (consumer)"); 
            exit(EXIT_FAILURE);
        }
    }

    /* ------------------------------------------------------------------
     * Criar P threads PRODUTORAS
     * ------------------------------------------------------------------ */
    for (int i = 0; i < P; i++) {
        prod_args[i].producer_id   = i;
        prod_args[i].num_producers = P;
        prod_args[i].fl            = fl;
        prod_args[i].assignment    = assignment;
        prod_args[i].bb            = bb;
        prod_args[i].status        = &statuses[i];
        prod_args[i].status_mutex  = &status_mutex;

        if (pthread_create(&prod_tids[i], NULL, producer_run, &prod_args[i]) != 0) {
            perror("pthread_create (producer)"); 
            exit(EXIT_FAILURE);
        }
    }

    /* ------------------------------------------------------------------
     * Aguardar todos os PRODUTORES terminarem
     * ------------------------------------------------------------------ */
    for (int i = 0; i < P; i++) {
        if (pthread_join(prod_tids[i], NULL) != 0)
            perror("pthread_join (producer)");
    }

    /* Todos os produtores terminaram — enviar sinal seguro de fim aos consumidores */
    bb_send_eof(bb);

    /* ------------------------------------------------------------------
     * Aguardar todos os CONSUMIDORES terminarem
     * ------------------------------------------------------------------ */
    for (int i = 0; i < C; i++) {
        if (pthread_join(cons_tids[i], NULL) != 0)
            perror("pthread_join (consumer)");
    }

    double elapsed = now_secs() - t0;

    /* ------------------------------------------------------------------
     * Parar thread de dashboard
     * ------------------------------------------------------------------ */
    if (!cfg.verbose) {
        if (pthread_mutex_lock(&dash_arg.stop_mutex) != 0) perror("pthread_mutex_lock");
        dash_arg.stop = 1;
        if (pthread_mutex_unlock(&dash_arg.stop_mutex) != 0) perror("pthread_mutex_unlock");

        if (pthread_join(dash_tid, NULL) != 0) perror("pthread_join (dashboard)");

        long errs = 0;
        for (int i = 0; i < C; i++)
            errs += cons_args[i].result.count_error
                  + cons_args[i].result.count_critical;
        dashboard_draw(statuses, P, elapsed, 0, errs);
        dashboard_done(P);
        dashboard_arg_destroy(&dash_arg);
    }

    /* ------------------------------------------------------------------
     * Agregar resultados dos consumidores
     * ------------------------------------------------------------------ */
    WorkerResult *results = calloc((size_t)C, sizeof(WorkerResult));
    if (!results) { perror("calloc"); return EXIT_FAILURE; }

    long total_brute  = 0;
    long total_consec = 0;

    for (int i = 0; i < C; i++) {
        results[i]     = cons_args[i].result;
        total_brute   += cons_args[i].brute_alerts;
        total_consec  += cons_args[i].consec_alerts;
    }

    /* Corrigir: lines_total nos consumidores conta eventos classificados,
       mas o total real de linhas lidas é a soma dos produtores */
    long total_produced = 0;
    for (int i = 0; i < P; i++)
        total_produced += prod_args[i].lines_produced;

    GlobalResult gr;
    aggregate(results, C, &gr);
    gr.total_lines = total_produced;   /* corrigir com linhas reais lidas  */

    /* Imprimir relatório */
    /* Ajustar cfg para mostrar P no relatório como nº de "workers" */
    cfg.num_procs = P;
    print_report(&gr, results, C, &cfg, elapsed);

    /* Alertas de padrões detetados */
    printf("\n╔══════════════════════════════════════════════════╗\n");
    printf("║          PADROES DETETADOS (Req 2-C)             ║\n");
    printf("╠══════════════════════════════════════════════════╣\n");
    printf("║  Alertas brute-force    : %-10ld            ║\n", total_brute);
    printf("║  Alertas 5xx consecutivos: %-10ld           ║\n", total_consec);
    printf("║  Produtores             : %-10d            ║\n", P);
    printf("║  Consumidores           : %-10d            ║\n", C);
    printf("║  Linhas produzidas      : %-10ld            ║\n", total_produced);
    printf("╚══════════════════════════════════════════════════╝\n");

    if (cfg.has_output)
        write_report_json(&gr, &cfg, elapsed, cfg.output_file);

    if (cfg.verbose) {
        printf("\n[Benchmarks]\n");
        printf("  Linhas/segundo : %.0f\n",
               elapsed > 0 ? (double)total_produced / elapsed : 0);
        printf("  Produtores     : %d\n", P);
        printf("  Consumidores   : %d\n", C);
        printf("  Tempo          : %.3f s\n", elapsed);
    }

    /* ------------------------------------------------------------------
     * Limpeza
     * ------------------------------------------------------------------ */
    bb_destroy(bb);
    pthread_mutex_destroy(&status_mutex);
    free(bb); free(results);
    free(prod_tids); free(cons_tids);
    free(prod_args); free(cons_args);
    free(statuses); free(assignment); free(fl);
    return EXIT_SUCCESS;
}
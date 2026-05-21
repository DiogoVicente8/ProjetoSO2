/*
 * logAnalyzer_threads.c  —  Fase 2, Requisitos A + B
 *
 * Req 2-A: W worker threads com pthread_create/join e mutexes
 * Req 2-B: Thread dedicada ao dashboard de progresso
 *
 * Uso:
 *   ./logAnalyzer_threads <dir> <num_threads> <modo> [--verbose] [--output=f]
 *
 * Syscalls/funções POSIX utilizadas:
 *   open, read, close               — I/O sem fopen
 *   pthread_create, pthread_join    — criação e espera de threads
 *   pthread_mutex_init/lock/unlock/destroy — sincronização
 *   gettimeofday                    — medição de tempo
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
#include "thread_worker.h"
 
/* -------------------------------------------------------------------------
 * Helper de tempo
 * ------------------------------------------------------------------------- */
static double now_secs(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (double)tv.tv_sec + (double)tv.tv_usec / 1e6;
}
 
/* =========================================================================
 * MAIN
 * ========================================================================= */
int main(int argc, char *argv[])
{
    /* ------------------------------------------------------------------
     * A. Parse de argumentos (reutiliza config.c da Fase 1)
     * ------------------------------------------------------------------ */
    Config cfg;
    if (parse_args(argc, argv, &cfg) < 0)
        return EXIT_FAILURE;
 
    if (cfg.verbose)
        print_config(&cfg);
 
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
 
    /* Ajustar num_threads se houver menos ficheiros */
    if (cfg.num_procs > fl->count)
        cfg.num_procs = fl->count;
 
    fprintf(stderr, "[INFO] %d ficheiro(s), %d thread(s)\n",
            fl->count, cfg.num_procs);
 
    int N = cfg.num_procs;
 
    /* ------------------------------------------------------------------
     * Divisão balanceada de ficheiros pelas threads
     * ------------------------------------------------------------------ */
    int *assignment = malloc((size_t)fl->count * sizeof(int));
    if (!assignment) { perror("malloc"); return EXIT_FAILURE; }
    split_files_balanced(fl, N, assignment);
 
    /* ------------------------------------------------------------------
     * Alocar estruturas de controlo
     * ------------------------------------------------------------------ */
    pthread_t    *tids     = malloc((size_t)N * sizeof(pthread_t));
    ThreadArg    *args     = calloc((size_t)N, sizeof(ThreadArg));
    WorkerStatus *statuses = calloc((size_t)N, sizeof(WorkerStatus));
    WorkerResult *results  = calloc((size_t)N, sizeof(WorkerResult));
 
    if (!tids || !args || !statuses || !results) {
        perror("malloc"); return EXIT_FAILURE;
    }
 
    /* Mutex que protege o array de statuses (partilhado entre workers
       e a thread de dashboard) */
    pthread_mutex_t status_mutex;
    pthread_mutex_init(&status_mutex, NULL);
 
    /* Estimar linhas por thread para a barra de progresso */
    for (int i = 0; i < N; i++) {
        long est = 0;
        for (int j = 0; j < fl->count; j++)
            if (assignment[j] == i) est += count_lines(fl->paths[j]);
        statuses[i].total_lines = est > 0 ? est : 1;
        statuses[i].state       = STATE_IDLE;
        statuses[i].pid         = (pid_t)(i + 1);
    }
 
    /* ------------------------------------------------------------------
     * Inicializar dashboard
     * ------------------------------------------------------------------ */
    if (!cfg.verbose)
        dashboard_init(N);
 
    double t0 = now_secs();
 
    /* ------------------------------------------------------------------
     * Req 2-B: Criar thread dedicada ao dashboard
     * ------------------------------------------------------------------ */
    pthread_t    dash_tid;
    DashboardArg dash_arg;
 
    if (!cfg.verbose) {
        dashboard_arg_init(&dash_arg, statuses, N, &status_mutex, t0);
 
        if (pthread_create(&dash_tid, NULL, dashboard_thread_run, &dash_arg) != 0) {
            perror("pthread_create (dashboard)");
            return EXIT_FAILURE;
        }
    }
 
    /* ------------------------------------------------------------------
     * Req 2-A: Criar W worker threads com pthread_create()
     * ------------------------------------------------------------------ */
    for (int i = 0; i < N; i++) {
        args[i].thread_id    = i;
        args[i].num_threads  = N;
        args[i].fl           = fl;
        args[i].assignment   = assignment;
        args[i].cfg          = &cfg;
        args[i].status       = &statuses[i];
        args[i].status_mutex = &status_mutex;
 
        if (pthread_create(&tids[i], NULL, thread_worker_run, &args[i]) != 0) {
            perror("pthread_create (worker)");
            return EXIT_FAILURE;
        }
    }
 
    /* ------------------------------------------------------------------
     * Aguardar todas as worker threads com pthread_join()
     * ------------------------------------------------------------------ */
    for (int i = 0; i < N; i++) {
        if (pthread_join(tids[i], NULL) != 0)
            perror("pthread_join");
        results[i] = args[i].result;
    }
 
    double elapsed = now_secs() - t0;
 
    /* ------------------------------------------------------------------
     * Req 2-B: Sinalizar a thread de dashboard para parar e fazer join
     * ------------------------------------------------------------------ */
    if (!cfg.verbose) {
        /* Sinalizar paragem */
        pthread_mutex_lock(&dash_arg.stop_mutex);
        dash_arg.stop = 1;
        pthread_mutex_unlock(&dash_arg.stop_mutex);
 
        /* Aguardar a thread de dashboard terminar */
        pthread_join(dash_tid, NULL);
 
        /* Desenhar estado final (100% em todos) */
        long errs = 0;
        for (int i = 0; i < N; i++)
            errs += results[i].count_error + results[i].count_critical;
        dashboard_draw(statuses, N, elapsed, 0, errs);
        dashboard_done(N);
 
        dashboard_arg_destroy(&dash_arg);
    }
 
    /* ------------------------------------------------------------------
     * Agregar resultados e imprimir relatório
     * ------------------------------------------------------------------ */
    GlobalResult gr;
    aggregate(results, N, &gr);
 
    print_report(&gr, results, N, &cfg, elapsed);
 
    if (cfg.has_output)
        write_report_json(&gr, &cfg, elapsed, cfg.output_file);
 
    if (cfg.verbose) {
        printf("\n[Benchmarks]\n");
        printf("  Linhas/segundo : %.0f\n",
               elapsed > 0 ? (double)gr.total_lines / elapsed : 0);
        printf("  Threads        : %d\n", N);
        printf("  Tempo          : %.3f s\n", elapsed);
    }
 
    /* ------------------------------------------------------------------
     * Limpeza
     * ------------------------------------------------------------------ */
    pthread_mutex_destroy(&status_mutex);
    free(tids); free(args); free(statuses); free(results);
    free(assignment); free(fl);
    return EXIT_SUCCESS;
}
 
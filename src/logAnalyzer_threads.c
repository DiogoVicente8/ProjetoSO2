/*
 * logAnalyzer_threads.c  —  Fase 2, Requisitos A + B
 *
 * Req 2-A: W worker threads criadas com pthread_create/join e sincronizadas
 *          com mutexes (modelo de memória partilhada).
 * Req 2-B: Thread dedicada ao dashboard de progresso em tempo real.
 *
 * Diferença conceptual face à Fase 1: aqui NÃO há fork() nem pipes/sockets.
 * Todas as threads partilham o mesmo espaço de endereçamento, pelo que os
 * resultados são lidos diretamente da memória (sem IPC) e a sincronização
 * faz-se com mutexes em vez de comunicação entre processos.
 *
 * Uso:
 *   ./logAnalyzer_threads <dir> <num_threads> <modo> [--verbose] [--output=f]
 *
 * Syscalls/funções POSIX utilizadas:
 *   open, read, close                       — I/O sem fopen
 *   pthread_create, pthread_join            — criação e espera de threads
 *   pthread_mutex_init/lock/unlock/destroy  — sincronização
 *   gettimeofday                            — medição de tempo
 */

#define _GNU_SOURCE                               /* Ativa extensões GNU. */
#include <stdio.h>                                /* printf, fprintf, perror. */
#include <stdlib.h>                               /* malloc, calloc, free, exit. */
#include <string.h>                               /* (usado indiretamente). */
#include <unistd.h>                               /* close. */
#include <pthread.h>                              /* pthread_*. */
#include <sys/time.h>                             /* gettimeofday. */
#include <errno.h>                                /* errno. */

#include "../include/config.h"                    /* Config, parse_args. */
#include "../include/files.h"                     /* FileList, discover_files, split_files_balanced. */
#include "../include/ipc.h"                       /* WorkerResult, GlobalResult, aggregate. */
#include "../include/dashboard.h"                 /* WorkerStatus, dashboard_*. */
#include "../include/dashboard_thread.h"          /* DashboardArg, thread do dashboard. */
#include "../include/report.h"                    /* print_report, write_report_json. */
#include "../include/thread_worker.h"             /* ThreadArg, thread_worker_run. */

/* --------------------------------------------------------------------------
 * Helper de tempo: tempo atual em segundos com precisão de microsegundos.
 * -------------------------------------------------------------------------- */
static double now_secs(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (double)tv.tv_sec + (double)tv.tv_usec / 1e6;
}

/* Tempo decorrido desde t0, com um mínimo para evitar divisão por zero. */
static double elapsed_since(double t0)
{
    double elapsed = now_secs() - t0;
    return elapsed > 0.000001 ? elapsed : 0.000001;
}

/* =========================================================================
 * MAIN
 * ========================================================================= */
int main(int argc, char *argv[])
{
    /* ------------------------------------------------------------------
     * REQUISITO A — Parse de argumentos (reutiliza config.c da Fase 1)
     * ------------------------------------------------------------------ */
    Config cfg;
    if (parse_args(argc, argv, &cfg) < 0)         /* Valida e preenche a config. */
        return EXIT_FAILURE;                      /* CLI inválida: sai. */

    if (cfg.verbose)
        print_config(&cfg);                       /* Mostra a config em modo verboso. */

    /* ------------------------------------------------------------------
     * Descoberta de ficheiros a processar
     * ------------------------------------------------------------------ */
    FileList *fl = calloc(1, sizeof(FileList));    /* Aloca a lista de ficheiros. */
    if (!fl) { perror("calloc"); return EXIT_FAILURE; }

    if (discover_files(cfg.log_dir, fl) <= 0) {    /* Percorre o diretório recursivamente. */
        fprintf(stderr, "Erro: nenhum ficheiro .log/.json em '%s'\n",
                cfg.log_dir);
        free(fl); return EXIT_FAILURE;
    }

    /* Se há menos ficheiros do que threads pedidas, reduz o número de threads. */
    if (cfg.num_procs > fl->count)
        cfg.num_procs = fl->count;

    fprintf(stderr, "[INFO] %d ficheiro(s), %d thread(s)\n",
            fl->count, cfg.num_procs);

    int N = cfg.num_procs;                         /* N = número de worker threads. */

    /* ------------------------------------------------------------------
     * Divisão balanceada de ficheiros pelas threads (algoritmo greedy
     * por tamanho, reutilizado da Fase 1)
     * ------------------------------------------------------------------ */
    int *assignment = malloc((size_t)fl->count * sizeof(int));   /* assignment[i] = thread dona do file i. */
    if (!assignment) { perror("malloc"); return EXIT_FAILURE; }
    split_files_balanced(fl, N, assignment);

    /* ------------------------------------------------------------------
     * Alocar estruturas de controlo
     * ------------------------------------------------------------------ */
    pthread_t    *tids     = malloc((size_t)N * sizeof(pthread_t));   /* IDs das threads. */
    ThreadArg    *args     = calloc((size_t)N, sizeof(ThreadArg));    /* Argumento de cada thread. */
    WorkerStatus *statuses = calloc((size_t)N, sizeof(WorkerStatus)); /* Estado p/ dashboard. */
    WorkerResult *results  = calloc((size_t)N, sizeof(WorkerResult)); /* Resultado de cada thread. */

    if (!tids || !args || !statuses || !results) {
        perror("malloc"); return EXIT_FAILURE;
    }

    /* Mutex único que protege o array de statuses, partilhado entre todas
     * as worker threads (que escrevem progresso) e a thread de dashboard
     * (que lê para desenhar). */
    pthread_mutex_t status_mutex;
    pthread_mutex_init(&status_mutex, NULL);

    /* Estima as linhas de cada thread (somando os ficheiros que lhe tocam)
     * para que a barra de progresso tenha um total de referência. */
    for (int i = 0; i < N; i++) {
        long est = 0;
        for (int j = 0; j < fl->count; j++)
            if (assignment[j] == i) est += count_lines(fl->paths[j]);
        statuses[i].total_lines = est > 0 ? est : 1;   /* Evita total zero. */
        statuses[i].state       = STATE_IDLE;          /* Estado inicial. */
        statuses[i].pid         = (pid_t)(i + 1);      /* ID mostrado no dashboard. */
    }

    /* ------------------------------------------------------------------
     * Inicializar o dashboard (reserva espaço no terminal)
     * ------------------------------------------------------------------ */
    if (!cfg.verbose)
        dashboard_init(N);

    double t0 = now_secs();                        /* Marca o instante de início. */

    /* ------------------------------------------------------------------
     * REQUISITO B — Criar a thread dedicada ao dashboard
     *
     * Esta thread corre em paralelo com os workers e atualiza a interface
     * a cada segundo até a main thread lhe pedir para parar.
     * ------------------------------------------------------------------ */
    pthread_t    dash_tid;
    DashboardArg dash_arg;

    if (!cfg.verbose) {
        dashboard_arg_init(&dash_arg, statuses, N, &status_mutex, t0);  /* Prepara o argumento. */

        if (pthread_create(&dash_tid, NULL, dashboard_thread_run, &dash_arg) != 0) {
            perror("pthread_create (dashboard)");
            return EXIT_FAILURE;
        }
    }

    /* ------------------------------------------------------------------
     * REQUISITO A — Criar as N worker threads com pthread_create()
     * ------------------------------------------------------------------ */
    for (int i = 0; i < N; i++) {
        args[i].thread_id    = i;                  /* Índice da thread. */
        args[i].num_threads  = N;                  /* Total de threads. */
        args[i].fl           = fl;                 /* Lista de ficheiros (só leitura). */
        args[i].assignment   = assignment;         /* Mapa ficheiro→thread. */
        args[i].cfg          = &cfg;               /* Configuração. */
        args[i].status       = &statuses[i];       /* O seu slot de status. */
        args[i].status_mutex = &status_mutex;      /* Mutex partilhado dos statuses. */

        if (pthread_create(&tids[i], NULL, thread_worker_run, &args[i]) != 0) {
            perror("pthread_create (worker)");
            return EXIT_FAILURE;
        }
    }

    /* ------------------------------------------------------------------
     * REQUISITO A — Aguardar todas as worker threads com pthread_join()
     *
     * pthread_join() bloqueia até a thread terminar. Como as threads
     * partilham memória, depois do join podemos ler args[i].result
     * diretamente (não há IPC como na Fase 1).
     * ------------------------------------------------------------------ */
    for (int i = 0; i < N; i++) {
        if (pthread_join(tids[i], NULL) != 0)
            perror("pthread_join");
        results[i] = args[i].result;               /* Copia o resultado da thread. */
    }

    double elapsed = elapsed_since(t0);            /* Tempo total de processamento. */

    /* ------------------------------------------------------------------
     * REQUISITO B — Parar a thread de dashboard e desenhar o estado final
     * ------------------------------------------------------------------ */
    if (!cfg.verbose) {
        /* Sinaliza a paragem (sob mutex, pois a flag é partilhada). */
        pthread_mutex_lock(&dash_arg.stop_mutex);
        dash_arg.stop = 1;
        pthread_mutex_unlock(&dash_arg.stop_mutex);

        pthread_join(dash_tid, NULL);              /* Espera a thread de dashboard terminar. */

        /* Desenha o estado final (todos a 100%) com totais consolidados. */
        long errs = 0;
        long lines = 0;
        for (int i = 0; i < N; i++)
            errs += results[i].count_error + results[i].count_critical;   /* Soma de erros. */
        for (int i = 0; i < N; i++)
            lines += statuses[i].lines_processed;  /* Soma de linhas. */
        long eps = (long)((double)lines / elapsed);    /* Eventos por segundo. */
        dashboard_draw(statuses, N, elapsed, eps, errs);
        dashboard_done(N);

        dashboard_arg_destroy(&dash_arg);          /* Destrói o mutex da flag. */
    }

    /* ------------------------------------------------------------------
     * Agregar resultados das threads e imprimir o relatório final
     * ------------------------------------------------------------------ */
    GlobalResult gr;
    aggregate(results, N, &gr);                    /* Soma os resultados de todas as threads. */

    print_report(&gr, results, N, &cfg, elapsed);  /* Relatório no terminal. */

    if (cfg.has_output)
        write_report_json(&gr, &cfg, elapsed, cfg.output_file);   /* Relatório JSON opcional. */

    if (cfg.verbose) {
        printf("\n[Benchmarks]\n");
        printf("  Linhas/segundo : %.0f\n",
               elapsed > 0 ? (double)gr.total_lines / elapsed : 0);
        printf("  Threads        : %d\n", N);
        printf("  Tempo          : %.3f s\n", elapsed);
    }

    /* ------------------------------------------------------------------
     * Limpeza de recursos
     * ------------------------------------------------------------------ */
    pthread_mutex_destroy(&status_mutex);          /* Destrói o mutex dos statuses. */
    free(tids); free(args); free(statuses); free(results);
    free(assignment); free(fl);
    return EXIT_SUCCESS;
}
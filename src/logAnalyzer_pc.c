/*
 * logAnalyzer_pc.c  —  Fase 2, Requisito C
 *
 * Arquitetura Produtor-Consumidor com Bounded Buffer:
 *   P threads produtoras  — leem ficheiros e inserem linhas no buffer
 *   C threads consumidoras — retiram do buffer, classificam e detetam padrões
 *   1 thread de dashboard  — atualiza o progresso em tempo real (sem busy-wait)
 *
 * É a arquitetura mais avançada do projeto: desacopla a LEITURA (I/O-bound,
 * feita pelos produtores) do PROCESSAMENTO (CPU-bound, feito pelos consumidores)
 * através de uma fila partilhada e sincronizada. Permite ajustar P e C de forma
 * independente para equilibrar I/O e CPU.
 *
 * Uso:
 *   ./logAnalyzer_pc <dir> <num_produtores> <modo> [--consumers=C] [--verbose] [--output=f]
 *
 * Syscalls/funções POSIX utilizadas:
 *   open, read, close                         — I/O sem fopen
 *   pthread_create, pthread_join              — criação e espera de threads
 *   pthread_mutex_init/lock/unlock/destroy    — exclusão mútua
 *   sem_init, sem_wait, sem_post, sem_destroy — sincronização do buffer
 *   gettimeofday                              — medição de tempo
 */

#define _GNU_SOURCE                               /* Ativa extensões GNU. */
#include <stdio.h>                                /* printf, fprintf, perror. */
#include <stdlib.h>                               /* malloc, calloc, free, atoi, exit. */
#include <string.h>                               /* strncmp. */
#include <unistd.h>                               /* close. */
#include <pthread.h>                              /* pthread_*. */
#include <sys/time.h>                             /* gettimeofday. */
#include <errno.h>                                /* errno. */

#include "../include/config.h"                    /* Config, parse_args. */
#include "../include/files.h"                     /* FileList, discover_files, split_files_balanced. */
#include "../include/ipc.h"                       /* WorkerResult, GlobalResult, aggregate. */
#include "../include/dashboard.h"                 /* WorkerStatus, dashboard_*. */
#include "../include/dashboard_thread.h"          /* DashboardArg. */
#include "../include/report.h"                    /* print_report, write_report_json. */
#include "../include/bounded_buffer.h"            /* BoundedBuffer, bb_*. */
#include "../include/pc_worker.h"                 /* ProducerArg, ConsumerArg, producer/consumer_run. */

#define DEFAULT_CONSUMERS 4                       /* Nº de consumidores se não for indicado. */

/* --------------------------------------------------------------------------
 * Helpers de tempo
 * -------------------------------------------------------------------------- */
static double now_secs(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (double)tv.tv_sec + (double)tv.tv_usec / 1e6;
}

static double elapsed_since(double t0)
{
    double elapsed = now_secs() - t0;
    return elapsed > 0.000001 ? elapsed : 0.000001;   /* Mínimo para evitar div/0. */
}

/* --------------------------------------------------------------------------
 * Parse da opção --consumers=N (específica desta fase)
 * -------------------------------------------------------------------------- */
static int parse_consumers(int argc, char *argv[], int default_val)
{
    for (int i = 4; i < argc; i++) {              /* Procura nas opções (a partir do 4º arg). */
        if (strncmp(argv[i], "--consumers=", 12) == 0) {
            int n = atoi(argv[i] + 12);           /* Converte o número após o '='. */
            return (n >= 1) ? n : default_val;    /* Valida (mínimo 1). */
        }
    }
    return default_val;                           /* Não especificado: usa o default. */
}

/* =========================================================================
 * MAIN
 * ========================================================================= */
int main(int argc, char *argv[])
{
    /* ------------------------------------------------------------------
     * Parse de argumentos (reutiliza config.c) + opção --consumers
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

    int P = cfg.num_procs;   /* P = número de threads produtoras. */
    int C = n_consumers;     /* C = número de threads consumidoras. */

    if (P > fl->count) P = fl->count;             /* Não faz sentido ter mais produtores que ficheiros. */

    fprintf(stderr, "[INFO] %d ficheiro(s) | %d produtor(es) | %d consumidor(es)\n",
            fl->count, P, C);

    /* ------------------------------------------------------------------
     * Divisão balanceada de ficheiros pelos PRODUTORES
     * ------------------------------------------------------------------ */
    int *assignment = malloc((size_t)fl->count * sizeof(int));
    if (!assignment) { perror("malloc"); free(fl); return EXIT_FAILURE; }
    split_files_balanced(fl, P, assignment);

    /* ------------------------------------------------------------------
     * Criar o Bounded Buffer partilhado (com C registado para o EOF)
     * ------------------------------------------------------------------ */
    BoundedBuffer *bb = calloc(1, sizeof(BoundedBuffer));
    if (!bb) { perror("calloc"); free(assignment); free(fl); return EXIT_FAILURE; }
    bb_init(bb, C);

    /* ------------------------------------------------------------------
     * Alocar estruturas de controlo das threads
     * ------------------------------------------------------------------ */
    pthread_t    *prod_tids = malloc((size_t)P * sizeof(pthread_t));   /* IDs produtores. */
    pthread_t    *cons_tids = malloc((size_t)C * sizeof(pthread_t));   /* IDs consumidores. */
    ProducerArg  *prod_args = calloc((size_t)P, sizeof(ProducerArg));  /* Args produtores. */
    ConsumerArg  *cons_args = calloc((size_t)C, sizeof(ConsumerArg));  /* Args consumidores. */
    WorkerStatus *statuses  = calloc((size_t)P, sizeof(WorkerStatus)); /* Status (dos produtores). */

    if (!prod_tids || !cons_tids || !prod_args || !cons_args || !statuses) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    pthread_mutex_t status_mutex;                 /* Mutex dos statuses (produtores + dashboard). */
    if (pthread_mutex_init(&status_mutex, NULL) != 0) {
        perror("pthread_mutex_init (status)");
        exit(EXIT_FAILURE);
    }

    /* Estima as linhas de cada produtor para a barra de progresso. */
    for (int i = 0; i < P; i++) {
        long est = 0;
        for (int j = 0; j < fl->count; j++)
            if (assignment[j] == i) est += count_lines(fl->paths[j]);
        statuses[i].total_lines = est > 0 ? est : 1;
        statuses[i].state       = STATE_IDLE;
        statuses[i].pid         = (pid_t)(i + 1);
    }

    /* ------------------------------------------------------------------
     * Inicializar dashboard + thread dedicada (Req 2-B reutilizado)
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
     * Criar as C threads CONSUMIDORAS primeiro
     *
     * Criam-se antes dos produtores para já estarem bloqueadas em
     * sem_wait(full), prontas a consumir assim que a primeira linha entrar
     * no buffer (evita que o buffer encha enquanto ninguém consome).
     * ------------------------------------------------------------------ */
    for (int i = 0; i < C; i++) {
        cons_args[i].consumer_id = i;
        cons_args[i].bb          = bb;             /* Buffer partilhado. */
        cons_args[i].cfg         = &cfg;

        if (pthread_create(&cons_tids[i], NULL, consumer_run, &cons_args[i]) != 0) {
            perror("pthread_create (consumer)");
            exit(EXIT_FAILURE);
        }
    }

    /* ------------------------------------------------------------------
     * Criar as P threads PRODUTORAS
     * ------------------------------------------------------------------ */
    for (int i = 0; i < P; i++) {
        prod_args[i].producer_id   = i;
        prod_args[i].num_producers = P;
        prod_args[i].fl            = fl;
        prod_args[i].assignment    = assignment;
        prod_args[i].bb            = bb;           /* Buffer partilhado. */
        prod_args[i].status        = &statuses[i];
        prod_args[i].status_mutex  = &status_mutex;

        if (pthread_create(&prod_tids[i], NULL, producer_run, &prod_args[i]) != 0) {
            perror("pthread_create (producer)");
            exit(EXIT_FAILURE);
        }
    }

    /* ------------------------------------------------------------------
     * Aguardar TODOS os produtores terminarem
     * ------------------------------------------------------------------ */
    for (int i = 0; i < P; i++) {
        if (pthread_join(prod_tids[i], NULL) != 0)
            perror("pthread_join (producer)");
    }

    /* Já não entram mais linhas: encerra o buffer e acorda os consumidores
     * (o sinal propaga-se em cadeia dentro de bb_get — ver bounded_buffer.c). */
    bb_send_eof(bb);

    /* ------------------------------------------------------------------
     * Aguardar TODOS os consumidores terminarem
     * ------------------------------------------------------------------ */
    for (int i = 0; i < C; i++) {
        if (pthread_join(cons_tids[i], NULL) != 0)
            perror("pthread_join (consumer)");
    }

    double elapsed = elapsed_since(t0);           /* Tempo total. */

    /* ------------------------------------------------------------------
     * Parar a thread de dashboard e desenhar o estado final
     * ------------------------------------------------------------------ */
    if (!cfg.verbose) {
        if (pthread_mutex_lock(&dash_arg.stop_mutex) != 0) perror("pthread_mutex_lock");
        dash_arg.stop = 1;                        /* Sinaliza paragem. */
        if (pthread_mutex_unlock(&dash_arg.stop_mutex) != 0) perror("pthread_mutex_unlock");

        if (pthread_join(dash_tid, NULL) != 0) perror("pthread_join (dashboard)");

        long errs = 0;
        long lines = 0;
        for (int i = 0; i < C; i++)
            errs += cons_args[i].result.count_error
                  + cons_args[i].result.count_critical;   /* Erros vêm dos consumidores. */
        for (int i = 0; i < P; i++)
            lines += statuses[i].lines_processed;          /* Linhas vêm dos produtores. */
        long eps = (long)((double)lines / elapsed);
        dashboard_draw(statuses, P, elapsed, eps, errs);
        dashboard_done(P);
        dashboard_arg_destroy(&dash_arg);
    }

    /* ------------------------------------------------------------------
     * Agregar resultados dos CONSUMIDORES (são eles que classificam)
     * ------------------------------------------------------------------ */
    WorkerResult *results = calloc((size_t)C, sizeof(WorkerResult));
    if (!results) { perror("calloc"); return EXIT_FAILURE; }

    long total_brute  = 0;                        /* Total de alertas de brute-force. */
    long total_consec = 0;                        /* Total de alertas de 5xx consecutivos. */

    for (int i = 0; i < C; i++) {
        results[i]     = cons_args[i].result;     /* Copia o resultado de cada consumidor. */
        total_brute   += cons_args[i].brute_alerts;
        total_consec  += cons_args[i].consec_alerts;
    }

    /* O total REAL de linhas lidas é a soma dos produtores (os consumidores
     * contam apenas os eventos que passam no filtro de modo). */
    long total_produced = 0;
    for (int i = 0; i < P; i++)
        total_produced += prod_args[i].lines_produced;

    GlobalResult gr;
    aggregate(results, C, &gr);                   /* Soma os resultados dos consumidores. */
    gr.total_lines = total_produced;              /* Corrige com as linhas reais lidas. */

    /* Relatório final (mostra P como nº de "workers"). */
    cfg.num_procs = P;
    print_report(&gr, results, C, &cfg, elapsed);

    /* Resumo dos padrões detetados (exclusivo do Req 2-C). */
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
     * Limpeza de todos os recursos
     * ------------------------------------------------------------------ */
    bb_destroy(bb);                               /* Semáforos e mutex do buffer. */
    pthread_mutex_destroy(&status_mutex);         /* Mutex dos statuses. */
    free(bb); free(results);
    free(prod_tids); free(cons_tids);
    free(prod_args); free(cons_args);
    free(statuses); free(assignment); free(fl);
    return EXIT_SUCCESS;
}
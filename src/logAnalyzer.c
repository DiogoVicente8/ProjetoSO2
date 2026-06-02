/*
 * logAnalyzer.c — Fase 1
 *
 * Orquestrador dos requisitos A, B, C, D e E.
 * A implementação de processos/IPC/dashboard está em phase1_process.c.
 */

#include <stdio.h>
#include <stdlib.h>

#include "../include/config.h"
#include "../include/dashboard.h"
#include "../include/files.h"
#include "../include/ipc.h"
#include "../include/phase1_process.h"
#include "../include/report.h"

/* ==========================================================================
 * MAPA DA FASE 1 — Ordem dos requisitos do enunciado
 *
 * A. Interface CLI
 *    - parse_args(), print_config()                         -> config.c
 *    - print_report(), write_report_json()                  -> report.c
 *
 * B. Arquitetura multi-processo básica
 *    - phase1_parent_discover_log_files()                   -> pai descobre logs
 *    - phase1_parent_spawn_workers()                        -> pai faz fork()
 *    - process_files()                                      -> filhos processam
 *    - phase1_parent_wait_for_workers()                     -> pai faz waitpid()
 *
 * C. Comunicação via pipes anónimos
 *    - phase1_parent_setup_ipc()                            -> cria pipe()
 *    - phase1_parent_collect_worker_results()               -> pai lê resultados
 *    - readn()/writen(), serialize/parse, aggregate()       -> ipc.c
 *
 * D. Dashboard de progresso
 *    - phase1_parent_prepare_worker_statuses()              -> estima trabalho
 *    - dashboard_init/draw/done()                           -> dashboard.c
 *
 * E. Unix Domain Sockets
 *    - phase1_parent_setup_ipc()                            -> socket/bind/listen
 *    - phase1_parent_collect_worker_results()               -> accept()/read()
 * ========================================================================== */

/* ==========================================================================
 * MAIN — Orquestrador da Fase 1
 * ========================================================================== */
int main(int argc, char *argv[])
{
    /* -------------------------------------------------------------------------
     * REQUISITO A — Interface de linha de comandos
     * ------------------------------------------------------------------------- */
    Config cfg;
    if (parse_args(argc, argv, &cfg) < 0)
        return EXIT_FAILURE;

    if (cfg.verbose)
        print_config(&cfg);

    /* -------------------------------------------------------------------------
     * REQUISITO B.1 — Processo PAI: descobrir ficheiros .log/.json
     * ------------------------------------------------------------------------- */
    FileList *fl = calloc(1, sizeof(FileList));
    if (!fl) {
        perror("calloc");
        return EXIT_FAILURE;
    }

    if (phase1_parent_discover_log_files(&cfg, fl) < 0) {
        free(fl);
        return EXIT_FAILURE;
    }

    /* -------------------------------------------------------------------------
     * Estruturas de controlo do processo pai
     * ------------------------------------------------------------------------- */
    pid_t        *pids     = malloc((size_t)cfg.num_procs * sizeof(pid_t));
    WorkerResult *results  = calloc((size_t)cfg.num_procs, sizeof(WorkerResult));
    WorkerStatus *statuses = calloc((size_t)cfg.num_procs, sizeof(WorkerStatus));
    if (!pids || !results || !statuses) {
        perror("malloc");
        free(fl);
        free(pids);
        free(results);
        free(statuses);
        return EXIT_FAILURE;
    }

    bool use_sockets = false;
#ifdef USE_SOCKETS
    use_sockets = true;
#endif

    int pipe_rd = -1, pipe_wr = -1;
    int server_fd = -1;

    /* -------------------------------------------------------------------------
     * REQUISITO C / E — Criar meio de comunicação IPC
     * C: pipe anónimo; E: Unix Domain Socket quando compilado com USE_SOCKETS.
     * ------------------------------------------------------------------------- */
    if (phase1_parent_setup_ipc(use_sockets, cfg.num_procs,
                                &pipe_rd, &pipe_wr, &server_fd) < 0)
        return EXIT_FAILURE;

    /* -------------------------------------------------------------------------
     * REQUISITO D — Inicializar dashboard de progresso
     * ------------------------------------------------------------------------- */
    phase1_parent_prepare_worker_statuses(fl, &cfg, statuses);
    if (!cfg.verbose)
        dashboard_init(cfg.num_procs);
    fflush(stdout);

    double t0 = phase1_now_secs();

    /* -------------------------------------------------------------------------
     * REQUISITO B.2 — Processo PAI: criar N filhos e distribuir trabalho
     * ------------------------------------------------------------------------- */
    if (phase1_parent_spawn_workers(&cfg, fl, pids, statuses, pipe_rd, pipe_wr,
                                    server_fd, use_sockets) < 0)
        return EXIT_FAILURE;

    /* -------------------------------------------------------------------------
     * REQUISITO C / E — Pai recolhe resultados dos workers
     * ------------------------------------------------------------------------- */
    int received = phase1_parent_collect_worker_results(&cfg, pids, results,
                                                        statuses, pipe_rd,
                                                        pipe_wr, server_fd,
                                                        use_sockets, t0);

    /* -------------------------------------------------------------------------
     * REQUISITO B.3 — Processo PAI: aguardar todos os filhos com waitpid()
     * ------------------------------------------------------------------------- */
    phase1_parent_wait_for_workers(pids, statuses, cfg.num_procs);

    double elapsed = phase1_now_secs() - t0;

    /* -------------------------------------------------------------------------
     * REQUISITO D — Dashboard final
     * ------------------------------------------------------------------------- */
    if (!cfg.verbose) {
        long errs = 0;
        long lines = 0;
        for (int i = 0; i < received; i++)
            errs += results[i].count_error + results[i].count_critical;
        for (int i = 0; i < cfg.num_procs; i++)
            lines += statuses[i].lines_processed;
        long eps = elapsed > 0 ? (long)((double)lines / elapsed) : 0;
        dashboard_draw(statuses, cfg.num_procs, elapsed, eps, errs);
        dashboard_done(cfg.num_procs);
    }

    /* -------------------------------------------------------------------------
     * REQUISITO A / C — Relatório final agregado
     * ------------------------------------------------------------------------- */
    GlobalResult gr;
    aggregate(results, received, &gr);

    print_report(&gr, results, received, &cfg, elapsed);

    if (cfg.has_output)
        write_report_json(&gr, &cfg, elapsed, cfg.output_file);

    if (cfg.verbose) {
        printf("\n[Benchmarks]\n");
        printf("  Linhas/segundo : %.0f\n",
               elapsed > 0 ? (double)gr.total_lines / elapsed : 0);
        printf("  Workers        : %d\n", cfg.num_procs);
        printf("  Tempo          : %.3f s\n", elapsed);
    }

    free(fl);
    free(pids);
    free(results);
    free(statuses);
    return EXIT_SUCCESS;
}

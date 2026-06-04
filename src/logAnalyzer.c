#include <stdio.h>      /* printf */
#include <stdlib.h>     /* EXIT_SUCCESS, EXIT_FAILURE, malloc, calloc, free */

#include "../include/config.h"          /* Definições de Config e parsing de argumentos */
#include "../include/dashboard.h"       /* Interface de dashboard de progresso */
#include "../include/files.h"           /* Descoberta e divisão de ficheiros */
#include "../include/ipc.h"             /* Comunicação IPC e funções auxiliares */
#include "../include/phase1_process.h"  /* Funções da fase 1 do processo pai */
#include "../include/report.h"          /* Funções de relatório terminal/JSON */

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
    Config cfg;                             /* Estrutura que guarda opções CLI. */
    if (parse_args(argc, argv, &cfg) < 0)
        return EXIT_FAILURE;                /* Se parsing falhar, sai com erro. */

    if (cfg.verbose)
        print_config(&cfg);                 /* Mostra opções do programa se verbose estiver ativo. */

    /* -------------------------------------------------------------------------
     * REQUISITO B.1 — Processo PAI: descobrir ficheiros .log/.json
     * ------------------------------------------------------------------------- */
    FileList *fl = calloc(1, sizeof(FileList));
    /* Aloca FileList e inicializa contagem a zero. */
    if (!fl) {
        perror("calloc");
        return EXIT_FAILURE;                /* Falha de memória. */
    }

    if (phase1_parent_discover_log_files(&cfg, fl) < 0) {
        free(fl);
        return EXIT_FAILURE;                /* Falha ao descobrir ficheiros de log. */
    }

    /* -------------------------------------------------------------------------
     * Estruturas de controlo do processo pai
     * ------------------------------------------------------------------------- */
    pid_t        *pids     = malloc((size_t)cfg.num_procs * sizeof(pid_t));
    WorkerResult *results  = calloc((size_t)cfg.num_procs, sizeof(WorkerResult));
    WorkerStatus *statuses = calloc((size_t)cfg.num_procs, sizeof(WorkerStatus));
    /* Aloca arrays para PIDs, resultados e statuses dos workers. */
    if (!pids || !results || !statuses) {
        perror("malloc");
        free(fl);
        free(pids);
        free(results);
        free(statuses);
        return EXIT_FAILURE;                /* Falha de memória ao preparar estruturas de controlo. */
    }

    bool use_sockets = false;               /* Usa pipe por padrão. */
#ifdef USE_SOCKETS
    use_sockets = true;                     /* Alterna para socket Unix Domain se habilitado. */
#endif

    int pipe_rd = -1, pipe_wr = -1;         /* Descritores para leitura e escrita do pipe. */
    int server_fd = -1;                     /* Descritor do servidor socket, se usado. */

    /* -------------------------------------------------------------------------
     * REQUISITO C / E — Criar meio de comunicação IPC
     * C: pipe anónimo; E: Unix Domain Socket quando compilado com USE_SOCKETS.
     * ------------------------------------------------------------------------- */
    if (phase1_parent_setup_ipc(use_sockets, cfg.num_procs,
                                &pipe_rd, &pipe_wr, &server_fd) < 0)
        return EXIT_FAILURE;                /* Falha na configuração do mecanismo de IPC. */

    /* -------------------------------------------------------------------------
     * REQUISITO D — Inicializar dashboard de progresso
     * ------------------------------------------------------------------------- */
    phase1_parent_prepare_worker_statuses(fl, &cfg, statuses);
    /* Calcula estimativas de linhas para cada worker antes de iniciar. */
    if (!cfg.verbose)
        dashboard_init(cfg.num_procs);       /* Desenha o dashboard inicial. */
    fflush(stdout);                         /* Garante que tudo é impresso imediatamente. */

    double t0 = phase1_now_secs();          /* Tempo de início da execução. */

    /* -------------------------------------------------------------------------
     * REQUISITO B.2 — Processo PAI: criar N filhos e distribuir trabalho
     * ------------------------------------------------------------------------- */
    if (phase1_parent_spawn_workers(&cfg, fl, pids, statuses, pipe_rd, pipe_wr,
                                    server_fd, use_sockets) < 0)
        return EXIT_FAILURE;                /* Falha ao criar processos filhos. */

    /* -------------------------------------------------------------------------
     * REQUISITO C / E — Pai recolhe resultados dos workers
     * ------------------------------------------------------------------------- */
    int received = phase1_parent_collect_worker_results(&cfg, pids, results,
                                                        statuses, pipe_rd,
                                                        pipe_wr, server_fd,
                                                        use_sockets, t0);
    /* Número de resultados de workers recebidos com sucesso. */

    /* -------------------------------------------------------------------------
     * REQUISITO B.3 — Processo PAI: aguardar todos os filhos com waitpid()
     * ------------------------------------------------------------------------- */
    phase1_parent_wait_for_workers(pids, statuses, cfg.num_procs);
    /* Espera até todos os workers terminarem. */

    double elapsed = phase1_now_secs() - t0; /* Calcula duração total do processamento. */

    /* -------------------------------------------------------------------------
     * REQUISITO D — Dashboard final
     * ------------------------------------------------------------------------- */
    if (!cfg.verbose) {
        long errs = 0;                       /* Total de erros graves. */
        long lines = 0;                      /* Total de linhas processadas. */
        for (int i = 0; i < received; i++)
            errs += results[i].count_error + results[i].count_critical;
        /* Soma erros e críticos de cada resultado de worker. */
        for (int i = 0; i < cfg.num_procs; i++)
            lines += statuses[i].lines_processed;
        /* Soma linhas processadas de cada status. */
        long eps = elapsed > 0 ? (long)((double)lines / elapsed) : 0;
        dashboard_draw(statuses, cfg.num_procs, elapsed, eps, errs);
        /* Atualiza o dashboard com os valores finais. */
        dashboard_done(cfg.num_procs);        /* Finaliza a renderização do dashboard. */
    }

    /* -------------------------------------------------------------------------
     * REQUISITO A / C — Relatório final agregado
     * ------------------------------------------------------------------------- */
    GlobalResult gr;                        /* Resultado agregado global. */
    aggregate(results, received, &gr);      /* Agrega todos os resultados individuais. */

    print_report(&gr, results, received, &cfg, elapsed);
    /* Exibe o relatório final no terminal. */

    if (cfg.has_output)
        write_report_json(&gr, &cfg, elapsed, cfg.output_file);
    /* Escreve JSON para o ficheiro de output se pedido. */

    if (cfg.verbose) {
        printf("\n[Benchmarks]\n");
        printf("  Linhas/segundo : %.0f\n",
               elapsed > 0 ? (double)gr.total_lines / elapsed : 0);
        printf("  Workers        : %d\n", cfg.num_procs);
        printf("  Tempo          : %.3f s\n", elapsed);
        /* Mostra métricas de benchmark em modo verbose. */
    }

    free(fl);                               /* Liberta memória da lista de ficheiros. */
    free(pids);                             /* Liberta memória do array de PIDs. */
    free(results);                          /* Liberta memória dos resultados. */
    free(statuses);                         /* Liberta memória dos estados. */
    return EXIT_SUCCESS;                    /* Termina o programa com êxito. */
}

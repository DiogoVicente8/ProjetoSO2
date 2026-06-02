#ifndef PHASE1_PROCESS_H
#define PHASE1_PROCESS_H

#include <stdbool.h>
#include <sys/types.h>

#include "config.h"
#include "dashboard.h"
#include "files.h"
#include "ipc.h"

/* Helper de tempo usado pela Fase 1. */
double phase1_now_secs(void);

/* Requisito B.1: pai descobre ficheiros .log/.json e ajusta nº de workers. */
int phase1_parent_discover_log_files(Config *cfg, FileList *fl);

/* Requisito B.2: pai cria N filhos com fork(). */
int phase1_parent_spawn_workers(const Config *cfg, const FileList *fl,
                                pid_t *pids, WorkerStatus *statuses,
                                int pipe_rd, int pipe_wr, int server_fd,
                                bool use_sockets);

/* Requisito B.3: pai espera por todos os filhos com waitpid(). */
void phase1_parent_wait_for_workers(pid_t *pids, WorkerStatus *statuses,
                                    int num_procs);

/* Requisito D: pai prepara o estado inicial usado pelo dashboard. */
void phase1_parent_prepare_worker_statuses(const FileList *fl, const Config *cfg,
                                           WorkerStatus *statuses);

/* Requisito C/E: cria pipe anónimo ou servidor Unix Domain Socket. */
int phase1_parent_setup_ipc(bool use_sockets, int num_procs,
                            int *pipe_rd, int *pipe_wr, int *server_fd);


/* Requisito C/E: pai recolhe resultados dos filhos por pipe/socket. */
int phase1_parent_collect_worker_results(const Config *cfg, pid_t *pids,
                                         WorkerResult *results,
                                         WorkerStatus *statuses,
                                         int pipe_rd, int pipe_wr,
                                         int server_fd, bool use_sockets,
                                         double t0);

#endif

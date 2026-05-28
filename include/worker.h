#ifndef WORKER_H
#define WORKER_H

#include "../include/config.h"
#include "../include/files.h"
#include "../include/ipc.h"

/* Processa todos os ficheiros atribuídos a este worker e devolve as métricas.
 * comm_fd: fd onde escrever eventos verbose (pipe ou socket). -1 = sem envio. */
WorkerResult process_files(int worker_id, const FileList *fl,
                            const Config *cfg, int comm_fd);

/* Deteta o formato da linha de log */
typedef enum { FMT_APACHE, FMT_JSON, FMT_SYSLOG, FMT_NGINX, FMT_UNKNOWN } LogFmt;
LogFmt detect_format(const char *line);

#endif

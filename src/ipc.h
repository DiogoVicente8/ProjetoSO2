#ifndef IPC_H
#define IPC_H

#include <sys/types.h>
#include <stddef.h>
#include "log_parser.h"

/* -----------------------------------------------------------------------
 * readn / writen  (Requisito C - obrigatórias)
 * Garantem leitura/escrita completa mesmo com EINTR ou escritas parciais.
 * ----------------------------------------------------------------------- */
ssize_t readn(int fd, void *ptr, size_t n);
ssize_t writen(int fd, const void *ptr, size_t n);

/* -----------------------------------------------------------------------
 * Resultado enviado por cada worker ao pai
 * ----------------------------------------------------------------------- */
#define TOP_IPS     10
#define MAX_IP_LEN  46

typedef struct {
    pid_t  pid;
    long   lines_total;
    long   lines_parsed;
    long   count_info;
    long   count_warn;
    long   count_error;
    long   count_critical;
    long   errors_4xx;
    long   errors_5xx;
    long   security_events;
    long   perf_events;
    char   top_ip[MAX_IP_LEN];   /* IP mais frequente */
    long   top_ip_count;
    char   top_ips[TOP_IPS][MAX_IP_LEN];
    long   top_ip_counts[TOP_IPS];
} WorkerResult;

/* Serializa/deserializa WorkerResult em linha de texto para pipe/socket */
void   worker_result_serialize(const WorkerResult *r, char *buf, size_t bufsz);
int    worker_result_parse(const char *line, WorkerResult *r);

/* -----------------------------------------------------------------------
 * Resultado global agregado pelo pai
 * ----------------------------------------------------------------------- */
typedef struct {
    long   total_lines;
    long   total_parsed;
    long   total_info;
    long   total_warn;
    long   total_error;
    long   total_critical;
    long   total_4xx;
    long   total_5xx;
    long   total_security;
    long   total_perf;
    char   top_ips[TOP_IPS][MAX_IP_LEN];
    long   top_ip_counts[TOP_IPS];
} GlobalResult;

void aggregate(const WorkerResult *results, int n, GlobalResult *gr);

#endif

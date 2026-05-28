#ifndef DASHBOARD_H
#define DASHBOARD_H

#include <sys/types.h>

typedef enum { STATE_IDLE, STATE_WORKING, STATE_DONE } WorkerState;

typedef struct {
    pid_t       pid;
    long        lines_processed;
    long        total_lines;
    float       progress_pct;
    WorkerState state;
} WorkerStatus;

/* Reserva espaço no terminal para o dashboard */
void dashboard_init(int n_workers);

/* Redesenha o dashboard no lugar (usa ANSI escape codes) */
void dashboard_draw(WorkerStatus *statuses, int n_workers,
                    double elapsed, long events_sec, long total_errors);

/* Limpa o dashboard no final */
void dashboard_done(int n_workers);

#endif

#ifndef DASHBOARD_THREAD_H                          /* Guarda de inclusão. */
#define DASHBOARD_THREAD_H

#include <pthread.h>                               /* pthread_mutex_t. */
#include "../include/dashboard.h"                  /* WorkerStatus, dashboard_draw. */

/* -----------------------------------------------------------------------
 * REQUISITO 2-B — Argumento passado à thread dedicada ao dashboard
 *
 * A thread de dashboard lê (sob status_mutex) o array de statuses que as
 * worker/producer threads vão atualizando, e redesenha a interface a cada
 * segundo. A main thread sinaliza a paragem através da flag stop (protegida
 * pelo seu próprio stop_mutex).
 * ----------------------------------------------------------------------- */
typedef struct {
    WorkerStatus    *statuses;      /* Array de statuses a desenhar (leitura). */
    int              n_workers;     /* Número de workers/produtores.           */
    pthread_mutex_t *status_mutex;  /* Mutex que protege os statuses.          */
    double           t0;            /* Instante de início (para o elapsed).    */

    volatile int     stop;          /* Flag de paragem: main põe a 1.          */
    pthread_mutex_t  stop_mutex;    /* Mutex que protege a flag stop.          */
} DashboardArg;

/* -----------------------------------------------------------------------
 * Protótipos
 * ----------------------------------------------------------------------- */

/* Inicializa o DashboardArg e cria o stop_mutex. */
void dashboard_arg_init(DashboardArg *da, WorkerStatus *statuses,
                        int n_workers, pthread_mutex_t *status_mutex,
                        double t0);

/* Destrói o stop_mutex (chamado após o join da thread de dashboard). */
void dashboard_arg_destroy(DashboardArg *da);

/* Entry point da thread dedicada ao dashboard (assinatura pthread). */
void *dashboard_thread_run(void *arg);

#endif /* DASHBOARD_THREAD_H */
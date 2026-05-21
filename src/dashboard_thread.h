#ifndef DASHBOARD_THREAD_H
#define DASHBOARD_THREAD_H
 
#include <pthread.h>
#include "dashboard.h"
 
/* -----------------------------------------------------------------------
 * Argumento passado à thread dedicada ao dashboard
 * ----------------------------------------------------------------------- */
typedef struct {
    WorkerStatus    *statuses;      /* array de status dos workers (leitura) */
    int              n_workers;     /* número de workers                      */
    pthread_mutex_t *status_mutex;  /* mutex que protege statuses             */
    double           t0;            /* instante de início (para elapsed)      */
 
    /* Flag de paragem: main seta stop=1 e faz join */
    volatile int     stop;
    pthread_mutex_t  stop_mutex;
} DashboardArg;
 
/* -----------------------------------------------------------------------
 * Protótipos
 * ----------------------------------------------------------------------- */
 
/* Inicializar DashboardArg (zera a estrutura e inicializa stop_mutex) */
void dashboard_arg_init(DashboardArg *da, WorkerStatus *statuses,
                        int n_workers, pthread_mutex_t *status_mutex,
                        double t0);
 
/* Destruir DashboardArg (destrói stop_mutex) */
void dashboard_arg_destroy(DashboardArg *da);
 
/* Entry point da thread dedicada ao dashboard */
void *dashboard_thread_run(void *arg);
 
#endif /* DASHBOARD_THREAD_H */
 
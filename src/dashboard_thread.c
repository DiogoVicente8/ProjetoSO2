#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
 
#include "../include/dashboard_thread.h"
#include "../include/ipc.h"   
 
/* -------------------------------------------------------------------------
 * Helper de tempo
 * ------------------------------------------------------------------------- */
static double now_secs(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (double)tv.tv_sec + (double)tv.tv_usec / 1e6;
}
 
/* =========================================================================
 * dashboard_arg_init
 * ========================================================================= */
void dashboard_arg_init(DashboardArg *da, WorkerStatus *statuses,
                        int n_workers, pthread_mutex_t *status_mutex,
                        double t0)
{
    memset(da, 0, sizeof(DashboardArg));
    da->statuses     = statuses;
    da->n_workers    = n_workers;
    da->status_mutex = status_mutex;
    da->t0           = t0;
    da->stop         = 0;
    pthread_mutex_init(&da->stop_mutex, NULL);
}
 
/* =========================================================================
 * dashboard_arg_destroy
 * ========================================================================= */
void dashboard_arg_destroy(DashboardArg *da)
{
    pthread_mutex_destroy(&da->stop_mutex);
}
 
/* =========================================================================
 * dashboard_thread_run — entry point da thread dedicada ao dashboard
 *
 * Acorda a cada 1 segundo, lê os statuses (com mutex) e redesenha
 * o dashboard. Para quando da->stop == 1.
 * ========================================================================= */
void *dashboard_thread_run(void *arg)
{
    DashboardArg *da = (DashboardArg *)arg;
 
    while (1) {
        /* Dormir 1 segundo (em incrementos de 100ms para reagir
           rapidamente ao sinal de paragem sem busy-wait) */
        for (int i = 0; i < 10; i++) {
            usleep(100000); /* 100 ms */
 
            pthread_mutex_lock(&da->stop_mutex);
            int should_stop = da->stop;
            pthread_mutex_unlock(&da->stop_mutex);
 
            if (should_stop) goto done;
        }
 
        /* Ler statuses com o mutex */
        pthread_mutex_lock(da->status_mutex);
 
        double elapsed    = now_secs() - da->t0;
        long total_lines  = 0;
        long total_errors = 0;
 
        for (int i = 0; i < da->n_workers; i++) {
            total_lines  += da->statuses[i].lines_processed;
            total_errors += (da->statuses[i].state == STATE_DONE)
                            ? 0   /* erros já contados no relatório final */
                            : 0;  /* workers em curso: erros lidos via result */
        }
 
        long eps = elapsed > 0 ? (long)(total_lines / elapsed) : 0;
 
        dashboard_draw(da->statuses, da->n_workers,
                       elapsed, eps, total_errors);
 
        pthread_mutex_unlock(da->status_mutex);
    }
 
done:
    return NULL;
}
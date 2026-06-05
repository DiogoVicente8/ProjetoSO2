#define _GNU_SOURCE                               /* Ativa extensões GNU. */
#include <stdlib.h>                               /* NULL. */
#include <string.h>                               /* memset. */
#include <unistd.h>                               /* usleep. */
#include <sys/time.h>                             /* gettimeofday, struct timeval. */

#include "../include/dashboard_thread.h"          /* DashboardArg, protótipos. */
#include "../include/ipc.h"                       /* WorkerResult (contagem de erros). */

/* --------------------------------------------------------------------------
 * Helper de tempo: devolve o tempo atual em segundos com precisão de µs.
 * Usado para calcular o tempo decorrido (elapsed) mostrado no dashboard.
 * -------------------------------------------------------------------------- */
static double now_secs(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);                      /* Lê o relógio do sistema. */
    return (double)tv.tv_sec + (double)tv.tv_usec / 1e6;   /* Segundos + fração. */
}

/* ==========================================================================
 * REQUISITO 2-B — dashboard_arg_init
 *
 * Inicializa a estrutura partilhada com a thread de dashboard: ponteiros
 * para os statuses dos workers, o mutex que os protege e o instante inicial.
 * Cria também o mutex próprio que protege a flag de paragem.
 * ========================================================================== */
void dashboard_arg_init(DashboardArg *da, WorkerStatus *statuses,
                        int n_workers, pthread_mutex_t *status_mutex,
                        double t0)
{
    memset(da, 0, sizeof(DashboardArg));          /* Zera toda a estrutura. */
    da->statuses     = statuses;                  /* Array de statuses a desenhar. */
    da->n_workers    = n_workers;                 /* Quantos workers existem. */
    da->status_mutex = status_mutex;              /* Mutex que protege os statuses. */
    da->t0           = t0;                        /* Instante de início (para elapsed). */
    da->stop         = 0;                         /* Flag de paragem começa a falso. */
    pthread_mutex_init(&da->stop_mutex, NULL);    /* Cria o mutex da flag de paragem. */
}

/* ==========================================================================
 * REQUISITO 2-B — dashboard_arg_destroy
 * Liberta o mutex criado em dashboard_arg_init (chamado após o join).
 * ========================================================================== */
void dashboard_arg_destroy(DashboardArg *da)
{
    pthread_mutex_destroy(&da->stop_mutex);       /* Destrói o mutex da flag. */
}

/* ==========================================================================
 * REQUISITO 2-B — dashboard_thread_run: entry point da thread de dashboard
 *
 * Esta é a diferença central face à Fase 1: em vez de o processo principal
 * desenhar o dashboard no meio da recolha de resultados, há agora uma THREAD
 * DEDICADA que acorda a cada 1 segundo, lê os statuses sob mutex e redesenha
 * a interface. Termina quando a main thread coloca da->stop = 1.
 * ========================================================================== */
void *dashboard_thread_run(void *arg)
{
    DashboardArg *da = (DashboardArg *)arg;       /* Converte o argumento genérico. */

    while (1) {
        /* Dorme ~1 segundo, mas em 10 fatias de 100 ms. Isto permite reagir
         * depressa ao sinal de paragem sem fazer busy-wait (que gastaria CPU). */
        for (int i = 0; i < 10; i++) {
            usleep(100000);                       /* Dorme 100 ms. */

            pthread_mutex_lock(&da->stop_mutex);  /* Protege a leitura da flag. */
            int should_stop = da->stop;           /* Copia o valor atual. */
            pthread_mutex_unlock(&da->stop_mutex);

            if (should_stop) goto done;           /* Foi pedida paragem: termina. */
        }

        /* Lê os statuses sob o mutex partilhado com os workers. */
        pthread_mutex_lock(da->status_mutex);

        double elapsed    = now_secs() - da->t0;  /* Tempo decorrido desde o início. */
        long total_lines  = 0;                    /* Soma das linhas processadas. */
        long total_errors = 0;                    /* Total de erros (preenchido no fim). */

        for (int i = 0; i < da->n_workers; i++) {
            total_lines  += da->statuses[i].lines_processed;   /* Acumula progresso. */
            total_errors += (da->statuses[i].state == STATE_DONE)
                            ? 0   /* Os erros são consolidados no relatório final. */
                            : 0;
        }

        if (elapsed <= 0.000001)                  /* Evita divisão por zero. */
            elapsed = 0.000001;
        long eps = (long)((double)total_lines / elapsed);   /* Eventos por segundo. */

        dashboard_draw(da->statuses, da->n_workers,
                       elapsed, eps, total_errors);          /* Redesenha o dashboard. */

        pthread_mutex_unlock(da->status_mutex);   /* Liberta o mutex. */
    }

done:
    return NULL;                                  /* pthread espera retorno void*. */
}
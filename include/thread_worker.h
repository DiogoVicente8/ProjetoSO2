#ifndef THREAD_WORKER_H                            /* Guarda de inclusão. */
#define THREAD_WORKER_H

#include <pthread.h>                               /* pthread_mutex_t. */
#include "../include/config.h"                     /* Config. */
#include "../include/files.h"                      /* FileList. */
#include "../include/ipc.h"                        /* WorkerResult, MAX_IP_LEN. */
#include "../include/dashboard.h"                  /* WorkerStatus. */
#include "../include/worker.h"                     /* LogFmt, FMT_* (reutilizados da Fase 1). */

/* -----------------------------------------------------------------------
 * REQUISITO 2-A — Tabela de IPs por thread
 *
 * Cada worker thread mantém a SUA tabela (na stack), por isso esta entrada
 * não precisa de sincronização. O resultado final é guardado no WorkerResult.
 * ----------------------------------------------------------------------- */
#define THREAD_IP_TABLE 512                        /* Máximo de IPs distintos por thread. */

typedef struct {
    char ip[MAX_IP_LEN];                           /* Endereço IP. */
    long count;                                    /* Nº de ocorrências. */
} ThreadIPEntry;

/* -----------------------------------------------------------------------
 * REQUISITO 2-A — Argumento passado a cada worker thread via pthread_create()
 *
 * Contém tudo o que a thread precisa: a sua identidade, a lista de ficheiros,
 * o mapa de atribuição, a config, o seu WorkerResult (escrito só por ela) e
 * o ponteiro para o seu slot de status (partilhado com a thread de dashboard).
 * ----------------------------------------------------------------------- */
typedef struct {
    int            thread_id;      /* Índice 0..N-1 desta thread.            */
    int            num_threads;    /* Total de threads.                      */
    const FileList *fl;            /* Lista de ficheiros (só leitura).       */
    const int      *assignment;    /* assignment[i] = thread dona do file i. */
    const Config   *cfg;           /* Configuração global (só leitura).      */

    WorkerResult   result;         /* Resultado desta thread (escrito só por ela). */

    WorkerStatus   *status;        /* Slot de progresso (lido pelo dashboard). */
    pthread_mutex_t *status_mutex; /* Mutex que protege o array de statuses.  */
} ThreadArg;

/* -----------------------------------------------------------------------
 * Protótipo: função executada por cada worker thread (assinatura pthread).
 * ----------------------------------------------------------------------- */
void *thread_worker_run(void *arg);

#endif /* THREAD_WORKER_H */
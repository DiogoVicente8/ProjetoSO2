#ifndef THREAD_WORKER_H
#define THREAD_WORKER_H
 
#include <pthread.h>
#include "../include/config.h"
#include "../include/files.h"
#include "../include/ipc.h"
#include "../include/dashboard.h"
#include "../include/worker.h"   /* LogFmt, FMT_* */
 
/* -----------------------------------------------------------------------
 * Resultado de cada worker thread (mesma estrutura do WorkerResult da
 * Fase 1, reutilizada para o relatório final)
 * ----------------------------------------------------------------------- */
 
/* Tabela de IPs partilhada entre threads (com mutex próprio) */
#define THREAD_IP_TABLE 512
 
typedef struct {
    char ip[MAX_IP_LEN];
    long count;
} ThreadIPEntry;
 
/* -----------------------------------------------------------------------
 * Argumento passado a cada worker thread via pthread_create()
 * ----------------------------------------------------------------------- */
typedef struct {
    int            thread_id;      /* índice 0..N-1                        */
    int            num_threads;    /* total de threads                      */
    const FileList *fl;            /* lista de ficheiros (só leitura)       */
    const int      *assignment;    /* assignment[i] = thread dono do file i */
    const Config   *cfg;           /* configuração global (só leitura)      */
 
    /* Resultado acumulado por esta thread (escrito só por ela) */
    WorkerResult   result;
 
    /* Dashboard: ponteiro para o slot desta thread no array de statuses */
    WorkerStatus   *status;        /* atualizado pela thread, lido pelo pai */
    pthread_mutex_t *status_mutex; /* protege o array de statuses           */
} ThreadArg;
 
/* -----------------------------------------------------------------------
 * Protótipos
 * ----------------------------------------------------------------------- */
 
/* Função que cada worker thread executa (assinatura exigida por pthread) */
void *thread_worker_run(void *arg);
 
#endif /* THREAD_WORKER_H */
 
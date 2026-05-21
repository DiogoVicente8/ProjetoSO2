#define _GNU_SOURCE
#include <string.h>
#include <errno.h>
#include "bounded_buffer.h"

/* =========================================================================
 * bb_init
 * ========================================================================= */
void bb_init(BoundedBuffer *bb, int n_consumers)
{
    memset(bb, 0, sizeof(BoundedBuffer));
    bb->head       = 0;
    bb->tail       = 0;
    bb->n_consumers = n_consumers;

    /* sem_empty começa com BUFFER_SIZE (todos os slots estão vazios) */
    sem_init(&bb->sem_empty, 0, BUFFER_SIZE);
    /* sem_full começa com 0 (não há nada para ler) */
    sem_init(&bb->sem_full,  0, 0);

    pthread_mutex_init(&bb->mutex, NULL);
}

/* =========================================================================
 * bb_destroy
 * ========================================================================= */
void bb_destroy(BoundedBuffer *bb)
{
    sem_destroy(&bb->sem_empty);
    sem_destroy(&bb->sem_full);
    pthread_mutex_destroy(&bb->mutex);
}

/* =========================================================================
 * bb_put — inserir linha no buffer (bloqueia se cheio)
 * ========================================================================= */
void bb_put(BoundedBuffer *bb, const char *line, int producer_id)
{
    /* Decrementar sem_empty: bloqueia se não houver slots livres */
    while (sem_wait(&bb->sem_empty) < 0)
        if (errno != EINTR) return;   /* erro inesperado */

    pthread_mutex_lock(&bb->mutex);

    strncpy(bb->slots[bb->tail].line, line, MAX_LINE_LENGTH - 1);
    bb->slots[bb->tail].line[MAX_LINE_LENGTH - 1] = '\0';
    bb->slots[bb->tail].producer_id = producer_id;
    bb->tail = (bb->tail + 1) % BUFFER_SIZE;

    pthread_mutex_unlock(&bb->mutex);

    /* Incrementar sem_full: acordar um consumidor se estiver bloqueado */
    sem_post(&bb->sem_full);
}

/* =========================================================================
 * bb_get — retirar linha do buffer (bloqueia se vazio)
 * Retorna 0 em linha válida, -1 em sinal de fim (line[0] == '\0')
 * ========================================================================= */
int bb_get(BoundedBuffer *bb, LogLine *out)
{
    /* Decrementar sem_full: bloqueia se não houver nada para ler */
    while (sem_wait(&bb->sem_full) < 0)
        if (errno != EINTR) return -1;

    pthread_mutex_lock(&bb->mutex);

    *out = bb->slots[bb->head];
    bb->head = (bb->head + 1) % BUFFER_SIZE;

    pthread_mutex_unlock(&bb->mutex);

    /* Incrementar sem_empty: libertar slot para os produtores */
    sem_post(&bb->sem_empty);

    /* Sinal de fim: linha vazia inserida por bb_send_eof */
    if (out->line[0] == '\0') return -1;

    return 0;
}

/* =========================================================================
 * bb_send_eof — inserir um sinal de fim por consumidor
 * Chamado quando todos os produtores terminaram
 * ========================================================================= */
void bb_send_eof(BoundedBuffer *bb)
{
    for (int i = 0; i < bb->n_consumers; i++)
        bb_put(bb, "", -1);   /* linha vazia = sinal de fim */
}

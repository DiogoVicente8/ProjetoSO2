#define _GNU_SOURCE
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include "bounded_buffer.h"

/* =========================================================================
 * bb_init
 * ========================================================================= */
void bb_init(BoundedBuffer *bb, int n_consumers)
{
    memset(bb, 0, sizeof(BoundedBuffer));
    bb->head        = 0;
    bb->tail        = 0;
    bb->n_consumers = n_consumers;
    bb->count       = 0;
    bb->closed      = 0;

    /* Ssyscalls nativas com verificação de erro estrita (Secção 8.2) */
    if (sem_init(&bb->sem_empty, 0, BUFFER_SIZE) < 0) {
        perror("sem_init (empty)");
        exit(EXIT_FAILURE);
    }
    if (sem_init(&bb->sem_full,  0, 0) < 0) {
        perror("sem_init (full)");
        exit(EXIT_FAILURE);
    }
    if (pthread_mutex_init(&bb->mutex, NULL) != 0) {
        perror("pthread_mutex_init");
        exit(EXIT_FAILURE);
    }
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
    /* Decrementar sem_empty: bloqueia se o buffer estiver completamente cheio */
    while (sem_wait(&bb->sem_empty) < 0) {
        if (errno == EINTR) continue;   /* Interrompido por sinal (benigno) — repetir */
        perror("sem_wait (empty)");
        return;
    }

    if (pthread_mutex_lock(&bb->mutex) != 0) {
        perror("pthread_mutex_lock");
        exit(EXIT_FAILURE);
    }

    /* Só aceita e insere dados se o buffer não tiver sido encerrado */
    if (!bb->closed) {
        strncpy(bb->slots[bb->tail].line, line, MAX_LINE_LENGTH - 1);
        bb->slots[bb->tail].line[MAX_LINE_LENGTH - 1] = '\0';
        bb->slots[bb->tail].producer_id = producer_id;
        bb->tail = (bb->tail + 1) % BUFFER_SIZE;
        bb->count++;
    }

    if (pthread_mutex_unlock(&bb->mutex) != 0) {
        perror("pthread_mutex_unlock");
        exit(EXIT_FAILURE);
    }

    /* Incrementar sem_full: sinaliza que há um item disponível para leitura */
    if (sem_post(&bb->sem_full) < 0) {
        perror("sem_post (full)");
    }
}

/* =========================================================================
 * bb_get — retirar linha do buffer (bloqueia se vazio)
 * Retorna 0 em linha válida, -1 em sinal de fim
 * ========================================================================= */
int bb_get(BoundedBuffer *bb, LogLine *out)
{
    /* Decrementar sem_full: bloqueia se o buffer estiver totalmente vazio */
    while (sem_wait(&bb->sem_full) < 0) {
        if (errno == EINTR) continue;
        perror("sem_wait (full)");
        return -1;
    }

    if (pthread_mutex_lock(&bb->mutex) != 0) {
        perror("pthread_mutex_lock");
        exit(EXIT_FAILURE);
    }

    /* SOLUÇÃO DA RACE CONDITION (Efeito Dominó):
     * Se o contador chegou a zero E a flag closed está ativa, fomos acordados 
     * pelo encerramento. Libertamos o mutex, propagamos o sem_post para acordar 
     * o próximo consumidor adormecido em cadeia e saímos com -1. */
    if (bb->count == 0 && bb->closed) {
        if (pthread_mutex_unlock(&bb->mutex) != 0) perror("pthread_mutex_unlock");
        if (sem_post(&bb->sem_full) < 0) perror("sem_post (domino eof)"); 
        return -1;
    }

    /* Retirar o elemento do array circular de forma normal */
    *out = bb->slots[bb->head];
    bb->head = (bb->head + 1) % BUFFER_SIZE;
    if (bb->count > 0) bb->count--;

    /* Detetar se é uma linha de eof legada (string vazia) */
    int is_empty_line = (out->line[0] == '\0');

    if (pthread_mutex_unlock(&bb->mutex) != 0) {
        perror("pthread_mutex_unlock");
        exit(EXIT_FAILURE);
    }

    /* Incrementar sem_empty: liberta espaço para os produtores voltarem a escrever */
    if (sem_post(&bb->sem_empty) < 0) {
        perror("sem_post (empty)");
    }

    if (is_empty_line) return -1;

    return 0;
}

/* =========================================================================
 * bb_send_eof — fechar o buffer e acordar os consumidores adormecidos
 * ========================================================================= */
void bb_send_eof(BoundedBuffer *bb)
{
    if (pthread_mutex_lock(&bb->mutex) != 0) {
        perror("pthread_mutex_lock");
        exit(EXIT_FAILURE);
    }

    bb->closed = 1; /* Fecha o buffer de forma segura usando exclusão mútua */

    if (pthread_mutex_unlock(&bb->mutex) != 0) {
        perror("pthread_mutex_unlock");
        exit(EXIT_FAILURE);
    }

    /* Dispara apenas UM sem_post inicial. O primeiro consumidor a acordar
     * vai tratar de passar o testemunho ao consumidor seguinte no bb_get,
     * garantindo um encerramento limpo sem deadlocks ou estouros de pilha. */
    if (sem_post(&bb->sem_full) < 0) {
        perror("sem_post (eof initial trigger)");
    }
}
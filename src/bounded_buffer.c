#define _GNU_SOURCE                               /* Ativa extensões GNU. */
#include <string.h>                               /* memset, strncpy. */
#include <errno.h>                                /* errno, EINTR. */
#include <stdio.h>                                /* perror. */
#include <stdlib.h>                               /* exit, EXIT_FAILURE. */
#include "../include/bounded_buffer.h"            /* BoundedBuffer, LogLine, protótipos. */
 
/* ==========================================================================
 * REQUISITO 2-C — Bounded Buffer (fila circular produtor-consumidor)
 *
 * Esta é a peça central do padrão produtor-consumidor. É partilhada por
 * todas as threads produtoras e consumidoras. A sincronização usa o esquema
 * clássico dos dois semáforos contadores + um mutex:
 *
 *   sem_empty — conta os SLOTS LIVRES. O produtor faz sem_wait antes de
 *               inserir (bloqueia se o buffer estiver cheio).
 *   sem_full  — conta os ITENS DISPONÍVEIS. O consumidor faz sem_wait antes
 *               de retirar (bloqueia se o buffer estiver vazio).
 *   mutex     — garante exclusão mútua na manipulação de head/tail/count.
 *
 * bb_init prepara estas três primitivas e os índices da fila circular.
 * ========================================================================== */
void bb_init(BoundedBuffer *bb, int n_consumers)
{
    memset(bb, 0, sizeof(BoundedBuffer));         /* Zera toda a estrutura. */
    bb->head        = 0;                          /* Próxima posição a ler. */
    bb->tail        = 0;                          /* Próxima posição a escrever. */
    bb->n_consumers = n_consumers;                /* Nº de consumidores (para o EOF). */
    bb->count       = 0;                          /* Itens atualmente no buffer. */
    bb->closed      = 0;                          /* Buffer ainda aberto. */
 
    /* Criação dos semáforos e mutex com verificação estrita de erro
     * (conforme a Secção 8.2 do enunciado: validar todas as chamadas). */
    if (sem_init(&bb->sem_empty, 0, BUFFER_SIZE) < 0) {   /* Começa com TODOS os slots livres. */
        perror("sem_init (empty)");
        exit(EXIT_FAILURE);
    }
    if (sem_init(&bb->sem_full,  0, 0) < 0) {     /* Começa SEM itens para ler. */
        perror("sem_init (full)");
        exit(EXIT_FAILURE);
    }
    if (pthread_mutex_init(&bb->mutex, NULL) != 0) {      /* Mutex dos índices. */
        perror("pthread_mutex_init");
        exit(EXIT_FAILURE);
    }
}
 
/* ==========================================================================
 * bb_destroy — liberta os semáforos e o mutex (chamado no fim do programa)
 * ========================================================================== */
void bb_destroy(BoundedBuffer *bb)
{
    sem_destroy(&bb->sem_empty);                  /* Destrói o semáforo de slots livres. */
    sem_destroy(&bb->sem_full);                   /* Destrói o semáforo de itens. */
    pthread_mutex_destroy(&bb->mutex);            /* Destrói o mutex. */
}
 
/* ==========================================================================
 * REQUISITO 2-C — bb_put: inserir uma linha no buffer (PRODUTOR)
 *
 * Padrão: sem_wait(empty) → lock(mutex) → escrever → unlock(mutex) →
 *         sem_post(full). Bloqueia automaticamente se o buffer estiver cheio.
 * ========================================================================== */
void bb_put(BoundedBuffer *bb, const char *line, int producer_id)
{
    /* Espera por um slot livre. Bloqueia se o buffer estiver totalmente cheio. */
    while (sem_wait(&bb->sem_empty) < 0) {
        if (errno == EINTR) continue;             /* Interrompido por sinal: repete. */
        perror("sem_wait (empty)");
        return;
    }
 
    if (pthread_mutex_lock(&bb->mutex) != 0) {    /* Secção crítica: protege a fila. */
        perror("pthread_mutex_lock");
        exit(EXIT_FAILURE);
    }
 
    /* Só insere se o buffer ainda não foi encerrado (evita inserir após o EOF). */
    if (!bb->closed) {
        strncpy(bb->slots[bb->tail].line, line, MAX_LINE_LENGTH - 1);  /* Copia a linha. */
        bb->slots[bb->tail].line[MAX_LINE_LENGTH - 1] = '\0';          /* Terminação nula. */
        bb->slots[bb->tail].producer_id = producer_id;                 /* Quem produziu. */
        bb->tail = (bb->tail + 1) % BUFFER_SIZE;  /* Avança o tail circularmente. */
        bb->count++;                              /* Mais um item no buffer. */
    }
 
    if (pthread_mutex_unlock(&bb->mutex) != 0) {
        perror("pthread_mutex_unlock");
        exit(EXIT_FAILURE);
    }
 
    /* Sinaliza que há um item disponível: acorda um consumidor bloqueado. */
    if (sem_post(&bb->sem_full) < 0) {
        perror("sem_post (full)");
    }
}
 
/* ==========================================================================
 * REQUISITO 2-C — bb_get: retirar uma linha do buffer (CONSUMIDOR)
 *
 * Padrão: sem_wait(full) → lock(mutex) → ler → unlock(mutex) →
 *         sem_post(empty). Bloqueia se o buffer estiver vazio.
 * Retorna 0 se obteve uma linha válida; -1 se recebeu o sinal de fim.
 * ========================================================================== */
int bb_get(BoundedBuffer *bb, LogLine *out)
{
    /* Espera por um item. Bloqueia se o buffer estiver totalmente vazio. */
    while (sem_wait(&bb->sem_full) < 0) {
        if (errno == EINTR) continue;             /* Interrompido por sinal: repete. */
        perror("sem_wait (full)");
        return -1;
    }
 
    if (pthread_mutex_lock(&bb->mutex) != 0) {    /* Secção crítica. */
        perror("pthread_mutex_lock");
        exit(EXIT_FAILURE);
    }
 
    /* ENCERRAMENTO EM CADEIA (resolve a "race condition do efeito dominó"):
     * Se o contador chegou a zero E o buffer está fechado, então fomos
     * acordados pelo sinal de fim. Libertamos o mutex, voltamos a fazer
     * sem_post(full) para "passar o testemunho" ao próximo consumidor
     * adormecido, e saímos com -1. Assim todos os consumidores terminam
     * com um único sinal inicial, sem deadlock. */
    if (bb->count == 0 && bb->closed) {
        if (pthread_mutex_unlock(&bb->mutex) != 0) perror("pthread_mutex_unlock");
        if (sem_post(&bb->sem_full) < 0) perror("sem_post (domino eof)");  /* Acorda o seguinte. */
        return -1;
    }
 
    /* Retira o elemento da cabeça da fila circular. */
    *out = bb->slots[bb->head];                   /* Copia o item para o chamador. */
    bb->head = (bb->head + 1) % BUFFER_SIZE;      /* Avança o head circularmente. */
    if (bb->count > 0) bb->count--;               /* Menos um item no buffer. */
 
    /* Deteta também o sinal de fim "legado" (linha vazia inserida via bb_put). */
    int is_empty_line = (out->line[0] == '\0');
 
    if (pthread_mutex_unlock(&bb->mutex) != 0) {
        perror("pthread_mutex_unlock");
        exit(EXIT_FAILURE);
    }
 
    /* Liberta um slot: acorda um produtor que esteja bloqueado por buffer cheio. */
    if (sem_post(&bb->sem_empty) < 0) {
        perror("sem_post (empty)");
    }
 
    if (is_empty_line) return -1;                 /* Linha vazia = sinal de fim. */
 
    return 0;                                     /* Linha válida. */
}
 
/* ==========================================================================
 * REQUISITO 2-C — bb_send_eof: encerrar o buffer e acordar os consumidores
 *
 * Chamado pela main thread depois de todos os produtores terminarem.
 * Marca o buffer como fechado (sob mutex) e dispara UM único sem_post.
 * O primeiro consumidor a acordar propaga o sinal aos restantes via a
 * lógica de "encerramento em cadeia" dentro de bb_get (ver acima).
 * ========================================================================== */
void bb_send_eof(BoundedBuffer *bb)
{
    if (pthread_mutex_lock(&bb->mutex) != 0) {
        perror("pthread_mutex_lock");
        exit(EXIT_FAILURE);
    }
 
    bb->closed = 1;                               /* Fecha o buffer com exclusão mútua. */
 
    if (pthread_mutex_unlock(&bb->mutex) != 0) {
        perror("pthread_mutex_unlock");
        exit(EXIT_FAILURE);
    }
 
    /* Dispara apenas o primeiro sinal; o resto propaga-se em cadeia no bb_get,
     * garantindo um encerramento limpo sem deadlocks nem recursão excessiva. */
    if (sem_post(&bb->sem_full) < 0) {
        perror("sem_post (eof initial trigger)");
    }
}
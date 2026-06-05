#ifndef BOUNDED_BUFFER_H                           /* Guarda de inclusão. */
#define BOUNDED_BUFFER_H

#include <pthread.h>                               /* pthread_mutex_t. */
#include <semaphore.h>                             /* sem_t (semáforos POSIX). */
#include "../include/log_parser.h"                 /* MAX_LINE_LENGTH. */

/* -----------------------------------------------------------------------
 * Tamanho do buffer circular. Define quantas linhas cabem em espera entre
 * produtores e consumidores. Maior = mais folga (menos bloqueios), mas
 * mais memória. 1024 é um bom compromisso.
 * ----------------------------------------------------------------------- */
#define BUFFER_SIZE 1024

/* -----------------------------------------------------------------------
 * Entrada do buffer: uma linha de log crua + o id do produtor que a inseriu.
 * ----------------------------------------------------------------------- */
typedef struct {
    char line[MAX_LINE_LENGTH];  /* Linha de texto a processar.            */
    int  producer_id;            /* Produtor que a inseriu (diagnóstico).  */
} LogLine;

/* -----------------------------------------------------------------------
 * REQUISITO 2-C — Bounded Buffer (fila circular com semáforos POSIX)
 *
 * Esquema clássico de sincronização produtor-consumidor:
 *   sem_empty — conta os SLOTS LIVRES (produtor faz sem_wait antes de inserir).
 *   sem_full  — conta os ITENS PRONTOS (consumidor faz sem_wait antes de ler).
 *   mutex     — exclusão mútua ao mexer em head/tail/count.
 *
 * head/tail implementam a fila circular; count e closed permitem um
 * encerramento limpo (ver bb_send_eof / bb_get no .c).
 * ----------------------------------------------------------------------- */
typedef struct {
    LogLine  slots[BUFFER_SIZE]; /* Array circular de entradas.             */
    int      head;               /* Próximo slot a ler (consumidor).        */
    int      tail;               /* Próximo slot a escrever (produtor).     */

    sem_t    sem_empty;          /* Semáforo: slots livres para escrever.   */
    sem_t    sem_full;           /* Semáforo: itens disponíveis para ler.   */
    pthread_mutex_t mutex;       /* Protege head, tail e count.             */

    int      n_consumers;        /* Nº de consumidores (para o sinal de fim). */
    int      count;              /* Itens atualmente no buffer.             */
    int      closed;             /* 1 = buffer fechado (não aceita mais puts). */
} BoundedBuffer;

/* -----------------------------------------------------------------------
 * Protótipos
 * ----------------------------------------------------------------------- */

/* Inicializa o buffer e os semáforos (n_consumers = nº de consumidores). */
void bb_init(BoundedBuffer *bb, int n_consumers);

/* Liberta semáforos e mutex. */
void bb_destroy(BoundedBuffer *bb);

/* Insere uma linha no buffer (bloqueia se cheio) — usado pelos PRODUTORES. */
void bb_put(BoundedBuffer *bb, const char *line, int producer_id);

/* Retira uma linha do buffer (bloqueia se vazio) — usado pelos CONSUMIDORES.
 * Retorna 0 se obteve uma linha válida; -1 se recebeu o sinal de fim. */
int  bb_get(BoundedBuffer *bb, LogLine *out);

/* Fecha o buffer e acorda os consumidores adormecidos (encerramento em cadeia). */
void bb_send_eof(BoundedBuffer *bb);

#endif /* BOUNDED_BUFFER_H */
#ifndef BOUNDED_BUFFER_H
#define BOUNDED_BUFFER_H

#include <pthread.h>
#include <semaphore.h>
#include "log_parser.h"

/* -----------------------------------------------------------------------
 * Tamanho do buffer (potência de 2 para wrap eficiente)
 * ----------------------------------------------------------------------- */
#define BUFFER_SIZE 1024

/* -----------------------------------------------------------------------
 * Entrada no buffer: uma linha de log + metadados
 * ----------------------------------------------------------------------- */
typedef struct {
    char line[MAX_LINE_LENGTH];  /* linha de texto crua                    */
    int  producer_id;            /* qual produtor inseriu (debug)          */
} LogLine;

/* -----------------------------------------------------------------------
 * Bounded Buffer — fila circular com semáforos POSIX
 *
 * Sincronização:
 *   sem_empty  — conta slots vazios  (produtor decrementa antes de inserir)
 *   sem_full   — conta slots cheios  (consumidor decrementa antes de retirar)
 *   mutex      — exclusão mútua na manipulação dos índices head/tail
 * ----------------------------------------------------------------------- */
typedef struct {
    LogLine  slots[BUFFER_SIZE]; /* array circular de entradas             */
    int      head;               /* próximo slot a ler  (consumidor)       */
    int      tail;               /* próximo slot a escrever (produtor)     */

    sem_t    sem_empty;          /* slots disponíveis para escrever        */
    sem_t    sem_full;           /* slots disponíveis para ler             */
    pthread_mutex_t mutex;       /* protege head e tail                    */

    /* Sinalização de fim: quando todos os produtores terminam,
       inserem uma entrada especial com line[0] == '\0' por consumidor */
    int      n_consumers;        /* quantos sinais de fim enviar           */
    int      count;              /* número atual de elementos no buffer    */
    int      closed;             /* flag: buffer fechado para novos puts   */
} BoundedBuffer;

/* -----------------------------------------------------------------------
 * Protótipos
 * ----------------------------------------------------------------------- */

/* Inicializar o buffer (n_consumers = nº de threads consumidoras) */
void bb_init(BoundedBuffer *bb, int n_consumers);

/* Destruir (liberta semáforos e mutex) */
void bb_destroy(BoundedBuffer *bb);

/* Inserir uma linha no buffer (bloqueia se cheio) */
void bb_put(BoundedBuffer *bb, const char *line, int producer_id);

/* Retirar uma linha do buffer (bloqueia se vazio).
 * Retorna 0 se obteve uma linha válida, -1 se recebeu sinal de fim. */
int  bb_get(BoundedBuffer *bb, LogLine *out);

/* Enviar N sinais de fim (um por consumidor) — chamado pelos produtores
 * quando terminam todos */
void bb_send_eof(BoundedBuffer *bb);

#endif /* BOUNDED_BUFFER_H */

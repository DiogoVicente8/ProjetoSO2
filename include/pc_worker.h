#ifndef PC_WORKER_H                                /* Guarda de inclusão. */
#define PC_WORKER_H

#include <pthread.h>                               /* pthread_mutex_t. */
#include <time.h>                                  /* time_t. */
#include "../include/bounded_buffer.h"             /* BoundedBuffer, LogLine. */
#include "../include/config.h"                     /* Config. */
#include "../include/dashboard.h"                  /* WorkerStatus. */
#include "../include/files.h"                      /* FileList. */
#include "../include/ipc.h"                        /* WorkerResult, MAX_IP_LEN. */

/* -----------------------------------------------------------------------
 * REQUISITO 2-C — Parâmetros de deteção de padrões de ataque
 * ----------------------------------------------------------------------- */
#define BRUTE_FORCE_WINDOW_SEC 120                 /* Janela de tempo p/ brute-force (segundos). */
#define BRUTE_FORCE_THRESHOLD  5                   /* Falhas na janela que disparam alerta. */
#define CONSEC_5XX_THRESHOLD   10                  /* Erros 5xx seguidos que disparam alerta. */
#define BF_TABLE_SIZE          1024                /* Máx. de IPs na tabela de brute-force. */
#define PC_IP_TABLE            1024                /* Máx. de IPs na tabela de tráfego. */

/* -----------------------------------------------------------------------
 * Entrada da tabela de brute-force: conta falhas de um IP numa janela.
 * ----------------------------------------------------------------------- */
typedef struct {
    char   ip[MAX_IP_LEN];       /* IP suspeito.                            */
    int    fail_count;           /* Falhas dentro da janela atual.          */
    time_t window_start;         /* Início da janela de contagem.           */
} BruteForceEntry;

/* -----------------------------------------------------------------------
 * REQUISITO 2-C — Argumento de cada thread PRODUTORA
 * ----------------------------------------------------------------------- */
typedef struct {
    int             producer_id;   /* Índice do produtor.                   */
    int             num_producers; /* Total de produtores.                  */
    const FileList  *fl;           /* Lista de ficheiros (só leitura).      */
    const int       *assignment;   /* Mapa ficheiro→produtor.               */
    BoundedBuffer   *bb;           /* Buffer partilhado (destino das linhas).*/
    WorkerStatus    *status;       /* Slot de progresso (para o dashboard). */
    pthread_mutex_t *status_mutex; /* Mutex que protege os statuses.        */
    long             lines_produced; /* Contador local de linhas inseridas. */
} ProducerArg;

/* -----------------------------------------------------------------------
 * REQUISITO 2-C — Argumento de cada thread CONSUMIDORA
 *
 * Cada consumidor tem o seu próprio WorkerResult e as suas tabelas locais
 * (brute-force e tráfego), evitando contenção entre consumidores. O pai
 * agrega tudo no fim.
 * ----------------------------------------------------------------------- */
typedef struct {
    int              consumer_id;  /* Índice do consumidor.                 */
    BoundedBuffer   *bb;           /* Buffer partilhado (fonte das linhas). */
    const Config    *cfg;          /* Configuração (modo de análise).       */
    WorkerResult     result;       /* Métricas acumuladas por este consumidor. */

    BruteForceEntry  bf_table[BF_TABLE_SIZE];  /* Tabela de deteção de brute-force. */
    int              bf_used;      /* Entradas usadas na bf_table.          */
    int              consec_5xx;   /* Contador de 5xx consecutivos.         */
    long             brute_alerts; /* Alertas de brute-force detetados.     */
    long             consec_alerts;/* Alertas de 5xx consecutivos.          */

    struct {                       /* Tabela de tráfego (top-IPs). */
        char ip[MAX_IP_LEN];
        long count;
    } ip_table[PC_IP_TABLE];
    int              ip_used;      /* Entradas usadas na ip_table.          */
} ConsumerArg;

/* -----------------------------------------------------------------------
 * Protótipos das funções executadas pelas threads (assinatura pthread).
 * ----------------------------------------------------------------------- */
void *producer_run(void *arg);     /* Entry point das threads produtoras.   */
void *consumer_run(void *arg);     /* Entry point das threads consumidoras. */

#endif /* PC_WORKER_H */
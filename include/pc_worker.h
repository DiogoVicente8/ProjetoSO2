#ifndef PC_WORKER_H
#define PC_WORKER_H

#include <pthread.h>
#include <time.h>
#include "../include/bounded_buffer.h"
#include "../include/config.h"
#include "../include/dashboard.h"
#include "../include/files.h"
#include "../include/ipc.h"

#define BRUTE_FORCE_WINDOW_SEC 120
#define BRUTE_FORCE_THRESHOLD 5
#define CONSEC_5XX_THRESHOLD 10
#define BF_TABLE_SIZE 1024
#define PC_IP_TABLE 1024

typedef struct {
    char ip[MAX_IP_LEN];
    int fail_count;
    time_t window_start;
} BruteForceEntry;

typedef struct {
    int producer_id;
    int num_producers;
    const FileList *fl;
    const int *assignment;
    BoundedBuffer *bb;
    WorkerStatus *status;
    pthread_mutex_t *status_mutex;
    long lines_produced;
} ProducerArg;

typedef struct {
    int consumer_id;
    BoundedBuffer *bb;
    const Config *cfg;
    WorkerResult result;
    BruteForceEntry bf_table[BF_TABLE_SIZE];
    int bf_used;
    int consec_5xx;
    long brute_alerts;
    long consec_alerts;
    struct {
        char ip[MAX_IP_LEN];
        long count;
    } ip_table[PC_IP_TABLE];
    int ip_used;
} ConsumerArg;

void *producer_run(void *arg);
void *consumer_run(void *arg);

#endif

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include "files.h"

/* --------------------------------------------------------------------------
 * Requisito 3.2 B — Processo PAI descobre os ficheiros de log
 *
 * Percorre o diretório recursivamente e recolhe todos os .log/.json para
 * criar a lista de trabalho que será dividida pelos workers.
 * -------------------------------------------------------------------------- */
int discover_files(const char *dir, FileList *fl)
{
    DIR *d = opendir(dir);
    if (!d) {
        perror("opendir");
        return -1;
    }

    struct dirent *entry;
    while ((entry = readdir(d)) != NULL) {

        /* ignorar "." e ".." */
        if (entry->d_name[0] == '.') continue;

        char path[1024];
        snprintf(path, sizeof(path), "%s/%s", dir, entry->d_name);

        struct stat st;
        if (stat(path, &st) < 0) continue;

        if (S_ISDIR(st.st_mode)) {
            /* Recursão: subdirectório */
            discover_files(path, fl);

        } else if (S_ISREG(st.st_mode)) {
            const char *ext = strrchr(entry->d_name, '.');
            if (ext && (strcmp(ext, ".log")  == 0 ||
                        strcmp(ext, ".json") == 0)) {
                if (fl->count < MAX_FILES) {
                    snprintf(fl->paths[fl->count],
                             sizeof(fl->paths[fl->count]), "%s", path);
                    fl->count++;
                }
            }
        }
    }

    closedir(d);
    return fl->count;
}

/* --------------------------------------------------------------------------
 * Requisito 3.2 B — Divisão de ficheiros entre N processos filho
 *
 * Cada worker recebe um intervalo da lista, processando o seu subconjunto
 * independentemente.
 * -------------------------------------------------------------------------- */
void split_files(const FileList *fl, int worker_id, int num_workers,
                 int *start, int *end)
{
    int chunk     = fl->count / num_workers;
    int remainder = fl->count % num_workers;

    /* os primeiros 'remainder' workers recebem chunk+1 ficheiros */
    if (worker_id < remainder) {
        *start = worker_id * (chunk + 1);
        *end   = *start + chunk + 1;
    } else {
        *start = remainder * (chunk + 1) + (worker_id - remainder) * chunk;
        *end   = *start + chunk;
    }
}

/* --------------------------------------------------------------------------
 * Requisitos 3.4 D e 8.1 — Estimativa de progresso com I/O POSIX
 *
 * Conta linhas usando open/read/close, sem fopen/fread, para calcular o total
 * esperado de trabalho de cada worker no dashboard.
 * -------------------------------------------------------------------------- */
long count_lines(const char *path)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;

    char  buf[8192];
    long  count = 0;
    ssize_t n;

    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        for (ssize_t i = 0; i < n; i++)
            if (buf[i] == '\n') count++;
    }
    close(fd);
    return count > 0 ? count : 1;
}

/* --------------------------------------------------------------------------
 * Fase 2 — Distribuição balanceada por tamanho estimado
 *
 * Usada pelas versões com threads para equilibrar carga e melhorar throughput.
 * -------------------------------------------------------------------------- */
void split_files_balanced(const FileList *fl, int num_workers, int *assignment)
{
    long loads[MAX_FILES];

    if (!fl || !assignment || num_workers <= 0) return;

    for (int i = 0; i < num_workers && i < MAX_FILES; i++)
        loads[i] = 0;

    for (int i = 0; i < fl->count; i++) {
        int best = 0;
        for (int w = 1; w < num_workers; w++) {
            if (loads[w] < loads[best])
                best = w;
        }
        assignment[i] = best;
        loads[best] += count_lines(fl->paths[i]);
    }
}

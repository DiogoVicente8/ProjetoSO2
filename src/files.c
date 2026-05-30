#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include "../include/files.h"

/* ==========================================================================
 * REQUISITO A / B — Descoberta e distribuição de ficheiros
 *
 * discover_files  : percorre o directório recursivamente e recolhe .log e .json
 * split_files     : divide os ficheiros pelos workers (round-robin)
 * count_lines     : conta linhas usando syscall read() — sem fopen
 * split_files_balanced: distribuição greedy por tamanho estimado
 * ========================================================================== */

/* REQUISITO A: varre o directório (e subdirectórios) e preenche FileList
 * com os caminhos de todos os ficheiros .log e .json encontrados.
 * Syscalls: opendir, readdir, stat, closedir */
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
            /* REQUISITO A: aceitar apenas .log e .json */
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

/* REQUISITO B: divide os ficheiros pelos workers usando round-robin.
 * Os primeiros 'remainder' workers recebem chunk+1 ficheiros,
 * os restantes recebem chunk ficheiros — distribuição equilibrada. */
void split_files(const FileList *fl, int worker_id, int num_workers,
                 int *start, int *end)
{
    int chunk     = fl->count / num_workers;
    int remainder = fl->count % num_workers;

    if (worker_id < remainder) {
        *start = worker_id * (chunk + 1);
        *end   = *start + chunk + 1;
    } else {
        *start = remainder * (chunk + 1) + (worker_id - remainder) * chunk;
        *end   = *start + chunk;
    }
}

/* REQUISITO B / D: conta o número de linhas de um ficheiro usando
 * apenas syscalls POSIX (open/read/close), sem usar fopen/fread.
 * Usado para estimar o progresso percentual do dashboard.
 * Syscalls: open, read, close */
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

/* REQUISITO B: atribuição greedy de ficheiros por tamanho estimado.
 * Alternativa ao round-robin — minimiza o desequilíbrio de carga
 * entre workers quando os ficheiros têm tamanhos muito diferentes. */
void split_files_balanced(const FileList *fl, int num_workers, int *assignment)
{
    long loads[MAX_FILES];

    if (!fl || !assignment || num_workers <= 0) return;

    for (int i = 0; i < num_workers && i < MAX_FILES; i++)
        loads[i] = 0;

    for (int i = 0; i < fl->count; i++) {
        /* Atribuir ao worker com menor carga actual */
        int best = 0;
        for (int w = 1; w < num_workers; w++) {
            if (loads[w] < loads[best])
                best = w;
        }
        assignment[i] = best;
        loads[best] += count_lines(fl->paths[i]);
    }
}
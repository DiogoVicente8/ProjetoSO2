#ifndef FILES_H
#define FILES_H

#define MAX_FILES 8192

typedef struct {
    char paths[MAX_FILES][1024];
    int  count;
} FileList;

/* Percorre dir recursivamente e preenche fl com .log e .json encontrados.
 * Retorna número de ficheiros encontrados, ou -1 em erro. */
int  discover_files(const char *dir, FileList *fl);

/* Calcula o intervalo [*start, *end[ de ficheiros para o worker worker_id. */
void split_files(const FileList *fl, int worker_id, int num_workers,
                 int *start, int *end);

/* Atribui cada ficheiro a um worker tentando equilibrar pelo número de linhas. */
void split_files_balanced(const FileList *fl, int num_workers, int *assignment);

/* Conta linhas num ficheiro usando read() */
long count_lines(const char *path);

#endif

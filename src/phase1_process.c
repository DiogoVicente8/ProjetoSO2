/*
 * phase1_process.c — Processo pai/filho da Fase 1
 *
 * Agrupa os requisitos B, C, D e E para manter logAnalyzer.c pequeno.
 * Este ficheiro contém a lógica de gestão de workers, IPC e atualização
 * de progresso / dashboard em tempo real.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/wait.h>

#include "../include/phase1_process.h"
#include "../include/worker.h"

/* Caminho do socket UNIX usado para comunicação entre worker e processo pai. */
#define SOCKET_PATH "/tmp/loganalyzer.sock"

/* ==========================================================================
 * REQUISITO B/C — Escrita dos resultados individuais em ficheiro por worker
 * ========================================================================== */
static void write_worker_result_file(const WorkerResult *r, const char *data)
{
    /* Cria um buffer para o nome do ficheiro de resultados. */
    char path[64];
    int len = snprintf(path, sizeof(path), "results_%d.txt", (int)r->pid);
    if (len < 0 || len >= (int)sizeof(path))
        return; /* Se o nome foi truncado, não prossegue. */

    /* Abre o ficheiro para escrita, criando ou truncando se necessário. */
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        perror("open (worker result)");
        return;
    }

    /* Escreve os dados no ficheiro e fecha o descritor. */
    writen(fd, data, strlen(data));
    close(fd);
}

/* ==========================================================================
 * REQUISITO C / D — Procura o estado do worker a partir do PID
 * ========================================================================== */
static WorkerStatus *find_status_by_pid(WorkerStatus *statuses,
                                        int n_workers, pid_t pid)
{
    /* Percorre cada worker até encontrar o PID correspondente. */
    for (int i = 0; i < n_workers; i++) {
        if (statuses[i].pid == pid)
            return &statuses[i];
    }
    return NULL; /* Se nenhum worker corresponder, retorna NULL. */
}

/* ==========================================================================
 * REQUISITO C — Processa a linha RESULT enviada pelo worker
 * ========================================================================== */
static int handle_result_line(const char *line, WorkerResult *results, int received,
                              int max, WorkerStatus *statuses, int n_workers)
{
    if (received >= max)
        return 0; /* Não processa mais resultados do que o permitido. */

    worker_result_parse(line, &results[received]); /* Deserializa o resultado. */

    WorkerStatus *status = find_status_by_pid(statuses, n_workers,
                                             results[received].pid);
    if (status) {
        status->lines_processed = results[received].lines_total; /* Atualiza total. */
        status->progress_pct = 100.0f; /* O worker terminou. */
        status->state = STATE_DONE;
    }
    return 1; /* Indica que um resultado foi processado. */
}

/* ==========================================================================
 * REQUISITO D — Helper de tempo
 * ========================================================================== */
double phase1_now_secs(void)
{
    struct timeval tv; /* Estrutura para tempo em segundos + microssegundos. */
    gettimeofday(&tv, NULL); /* Obtém o tempo atual. */
    return (double)tv.tv_sec + (double)tv.tv_usec / 1e6; /* Converte para segundos. */
}

/* ==========================================================================
 * REQUISITO D — Atualiza a barra de progresso com mensagens PROGRESS
 * ========================================================================== */
static void update_worker_progress(const char *line,
                                   WorkerStatus *statuses, int n_workers)
{
    pid_t pid = 0; /* PID do worker recebido na mensagem. */
    long lines = 0; /* Número de linhas processadas até agora. */
    const char *p;

    if ((p = strstr(line, "PID:")) != NULL)
        pid = (pid_t)atol(p + 4); /* Extrai o valor após "PID:". */
    if ((p = strstr(line, "LINES:")) != NULL)
        lines = atol(p + 6); /* Extrai o valor após "LINES:". */

    WorkerStatus *status = find_status_by_pid(statuses, n_workers, pid);
    if (!status)
        return; /* Ignora se o PID não corresponder a nenhum worker. */

    status->lines_processed = lines; /* Regista o progresso atual. */
    if (status->total_lines > 0) {
        status->progress_pct = (float)lines / status->total_lines * 100.0f;
        if (status->progress_pct > 100.0f)
            status->progress_pct = 100.0f; /* Limita a 100%. */
    }
    status->state = STATE_WORKING; /* O worker ainda está a processar. */
}

/* ==========================================================================
 * REQUISITO D — Imprime eventos verbose em tempo real
 * ========================================================================== */
static void print_verbose_event(const char *line)
{
    char sev[16] = ""; /* Severidade do evento. */
    char msg[320] = ""; /* Mensagem do evento. */
    char ip[48] = ""; /* IP associado ao evento. */
    const char *p;

    if ((p = strstr(line, "SEV:")) != NULL)
        sscanf(p + 4, "%15[^;]", sev); /* Copia até ao separador ';'. */
    if ((p = strstr(line, "MSG:")) != NULL)
        sscanf(p + 4, "%319[^;]", msg);
    if ((p = strstr(line, "IP:")) != NULL)
        sscanf(p + 3, "%47[^;]", ip);

    printf("  [%s] %s  (IP: %s)\n", sev, msg, ip); /* Imprime o evento verbose. */
}

/* ==========================================================================
 * REQUISITO E — Liga o worker ao pai usando Unix Domain Socket
 * ========================================================================== */
static int connect_to_parent_socket(void)
{
    int sk = socket(AF_UNIX, SOCK_STREAM, 0); /* Cria socket UNIX de stream. */
    if (sk < 0)
        return -1; /* Falha na criação do socket. */

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr)); /* Zera a estrutura de endereço. */
    addr.sun_family = AF_UNIX; /* Define família UNIX. */
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1); /* Define caminho. */

    for (int tries = 0; tries < 30; tries++) {
        if (connect(sk, (struct sockaddr *)&addr, sizeof(addr)) == 0)
            return sk; /* Conexão bem-sucedida. */
        usleep(100000); /* Espera 100ms antes de tentar novamente. */
    }

    close(sk); /* Fecha socket se não conseguiu conectar. */
    return -1;
}

/* ==========================================================================
 * REQUISITO C / D / E — Lê dados de pipe ou socket e actualiza dashboard
 * ========================================================================== */
static int collect_from_fd(int fd, WorkerResult *results, int max,
                           WorkerStatus *statuses, int n_workers,
                           double t0, bool verbose)
{
    char buf[8192]; /* Buffer para dados lidos. */
    char line[1024]; /* Buffer para linha actual. */
    int lpos = 0; /* Posição actual na linha. */
    int received = 0; /* Resultados completos recebidos. */
    double t_last = t0; /* Tempo da última actualização do dashboard. */

    while (received < max) {
        ssize_t n = read(fd, buf, sizeof(buf) - 1); /* Lê dados do pipe/socket. */
        if (n < 0) {
            if (errno == EINTR)
                continue; /* Continua se a leitura foi interrompida. */
            break; /* Erro irreparável. */
        }
        if (n == 0)
            break; /* Fim do fluxo. */

        buf[n] = '\0'; /* Termina a string para parsing. */
        for (ssize_t i = 0; i < n; i++) {
            char c = buf[i];
            if (c == '\n' || c == '\r') {
                if (lpos == 0)
                    continue; /* Ignora linhas vazias. */

                line[lpos] = '\0'; /* Termina a linha actual. */
                lpos = 0; /* Reinicia a posição da linha. */

                if (strncmp(line, "RESULT;", 7) == 0) {
                    received += handle_result_line(line, results, received,
                                                   max, statuses, n_workers);
                } else if (strncmp(line, "PROGRESS;", 9) == 0) {
                    update_worker_progress(line, statuses, n_workers);
                } else if (verbose && strncmp(line, "VERBOSE;", 8) == 0) {
                    print_verbose_event(line);
                }

                double t_now = phase1_now_secs(); /* Tempo actual. */
                if (t_now - t_last >= 1.0) {
                    long errs = 0; /* Contador de erros totais. */
                    for (int j = 0; j < received; j++)
                        errs += results[j].count_error + results[j].count_critical;
                    long lines = 0; /* Total de linhas processadas por todos. */
                    for (int j = 0; j < n_workers; j++)
                        lines += statuses[j].lines_processed;
                    long eps = (t_now - t0 > 0) ? (long)(lines / (t_now - t0)) : 0;
                    if (!verbose)
                        dashboard_draw(statuses, n_workers,
                                       t_now - t0, eps, errs);
                    t_last = t_now; /* Actualiza o tempo da última actualização. */
                }
            } else if (lpos < (int)sizeof(line) - 1) {
                line[lpos++] = c; /* Acumula caracteres na linha actual. */
            }
        }
    }
    return received; /* Retorna o número de resultados recebidos. */
}

/* ==========================================================================
 * REQUISITO B / C / E — Processo FILHO
 * ========================================================================== */
static void run_worker(int id, const FileList *fl, const Config *cfg,
                       int write_fd, bool use_sockets)
{
    int comm_fd = write_fd; /* Descritor de comunicação padrão. */

    if (use_sockets) {
        int sk = connect_to_parent_socket(); /* Liga ao socket do pai. */
        if (sk < 0) {
            perror("connect");
            exit(EXIT_FAILURE); /* Sai se não conseguir conectar. */
        }
        comm_fd = sk; /* Usa o socket em vez do pipe. */
    }

    WorkerResult r = process_files(id, fl, cfg, comm_fd); /* Processa os ficheiros. */

    char buf[2048]; /* Buffer para resultado serializado. */
    worker_result_serialize(&r, buf, sizeof(buf)); /* Serializa resultado. */
    write_worker_result_file(&r, buf); /* Grava ficheiro de resultado local. */
    writen(comm_fd, buf, strlen(buf)); /* Envia resultado ao pai. */

    if (use_sockets)
        close(comm_fd); /* Fecha a ligação socket no worker. */
    exit(EXIT_SUCCESS); /* Termina o processo worker. */
}

/* ==========================================================================
 * REQUISITO B.1 — Processo PAI: descobrir ficheiros .log/.json
 * ========================================================================== */
int phase1_parent_discover_log_files(Config *cfg, FileList *fl)
{
    if (discover_files(cfg->log_dir, fl) <= 0) {
        fprintf(stderr, "Erro: nenhum ficheiro .log/.json encontrado em '%s'\n",
                cfg->log_dir);
        return -1; /* Retorna erro se não encontrar ficheiros. */
    }

    printf("[INFO] %d ficheiro(s) encontrado(s)\n", fl->count); /* Mostra contagem. */

    if (cfg->num_procs > fl->count) {
        cfg->num_procs = fl->count; /* Ajusta workers ao número de ficheiros. */
        printf("[INFO] Workers ajustados para %d (nº de ficheiros)\n",
               cfg->num_procs);
    }

    return 0; /* Sucesso. */
}

/* ==========================================================================
 * REQUISITO D — Processo PAI: preparar estados para o dashboard
 * ========================================================================== */
void phase1_parent_prepare_worker_statuses(const FileList *fl, const Config *cfg,
                                           WorkerStatus *statuses)
{
    for (int i = 0; i < cfg->num_procs; i++) {
        int s, e; /* Índices de início e fim dos ficheiros do worker. */
        split_files(fl, i, cfg->num_procs, &s, &e);

        long est = 0; /* Estimativa de linhas para este worker. */
        for (int j = s; j < e; j++)
            est += count_lines(fl->paths[j]); /* Conta linhas de cada ficheiro. */

        statuses[i].total_lines = est > 0 ? est : 1; /* Evita divisão por zero. */
        statuses[i].state = STATE_IDLE; /* Inicializa como idle. */
    }
}

/* ==========================================================================
 * REQUISITO C / E — Processo PAI: criar comunicação IPC
 * ========================================================================== */
int phase1_parent_setup_ipc(bool use_sockets, int num_procs,
                            int *pipe_rd, int *pipe_wr, int *server_fd)
{
    *pipe_rd = -1; /* Inicializa descritores com valores inválidos. */
    *pipe_wr = -1;
    *server_fd = -1;

    if (use_sockets) {
        unlink(SOCKET_PATH); /* Remove socket antigo se existir. */
        *server_fd = socket(AF_UNIX, SOCK_STREAM, 0); /* Cria socket de servidor. */
        if (*server_fd < 0) {
            perror("socket");
            return -1;
        }

        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

        if (bind(*server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            perror("bind");
            return -1;
        }
        if (listen(*server_fd, num_procs + 2) < 0) {
            perror("listen");
            return -1;
        }
    } else {
        int fds[2]; /* Par de descritores de pipe. */
        if (pipe(fds) < 0) {
            perror("pipe");
            return -1;
        }
        *pipe_rd = fds[0]; /* Descritor de leitura para o pai. */
        *pipe_wr = fds[1]; /* Descritor de escrita para os workers. */
    }

    return 0; /* Comunicação criada com sucesso. */
}

/* ==========================================================================
 * REQUISITO B.2 — Processo PAI: criar N filhos e distribuir trabalho
 * ========================================================================== */
int phase1_parent_spawn_workers(const Config *cfg, const FileList *fl,
                                pid_t *pids, WorkerStatus *statuses,
                                int pipe_rd, int pipe_wr, int server_fd,
                                bool use_sockets)
{
    for (int i = 0; i < cfg->num_procs; i++) {
        pid_t pid = fork(); /* Cria um novo processo worker. */
        if (pid < 0) {
            perror("fork");
            return -1;
        }

        if (pid == 0) {
            if (!use_sockets)
                close(pipe_rd); /* Filho fecha extremidade de leitura do pipe. */
            else
                close(server_fd); /* Filho fecha socket de servidor no modo sockets. */

            run_worker(i, fl, cfg, pipe_wr, use_sockets); /* Executa worker. */
        }

        pids[i] = pid; /* Guarda PID do filho no pai. */
        statuses[i].pid = pid; /* Regista PID no estado. */
        statuses[i].state = STATE_WORKING; /* Worker está activo. */
    }

    return 0;
}

/* ==========================================================================
 * REQUISITO C / E — Processo PAI: recolher resultados dos filhos
 * ========================================================================== */
int phase1_parent_collect_worker_results(const Config *cfg, pid_t *pids,
                                         WorkerResult *results,
                                         WorkerStatus *statuses,
                                         int pipe_rd, int pipe_wr,
                                         int server_fd, bool use_sockets,
                                         double t0)
{
    int received = 0; /* Número de resultados completos recebidos. */

    if (use_sockets) {
        for (int i = 0; i < cfg->num_procs; i++) {
            int cli = accept(server_fd, NULL, NULL); /* Aceita ligação do worker. */
            if (cli < 0) {
                if (errno == EINTR) {
                    i--; /* Tenta novamente se a accept foi interrompida. */
                    continue;
                }
                perror("accept");

                for (int j = 0; j < cfg->num_procs; j++)
                    kill(pids[j], SIGKILL); /* Aborta todos os workers. */

                close(server_fd);
                unlink(SOCKET_PATH); /* Limpa o socket. */
                server_fd = -1;
                break;
            }

            received += collect_from_fd(cli, results + received,
                                        cfg->num_procs - received,
                                        statuses, cfg->num_procs,
                                        t0, cfg->verbose);
            close(cli); /* Fecha a ligação com este worker. */
        }

        if (server_fd >= 0) {
            close(server_fd);
            unlink(SOCKET_PATH); /* Remove arquivo do socket no final. */
        }
    } else {
        close(pipe_wr); /* Fecha extremidade de escrita no pai antes de ler. */
        received = collect_from_fd(pipe_rd, results, cfg->num_procs,
                                   statuses, cfg->num_procs, t0, cfg->verbose);
        close(pipe_rd); /* Fecha extremidade de leitura após terminar. */
    }

    return received; /* Retorna quantos resultados foram recebidos. */
}

/* ==========================================================================
 * REQUISITO B.3 — Processo PAI: aguardar filhos com waitpid()
 * ========================================================================== */
void phase1_parent_wait_for_workers(pid_t *pids, WorkerStatus *statuses,
                                    int num_procs)
{
    for (int i = 0; i < num_procs; i++) {
        int status;
        if (waitpid(pids[i], &status, 0) < 0)
            perror("waitpid"); /* Aguarda a terminação do filho. */

        statuses[i].state = STATE_DONE; /* Marca o worker como concluído. */
        statuses[i].progress_pct = 100.0f; /* Progresso final completo. */
    }
}

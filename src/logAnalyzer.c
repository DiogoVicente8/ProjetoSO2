/*
 * logAnalyzer.c  —  Fase 1 completa
 *
 * Requisito A: parse de argumentos CLI
 * Requisito B: N processos filho com fork()/waitpid()
 * Requisito C: comunicação pai-filho via pipe anónimo (readn/writen)
 * Requisito D: dashboard de progresso em tempo real (ANSI, SIGUSR1)
 * Requisito E: alternativa com Unix Domain Sockets (--sockets)
 *
 * Syscalls usadas:
 * fork, waitpid, pipe, read, write, open, close, stat, kill, signal
 * socket, bind, listen, accept, connect, unlink
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "../include/config.h"
#include "../include/files.h"
#include "../include/ipc.h"
#include "../include/worker.h"
#include "../include/dashboard.h"
#include "../include/report.h"

#define SOCKET_PATH "/tmp/loganalyzer.sock"

/* ==========================================================================
 * REQUISITO C / D — Procura o estado do worker a partir do PID
 * Usado para mapear mensagens IPC ao slot correcto no dashboard
 * ========================================================================== */
static WorkerStatus *find_status_by_pid(WorkerStatus *statuses,
                                        int n_workers, pid_t pid)
{
    for (int i = 0; i < n_workers; i++) {
        if (statuses[i].pid == pid)
            return &statuses[i];
    }
    return NULL;
}


/* ==========================================================================
 * REQUISITO C — Processa a linha RESULT enviada pelo worker (resultado final)
 * Protocolo: RESULT;PID:<pid>;LINES:<n>;ERR:<e>;...
 * ========================================================================== */
static int handle_result_line(const char *line, WorkerResult *results, int received,
                              int max, WorkerStatus *statuses, int n_workers)
{
    if (received >= max)
        return 0;

    worker_result_parse(line, &results[received]);
    WorkerStatus *status = find_status_by_pid(statuses, n_workers,
                                             results[received].pid);
    if (status) {
        status->lines_processed = results[received].lines_total;
        status->progress_pct = 100.0f;
        status->state = STATE_DONE;
    }
    return 1;
}
/* ==========================================================================
 * REQUISITO D — Helper de tempo (usado no dashboard em tempo real)
 * Syscall: gettimeofday
 * ========================================================================== */
static double now_secs(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (double)tv.tv_sec + (double)tv.tv_usec / 1e6;
}

/* ==========================================================================
 * REQUISITO D — Atualiza a barra de progresso com mensagens PROGRESS
 * Protocolo: PROGRESS;PID:<pid>;LINES:<n>
 * ========================================================================== */
static void update_worker_progress(const char *line,
                                   WorkerStatus *statuses, int n_workers)
{
    pid_t pid = 0;
    long lines = 0;
    const char *p;

    if ((p = strstr(line, "PID:")) != NULL)
        pid = (pid_t)atol(p + 4);
    if ((p = strstr(line, "LINES:")) != NULL)
        lines = atol(p + 6);

    WorkerStatus *status = find_status_by_pid(statuses, n_workers, pid);
    if (!status)
        return;

    status->lines_processed = lines;
    if (status->total_lines > 0) {
        status->progress_pct = (float)lines / status->total_lines * 100.0f;
        if (status->progress_pct > 100.0f)
            status->progress_pct = 100.0f;
    }
    status->state = STATE_WORKING;
}

/* ==========================================================================
 * REQUISITO D — Imprime eventos verbose em tempo real (modo --verbose)
 * Protocolo: VERBOSE;SEV:<sev>;MSG:<msg>;IP:<ip>
 * ========================================================================== */
static void print_verbose_event(const char *line)
{
    char sev[16] = "", msg[320] = "", ip[48] = "";
    const char *p;

    if ((p = strstr(line, "SEV:")) != NULL)
        sscanf(p + 4, "%15[^;]", sev);
    if ((p = strstr(line, "MSG:")) != NULL)
        sscanf(p + 4, "%319[^;]", msg);
    if ((p = strstr(line, "IP:")) != NULL)
        sscanf(p + 3, "%47[^;]", ip);

    printf("  [%s] %s  (IP: %s)\n", sev, msg, ip);
}
/* ==========================================================================
 * REQUISITO E — Liga o worker ao pai usando Unix Domain Socket
 * Syscalls: socket, connect, close, usleep
 * ========================================================================== */
static int connect_to_parent_socket(void)
{
    int sk = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sk < 0)
        return -1;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    for (int tries = 0; tries < 30; tries++) {
        if (connect(sk, (struct sockaddr *)&addr, sizeof(addr)) == 0)
            return sk;
        usleep(100000);
    }

    close(sk);
    return -1;
}


/* ==========================================================================
 * REQUISITO C / D / E — Lê dados de pipe ou socket e actualiza o dashboard
 *
 * Esta é a função central do processo pai:
 *   - Lê blocos do fd (pipe_rd ou socket cliente)
 *   - Monta linhas completas e despacha por tipo de mensagem
 *   - Redesenha o dashboard a cada 1 segundo
 *
 * Syscalls: read
 * ========================================================================== */
static int collect_from_fd(int fd, WorkerResult *results, int max,
                            WorkerStatus *statuses, int n_workers,
                            double t0, bool verbose)
{
    char   buf[8192];
    char   line[1024];
    int    lpos     = 0;
    int    received = 0;
    double t_last   = t0;
    long   ev_total = 0;

    while (received < max) {
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (n == 0)
            break;

        buf[n] = '\0';
        for (ssize_t i = 0; i < n; i++) {
            char c = buf[i];
            if (c == '\n' || c == '\r') {
                if (lpos == 0)
                    continue;

                line[lpos] = '\0';
                lpos = 0;

                /* --- REQUISITO C: resultado final do worker --- */
                if (strncmp(line, "RESULT;", 7) == 0) {
                    received += handle_result_line(line, results, received,
                                                   max, statuses, n_workers);

                /* --- REQUISITO D: actualização de progresso --- */
                } else if (strncmp(line, "PROGRESS;", 9) == 0) {
                    update_worker_progress(line, statuses, n_workers);

                /* --- REQUISITO D: evento verbose --- */
                } else if (verbose && strncmp(line, "VERBOSE;", 8) == 0) {
                    ev_total++;
                    print_verbose_event(line);
                }

                /* --- REQUISITO D: refresh do dashboard a cada 1s --- */
                double t_now = now_secs();
                if (t_now - t_last >= 1.0) {
                    long errs = 0;
                    for (int j = 0; j < received; j++)
                        errs += results[j].count_error + results[j].count_critical;
                    long eps = (t_now - t0 > 0) ? (long)(ev_total / (t_now - t0)) : 0;
                    if (!verbose)
                        dashboard_draw(statuses, n_workers,
                                       t_now - t0, eps, errs);
                    t_last = t_now;
                }
            } else if (lpos < (int)sizeof(line) - 1) {
                line[lpos++] = c;
            }
        }
    }
    return received;
}

/* ==========================================================================
 * REQUISITO B / C / E — Processo FILHO (worker)
 *
 * Executado após fork(). Obtém o fd de comunicação (pipe ou socket),
 * processa os ficheiros atribuídos e envia o resultado final ao pai.
 *
 * Syscalls: connect (E), write via writen (C/E), exit, close
 * ========================================================================== */
static void run_worker(int id, const FileList *fl, const Config *cfg,
                        int write_fd, bool use_sockets)
{
    int comm_fd = write_fd;

    /* --- REQUISITO E: obter fd via socket em vez de pipe --- */
    if (use_sockets) {
        int sk = connect_to_parent_socket();
        if (sk < 0) {
            perror("connect");
            exit(EXIT_FAILURE);
        }
        comm_fd = sk;
    }

    /* Processar ficheiros e recolher métricas */
    WorkerResult r = process_files(id, fl, cfg, comm_fd);

    /* --- REQUISITO C / E: enviar resultado final ao pai --- */
    char buf[2048];
    worker_result_serialize(&r, buf, sizeof(buf));
    writen(comm_fd, buf, strlen(buf));

    if (use_sockets) close(comm_fd);
    exit(EXIT_SUCCESS);
}

/* ==========================================================================
 * MAIN — Orquestrador (Requisitos A / B / C / D / E)
 * ========================================================================== */
int main(int argc, char *argv[])
{
    /* -------------------------------------------------------------------------
     * REQUISITO A — Parse da linha de comandos
     * Preenche Config com: directório, num_procs, verbose, output, etc.
     * ------------------------------------------------------------------------- */
    Config cfg;
    if (parse_args(argc, argv, &cfg) < 0)
        return EXIT_FAILURE;

    if (cfg.verbose)
        print_config(&cfg);

    /* -------------------------------------------------------------------------
     * Descoberta de ficheiros (suporte a A/B)
     * ------------------------------------------------------------------------- */
    FileList *fl = calloc(1, sizeof(FileList));
    if (!fl) { perror("calloc"); return EXIT_FAILURE; }

    if (discover_files(cfg.log_dir, fl) <= 0) {
        fprintf(stderr, "Erro: nenhum ficheiro .log/.json encontrado em '%s'\n",
                cfg.log_dir);
        free(fl); return EXIT_FAILURE;
    }
    printf("[INFO] %d ficheiro(s) encontrado(s)\n", fl->count);

    /* Ajustar num_procs se houver menos ficheiros que workers pedidos */
    if (cfg.num_procs > fl->count) {
        cfg.num_procs = fl->count;
        printf("[INFO] Workers ajustados para %d (nº de ficheiros)\n",
               cfg.num_procs);
    }

    /* -------------------------------------------------------------------------
     * Estruturas de controlo partilhadas pelo pai
     * ------------------------------------------------------------------------- */
    pid_t        *pids     = malloc((size_t)cfg.num_procs * sizeof(pid_t));
    WorkerResult *results  = calloc((size_t)cfg.num_procs, sizeof(WorkerResult));
    WorkerStatus *statuses = calloc((size_t)cfg.num_procs, sizeof(WorkerStatus));
    if (!pids || !results || !statuses) { perror("malloc"); return EXIT_FAILURE; }

    /* REQUISITO D: estimar linhas por worker para a barra de progresso */
    for (int i = 0; i < cfg.num_procs; i++) {
        int s, e;
        split_files(fl, i, cfg.num_procs, &s, &e);
        long est = 0;
        for (int j = s; j < e; j++) est += count_lines(fl->paths[j]);
        statuses[i].total_lines = est > 0 ? est : 1;
        statuses[i].state       = STATE_IDLE;
    }

    /* REQUISITO D: inicializar dashboard (só no modo normal) */
    if (!cfg.verbose)
        dashboard_init(cfg.num_procs);
    fflush(stdout);

    double t0 = now_secs();

    /* -------------------------------------------------------------------------
     * REQUISITO C / E — Criar meio de comunicação IPC
     * ------------------------------------------------------------------------- */
    bool use_sockets = false;
#ifdef USE_SOCKETS
    use_sockets = true;
#endif

    int pipe_rd = -1, pipe_wr = -1;
    int server_fd = -1;

    /* REQUISITO E: Unix Domain Socket — pai actua como servidor */
    if (use_sockets) {
        unlink(SOCKET_PATH);
        server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (server_fd < 0) { perror("socket"); return EXIT_FAILURE; }

        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

        if (bind(server_fd,   (struct sockaddr *)&addr, sizeof(addr)) < 0)
            { perror("bind");   return EXIT_FAILURE; }
        if (listen(server_fd, cfg.num_procs + 2) < 0)
            { perror("listen"); return EXIT_FAILURE; }

    /* REQUISITO C: pipe anónimo — todos os filhos escrevem, pai lê */
    } else {
        int fds[2];
        if (pipe(fds) < 0) { perror("pipe"); return EXIT_FAILURE; }
        pipe_rd = fds[0];
        pipe_wr = fds[1];
    }

    /* -------------------------------------------------------------------------
     * REQUISITO B — fork() dos N workers
     * Syscalls: fork
     * ------------------------------------------------------------------------- */
    for (int i = 0; i < cfg.num_procs; i++) {
        pid_t pid = fork();
        if (pid < 0) { perror("fork"); return EXIT_FAILURE; }

        if (pid == 0) {
            /* --- FILHO --- */
            if (!use_sockets)
                close(pipe_rd);     /* filho não lê do pipe */
            else
                close(server_fd);   /* filho não usa o server socket */

            run_worker(i, fl, &cfg, pipe_wr, use_sockets);
            /* run_worker termina com exit() — nunca chega aqui */
        }

        /* --- PAI: regista PID e estado inicial --- */
        pids[i]           = pid;
        statuses[i].pid   = pid;
        statuses[i].state = STATE_WORKING;
    }

    /* -------------------------------------------------------------------------
     * REQUISITO C / E — Pai recolhe resultados dos workers
     * ------------------------------------------------------------------------- */
    int received = 0;

    /* REQUISITO E: aceitar conexões dos filhos (uma por worker) */
    if (use_sockets) {
        for (int i = 0; i < cfg.num_procs; i++) {
            int cli = accept(server_fd, NULL, NULL);
            if (cli < 0) {
                if (errno == EINTR) { i--; continue; }
                perror("accept");

                /* Erro crítico: matar filhos para evitar zombies */
                for (int j = 0; j < cfg.num_procs; j++)
                    kill(pids[j], SIGKILL);

                close(server_fd);
                unlink(SOCKET_PATH);
                server_fd = -1;
                break;
            }

            received += collect_from_fd(cli, results + received,
                                        cfg.num_procs - received,
                                        statuses, cfg.num_procs,
                                        t0, cfg.verbose);
            close(cli);
        }

        if (server_fd >= 0) {
            close(server_fd);
            unlink(SOCKET_PATH);
        }

    /* REQUISITO C: ler do pipe até EOF (todos os filhos fecharam a escrita) */
    } else {
        close(pipe_wr); /* pai fecha a extremidade de escrita */
        received = collect_from_fd(pipe_rd, results, cfg.num_procs,
                                   statuses, cfg.num_procs, t0, cfg.verbose);
        close(pipe_rd);
    }

    /* -------------------------------------------------------------------------
     * REQUISITO B — Aguardar todos os filhos com waitpid()
     * Syscall: waitpid
     * Evita processos zombie e garante que os recursos dos filhos são libertados
     * ------------------------------------------------------------------------- */
    for (int i = 0; i < cfg.num_procs; i++) {
        int status;
        if (waitpid(pids[i], &status, 0) < 0) perror("waitpid");
        statuses[i].state        = STATE_DONE;
        statuses[i].progress_pct = 100.0f;
    }

    double elapsed = now_secs() - t0;

    /* -------------------------------------------------------------------------
     * REQUISITO D — Dashboard final e relatório
     * ------------------------------------------------------------------------- */
    if (!cfg.verbose) {
        long errs = 0;
        for (int i = 0; i < received; i++)
            errs += results[i].count_error + results[i].count_critical;
        dashboard_draw(statuses, cfg.num_procs, elapsed, 0, errs);
        dashboard_done(cfg.num_procs);
    }

    /* -------------------------------------------------------------------------
     * REQUISITO A — Relatório final (output definido nos argumentos CLI)
     * aggregate() combina todos os WorkerResult num GlobalResult centralizado
     * ------------------------------------------------------------------------- */
    GlobalResult gr;
    aggregate(results, received, &gr);

    print_report(&gr, results, received, &cfg, elapsed);

    if (cfg.has_output)
        write_report_json(&gr, &cfg, elapsed, cfg.output_file);

    /* -------------------------------------------------------------------------
     * REQUISITO D — Benchmarks (só em modo verbose)
     * ------------------------------------------------------------------------- */
    if (cfg.verbose) {
        printf("\n[Benchmarks]\n");
        printf("  Linhas/segundo : %.0f\n",
               elapsed > 0 ? (double)gr.total_lines / elapsed : 0);
        printf("  Workers        : %d\n", cfg.num_procs);
        printf("  Tempo          : %.3f s\n", elapsed);
    }

    free(fl); free(pids); free(results); free(statuses);
    return EXIT_SUCCESS;
}
/*
 * logAnalyzer.c  —  Fase 1 completa (Versão Corrigida e Robusta)
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

#include "config.h"
#include "files.h"
#include "ipc.h"
#include "worker.h"
#include "dashboard.h"
#include "report.h"

#define SOCKET_PATH "/tmp/loganalyzer.sock"

/* ==========================================================================
 * Helpers de tempo
 * ========================================================================== */
static double now_secs(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (double)tv.tv_sec + (double)tv.tv_usec / 1e6;
}

/* ==========================================================================
 * Leitura de resultados a partir de um fd (pipe ou socket aceite)
 *
 * Lê linhas de texto terminadas em '\n'.
 * Linhas "RESULT;..." → resultado final do worker.
 * Linhas "VERBOSE;..."→ evento crítico em tempo real (modo verbose).
 *
 * Retorna o número de WorkerResults recebidos.
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
        if (n < 0) { if (errno == EINTR) continue; break; }
        if (n == 0) break;
        buf[n] = '\0';

        for (ssize_t i = 0; i < n; i++) {
            char c = buf[i];
            if (c == '\n' || c == '\r') {
                if (lpos == 0) continue;
                line[lpos] = '\0'; lpos = 0;

                if (strncmp(line, "RESULT;", 7) == 0) {
                    if (received < max) {
                        worker_result_parse(line, &results[received]);
                        for (int s = 0; s < n_workers; s++) {
                            if (statuses[s].pid == results[received].pid) {
                                statuses[s].lines_processed = results[received].lines_total;
                                statuses[s].state = STATE_DONE;
                                statuses[s].progress_pct = 100.0f;
                                break;
                            }
                        }
                        received++;
                    }
                } else if (strncmp(line, "PROGRESS;", 9) == 0) {
                    pid_t pid = 0;
                    long lines = 0;
                    const char *p;
                    if ((p = strstr(line, "PID:")) != NULL) pid = (pid_t)atol(p + 4);
                    if ((p = strstr(line, "LINES:")) != NULL) lines = atol(p + 6);
                    for (int s = 0; s < n_workers; s++) {
                        if (statuses[s].pid == pid) {
                            statuses[s].lines_processed = lines;
                            if (statuses[s].total_lines > 0) {
                                statuses[s].progress_pct =
                                    (float)lines / statuses[s].total_lines * 100.0f;
                                if (statuses[s].progress_pct > 100.0f)
                                    statuses[s].progress_pct = 100.0f;
                            }
                            statuses[s].state = STATE_WORKING;
                            break;
                        }
                    }
                } else if (verbose && strncmp(line, "VERBOSE;", 8) == 0) {
                    ev_total++;
                    /* Extrair e imprimir campos relevantes */
                    char sev[16] = "", msg[320] = "", ip[48] = "";
                    /* parsing simples do formato VERBOSE;...;SEV:X;MSG:Y;IP:Z */
                    const char *p;
                    if ((p = strstr(line, "SEV:"))  != NULL) {
                        sscanf(p + 4, "%15[^;]", sev);
                    }
                    if ((p = strstr(line, "MSG:"))  != NULL) {
                        sscanf(p + 4, "%319[^;]", msg);
                    }
                    if ((p = strstr(line, "IP:"))   != NULL) {
                        sscanf(p + 3, "%47[^;]", ip);
                    }
                    printf("  [%s] %s  (IP: %s)\n", sev, msg, ip);
                }

                /* Atualizar dashboard ~1×/segundo */
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
 * Processo FILHO — Requisitos B/C/E
 * ========================================================================== */
static void run_worker(int id, const FileList *fl, const Config *cfg,
                        int write_fd, bool use_sockets)
{
    int comm_fd = write_fd;

    if (use_sockets) {
        /* E: ligar ao servidor (pai) via Unix Domain Socket */
        int sk = socket(AF_UNIX, SOCK_STREAM, 0);
        if (sk < 0) { perror("socket"); exit(EXIT_FAILURE); }

        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

        /* Retry porque o pai pode ainda não estar em listen() */
        for (int tries = 0; tries < 30; tries++) {
            if (connect(sk, (struct sockaddr *)&addr, sizeof(addr)) == 0)
                goto connected;
            usleep(100000);  /* 100 ms */
        }
        perror("connect"); close(sk); exit(EXIT_FAILURE);
    connected:
        comm_fd = sk;
    }

    /* Processar ficheiros e recolher métricas */
    WorkerResult r = process_files(id, fl, cfg, comm_fd);

    /* Enviar resultado final ao pai */
    char buf[2048];
    worker_result_serialize(&r, buf, sizeof(buf));
    writen(comm_fd, buf, strlen(buf));

    if (use_sockets) close(comm_fd);
    exit(EXIT_SUCCESS);
}

/* ==========================================================================
 * MAIN
 * ========================================================================== */
int main(int argc, char *argv[])
{
    /* ------------------------------------------------------------------ */
    /* A. Parse da linha de comandos                                       */
    /* ------------------------------------------------------------------ */
    Config cfg;
    if (parse_args(argc, argv, &cfg) < 0)
        return EXIT_FAILURE;

    if (cfg.verbose)
        print_config(&cfg);

    /* ------------------------------------------------------------------ */
    /* Descoberta de ficheiros                                             */
    /* ------------------------------------------------------------------ */
    FileList *fl = calloc(1, sizeof(FileList));
    if (!fl) { perror("calloc"); return EXIT_FAILURE; }

    if (discover_files(cfg.log_dir, fl) <= 0) {
        fprintf(stderr, "Erro: nenhum ficheiro .log/.json encontrado em '%s'\n",
                cfg.log_dir);
        free(fl); return EXIT_FAILURE;
    }
    printf("[INFO] %d ficheiro(s) encontrado(s)\n", fl->count);

    /* Ajustar num_procs se houver menos ficheiros */
    if (cfg.num_procs > fl->count) {
        cfg.num_procs = fl->count;
        printf("[INFO] Workers ajustados para %d (nº de ficheiros)\n",
               cfg.num_procs);
    }

    /* ------------------------------------------------------------------ */
    /* Estruturas de controlo                                              */
    /* ------------------------------------------------------------------ */
    pid_t        *pids     = malloc((size_t)cfg.num_procs * sizeof(pid_t));
    WorkerResult *results  = calloc((size_t)cfg.num_procs, sizeof(WorkerResult));
    WorkerStatus *statuses = calloc((size_t)cfg.num_procs, sizeof(WorkerStatus));
    if (!pids || !results || !statuses) { perror("malloc"); return EXIT_FAILURE; }

    /* Estimar linhas por worker para a barra de progresso */
    for (int i = 0; i < cfg.num_procs; i++) {
        int s, e;
        split_files(fl, i, cfg.num_procs, &s, &e);
        long est = 0;
        for (int j = s; j < e; j++) est += count_lines(fl->paths[j]);
        statuses[i].total_lines = est > 0 ? est : 1;
        statuses[i].state       = STATE_IDLE;
    }

    /* ------------------------------------------------------------------ */
    /* Inicializar dashboard (só no modo normal)                           */
    /* ------------------------------------------------------------------ */
    if (!cfg.verbose)
        dashboard_init(cfg.num_procs);
    fflush(stdout);

    double t0 = now_secs();

    /* ------------------------------------------------------------------ */
    /* B/C/E. Criar pipe ou socket e fazer fork dos workers               */
    /* ------------------------------------------------------------------ */
    bool use_sockets = false;
    /* Verificar se --sockets foi pedido: o campo extra pode ser adicionado
       ao Config se necessário; por ora detectamos via variável de ambiente
       para manter a interface do enunciado intacta.                        */
#ifdef USE_SOCKETS
    use_sockets = true;
#endif

    int pipe_rd = -1, pipe_wr = -1;
    int server_fd = -1;

    if (use_sockets) {
        /* E. Unix Domain Socket — PAI = SERVIDOR */
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
    } else {
        /* C. Pipe anónimo — todos os filhos escrevem, pai lê */
        int fds[2];
        if (pipe(fds) < 0) { perror("pipe"); return EXIT_FAILURE; }
        pipe_rd = fds[0];
        pipe_wr = fds[1];
    }

    /* fork() dos N workers */
    for (int i = 0; i < cfg.num_procs; i++) {
        pid_t pid = fork();
        if (pid < 0) { perror("fork"); return EXIT_FAILURE; }

        if (pid == 0) {
            /* --- FILHO --- */
            if (!use_sockets) {
                close(pipe_rd);         /* filho não lê do pipe */
            } else {
                close(server_fd);       /* filho não usa o server socket */
            }
            run_worker(i, fl, &cfg, pipe_wr, use_sockets);
            /* run_worker chama exit() */
        }

        /* --- PAI --- */
        pids[i]             = pid;
        statuses[i].pid     = pid;
        statuses[i].state   = STATE_WORKING;
    }

    /* ------------------------------------------------------------------ */
    /* PAI: recolher resultados                                            */
    /* ------------------------------------------------------------------ */
    int received = 0;

    if (use_sockets) {
        /* E: aceitar cfg.num_procs conexões dos filhos */
        for (int i = 0; i < cfg.num_procs; i++) {
            int cli = accept(server_fd, NULL, NULL);
            if (cli < 0) { 
                /* Se for interrupção de sinal benigno (EINTR), tentamos novamente */
                if (errno == EINTR) {
                    i--; 
                    continue; 
                }
                perror("accept"); 
                
                /* ERRO CRÍTICO: Matar os processos filhos para evitar órfãos e zombies */
                for (int j = 0; j < cfg.num_procs; j++) {
                    kill(pids[j], SIGKILL); 
                }
                
                /* Fechar recursos abertos do Kernel */
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
        
        /* Encerramento normal do Socket do Servidor */
        if (server_fd >= 0) {
            close(server_fd);
            unlink(SOCKET_PATH);
        }
    } else {
        /* C: fechar extremidade de escrita no pai */
        close(pipe_wr);
        received = collect_from_fd(pipe_rd, results, cfg.num_procs, statuses, cfg.num_procs, t0, cfg.verbose);
        close(pipe_rd);
    }

    /* ------------------------------------------------------------------ */
    /* B. Aguardar todos os filhos com waitpid()                          */
    /* ------------------------------------------------------------------ */
    for (int i = 0; i < cfg.num_procs; i++) {
        int status;
        if (waitpid(pids[i], &status, 0) < 0) perror("waitpid");
        statuses[i].state       = STATE_DONE;
        statuses[i].progress_pct = 100.0f;
    }

    double elapsed = now_secs() - t0;

    /* Dashboard final */
    if (!cfg.verbose) {
        long errs = 0;
        for (int i = 0; i < received; i++)
            errs += results[i].count_error + results[i].count_critical;
        dashboard_draw(statuses, cfg.num_procs, elapsed, 0, errs);
        dashboard_done(cfg.num_procs);
    }

    /* ------------------------------------------------------------------ */
    /* Agregar e imprimir relatório                                        */
    /* ------------------------------------------------------------------ */
    GlobalResult gr;
    aggregate(results, received, &gr);

    print_report(&gr, results, received, &cfg, elapsed);

    if (cfg.has_output)
        write_report_json(&gr, &cfg, elapsed, cfg.output_file);

    /* ------------------------------------------------------------------ */
    /* Benchmarks de speedup (útil para o relatório do projeto)           */
    /* ------------------------------------------------------------------ */
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
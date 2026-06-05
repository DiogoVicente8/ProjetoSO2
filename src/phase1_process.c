/*
 * phase1_process.c — Processo pai/filho da Fase 1
 *
 * Agrupa os requisitos B, C, D e E para manter logAnalyzer.c pequeno.
 * Este ficheiro contém a lógica de gestão de workers, IPC e atualização
 * de progresso / dashboard em tempo real.
 */

#define _GNU_SOURCE                  /* Ativa extensões GNU (usleep, gettimeofday, etc.). */
#include <errno.h>                   /* errno, EINTR. */
#include <fcntl.h>                   /* open, O_WRONLY, O_CREAT, O_TRUNC. */
#include <signal.h>                  /* kill, SIGKILL. */
#include <stdio.h>                   /* fprintf, printf, perror. */
#include <stdlib.h>                  /* exit, atol, EXIT_SUCCESS, EXIT_FAILURE. */
#include <string.h>                  /* memset, strncpy, strstr, strlen, strncmp. */
#include <unistd.h>                  /* read, write, close, pipe, fork, usleep. */
#include <sys/socket.h>              /* socket, bind, listen, accept, connect. */
#include <sys/time.h>                /* gettimeofday, struct timeval. */
#include <sys/un.h>                  /* struct sockaddr_un, AF_UNIX. */
#include <sys/wait.h>                /* waitpid. */

#include "../include/phase1_process.h"  /* Protótipos das funções deste ficheiro. */
#include "../include/worker.h"          /* WorkerResult, process_files, worker_result_*. */

/* Caminho do socket UNIX usado para comunicação entre worker e processo pai. */
#define SOCKET_PATH "/tmp/loganalyzer.sock"

/* ==========================================================================
 * REQUISITO B/C — Escrita dos resultados individuais em ficheiro por worker
 * ========================================================================== */

/* Grava o resultado serializado de um worker num ficheiro results_<pid>.txt.
 * Isto cumpre o Requisito B, onde cada processo deve deixar o seu resultado
 * em disco de forma independente, sem comunicar com o pai. */
static void write_worker_result_file(const WorkerResult *r, const char *data)
{
    char path[64];                                          /* Buffer para o nome do ficheiro. */
    int len = snprintf(path, sizeof(path), "results_%d.txt", (int)r->pid);
    /* Constrói o nome "results_<pid>.txt" com o PID deste worker. */
    if (len < 0 || len >= (int)sizeof(path))
        return;                                             /* Nome truncado: abandona. */

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    /* Abre/cria o ficheiro para escrita; O_TRUNC apaga conteúdo anterior. */
    if (fd < 0) {
        perror("open (worker result)");                     /* Mostra erro se falhar. */
        return;
    }

    writen(fd, data, strlen(data));                         /* Escreve o resultado serializado. */
    close(fd);                                              /* Fecha o ficheiro. */
}

/* ==========================================================================
 * REQUISITO C / D — Procura o estado do worker a partir do PID
 * ========================================================================== */

/* Percorre o array de estados dos workers e devolve um apontador para o
 * WorkerStatus cujo PID corresponde ao PID recebido. Usada para actualizar
 * o progresso e o estado de um worker específico quando chega uma mensagem. */
static WorkerStatus *find_status_by_pid(WorkerStatus *statuses,
                                        int n_workers, pid_t pid)
{
    for (int i = 0; i < n_workers; i++) {   /* Percorre todos os workers. */
        if (statuses[i].pid == pid)          /* Compara o PID de cada entrada. */
            return &statuses[i];             /* Encontrou: devolve ponteiro para o status. */
    }
    return NULL;                             /* Nenhum worker tem este PID. */
}

/* ==========================================================================
 * REQUISITO C — Processa a linha RESULT enviada pelo worker
 * ========================================================================== */

/* Recebe uma linha com prefixo "RESULT;" enviada pelo worker pelo pipe/socket,
 * deserializa-a para um WorkerResult e marca esse worker como concluído no
 * dashboard. Devolve 1 se o resultado foi guardado, 0 se o limite foi atingido. */
static int handle_result_line(const char *line, WorkerResult *results, int received,
                              int max, WorkerStatus *statuses, int n_workers)
{
    if (received >= max)
        return 0;                                          /* Já temos todos os resultados esperados. */

    worker_result_parse(line, &results[received]);         /* Deserializa a linha para WorkerResult. */

    WorkerStatus *status = find_status_by_pid(statuses, n_workers,
                                             results[received].pid);
    /* Procura o WorkerStatus correspondente ao PID que enviou este resultado. */
    if (status) {
        status->lines_processed = results[received].lines_total; /* Actualiza linhas processadas. */
        status->progress_pct = 100.0f;                           /* Marca progresso como 100%. */
        status->state = STATE_DONE;                              /* Worker terminou. */
    }
    return 1;                                              /* Um resultado foi processado. */
}

/* ==========================================================================
 * REQUISITO D — Helper de tempo
 * ========================================================================== */

/* Devolve o tempo actual em segundos com precisão de microssegundos.
 * Usado para calcular o intervalo entre actualizações do dashboard (1 segundo)
 * e para calcular o tempo decorrido desde o início do processamento. */
double phase1_now_secs(void)
{
    struct timeval tv;                                     /* Estrutura: segundos + microssegundos. */
    gettimeofday(&tv, NULL);                               /* Preenche tv com o tempo actual. */
    return (double)tv.tv_sec + (double)tv.tv_usec / 1e6;  /* Converte para segundos em vírgula flutuante. */
}

/* ==========================================================================
 * REQUISITO D — Atualiza a barra de progresso com mensagens PROGRESS
 * ========================================================================== */

/* Recebe uma linha com prefixo "PROGRESS;" enviada pelo worker a cada 500 linhas
 * processadas, extrai o PID e o número de linhas, e actualiza a percentagem de
 * progresso desse worker para que o dashboard reflicta o estado em tempo real. */
static void update_worker_progress(const char *line,
                                   WorkerStatus *statuses, int n_workers)
{
    pid_t pid = 0;                                         /* PID extraído da mensagem. */
    long lines = 0;                                        /* Linhas processadas extraídas. */
    const char *p;

    if ((p = strstr(line, "PID:")) != NULL)
        pid = (pid_t)atol(p + 4);                          /* Lê o valor após "PID:". */
    if ((p = strstr(line, "LINES:")) != NULL)
        lines = atol(p + 6);                               /* Lê o valor após "LINES:". */

    WorkerStatus *status = find_status_by_pid(statuses, n_workers, pid);
    /* Procura o WorkerStatus correspondente a este PID. */
    if (!status)
        return;                                            /* PID desconhecido: ignora a mensagem. */

    status->lines_processed = lines;                       /* Actualiza linhas processadas até agora. */
    if (status->total_lines > 0) {
        status->progress_pct = (float)lines / status->total_lines * 100.0f;
        /* Calcula a percentagem: linhas processadas / linhas totais × 100. */
        if (status->progress_pct > 100.0f)
            status->progress_pct = 100.0f;                 /* Garante que não ultrapassa 100%. */
    }
    status->state = STATE_WORKING;                         /* Worker ainda está a processar. */
}

/* ==========================================================================
 * REQUISITO D — Imprime eventos verbose em tempo real
 * ========================================================================== */

/* Recebe uma linha com prefixo "VERBOSE;" enviada pelo worker quando deteta
 * um evento de severidade HIGH ou CRITICAL em modo --verbose, extrai a
 * severidade, mensagem e IP, e imprime-os imediatamente no terminal do pai. */
static void print_verbose_event(const char *line)
{
    char sev[16] = "";   /* Buffer para a string de severidade (ex: "HIGH"). */
    char msg[320] = "";  /* Buffer para a descrição do evento. */
    char ip[48] = "";    /* Buffer para o IP de origem do evento. */
    const char *p;

    if ((p = strstr(line, "SEV:")) != NULL)
        sscanf(p + 4, "%15[^;]", sev);    /* Extrai até ao próximo ';'. */
    if ((p = strstr(line, "MSG:")) != NULL)
        sscanf(p + 4, "%319[^;]", msg);   /* Extrai a mensagem até ao ';'. */
    if ((p = strstr(line, "IP:")) != NULL)
        sscanf(p + 3, "%47[^;]", ip);     /* Extrai o IP até ao ';'. */

    printf("  [%s] %s  (IP: %s)\n", sev, msg, ip); /* Imprime o evento no terminal do pai. */
}

/* ==========================================================================
 * REQUISITO E — Liga o worker ao pai usando Unix Domain Socket
 * ========================================================================== */

/* Cria um socket AF_UNIX e tenta ligar ao servidor criado pelo processo pai
 * em /tmp/loganalyzer.sock. Tenta até 30 vezes com 100ms de espera entre
 * tentativas para dar tempo ao pai de ficar em listen() antes do filho conectar.
 * Devolve o descritor do socket ligado, ou -1 em caso de falha. */
static int connect_to_parent_socket(void)
{
    int sk = socket(AF_UNIX, SOCK_STREAM, 0); /* Cria socket de stream UNIX. */
    if (sk < 0)
        return -1;                            /* Falha na criação do socket. */

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));           /* Zera a estrutura de endereço. */
    addr.sun_family = AF_UNIX;                /* Define que é um socket de domínio UNIX. */
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1); /* Define o caminho do socket. */

    for (int tries = 0; tries < 30; tries++) {           /* Tenta até 30 vezes. */
        if (connect(sk, (struct sockaddr *)&addr, sizeof(addr)) == 0)
            return sk;                        /* Ligação bem-sucedida: devolve o socket. */
        usleep(100000);                       /* Aguarda 100ms antes de tentar de novo. */
    }

    close(sk);                                /* Esgotou tentativas: fecha o socket. */
    return -1;                                /* Devolve -1 a indicar falha. */
}

/* ==========================================================================
 * REQUISITO C / D / E — Lê dados de pipe ou socket e actualiza dashboard
 * ========================================================================== */

/* Lê continuamente dados do descritor fd (pipe ou socket) e processa as
 * mensagens linha a linha. Suporta três tipos de mensagens do protocolo:
 *   RESULT;   — resultado final do worker, deserializado e guardado
 *   PROGRESS; — actualização de progresso, reflectida no dashboard
 *   VERBOSE;  — evento crítico em tempo real, impresso no terminal
 * O dashboard é redesenhado a cada 1 segundo. Devolve o número de
 * resultados finais recebidos. */
static int collect_from_fd(int fd, WorkerResult *results, int max,
                           WorkerStatus *statuses, int n_workers,
                           double t0, bool verbose)
{
    char buf[8192];               /* Buffer para os bytes lidos do pipe/socket. */
    char line[1024];              /* Buffer para acumular os bytes de uma linha. */
    int lpos = 0;                 /* Posição actual de escrita em line[]. */
    int received = 0;             /* Número de resultados RESULT; recebidos até agora. */
    double t_last = t0;           /* Tempo da última actualização do dashboard. */

    while (received < max) {                                  /* Repete até receber todos os resultados. */
        ssize_t n = read(fd, buf, sizeof(buf) - 1);           /* Lê dados do pipe/socket. */
        if (n < 0) {
            if (errno == EINTR)
                continue;                                     /* Sinal interrompeu o read(): repete. */
            break;                                            /* Outro erro: sai do loop. */
        }
        if (n == 0)
            break;                                            /* EOF: pipe fechado / socket desligado. */

        buf[n] = '\0';                                        /* Termina o buffer para segurança. */
        for (ssize_t i = 0; i < n; i++) {                     /* Itera byte a byte no bloco recebido. */
            char c = buf[i];
            if (c == '\n' || c == '\r') {                     /* Fim de linha detectado. */
                if (lpos == 0)
                    continue;                                 /* Linha vazia: ignora. */

                line[lpos] = '\0';                            /* Termina a string da linha. */
                lpos = 0;                                     /* Reset para a próxima linha. */

                if (strncmp(line, "RESULT;", 7) == 0) {
                    received += handle_result_line(line, results, received,
                                                   max, statuses, n_workers);
                    /* Deserializa o resultado e marca o worker como DONE. */
                } else if (strncmp(line, "PROGRESS;", 9) == 0) {
                    update_worker_progress(line, statuses, n_workers);
                    /* Actualiza a percentagem do worker no dashboard. */
                } else if (verbose && strncmp(line, "VERBOSE;", 8) == 0) {
                    print_verbose_event(line);
                    /* Em modo --verbose, imprime o evento crítico no terminal. */
                }

                double t_now = phase1_now_secs();             /* Tempo actual em segundos. */
                if (t_now - t_last >= 1.0) {                  /* Passou 1 segundo desde o último draw? */
                    long errs = 0;
                    for (int j = 0; j < received; j++)
                        errs += results[j].count_error + results[j].count_critical;
                    /* Soma erros ERROR + CRITICAL de todos os workers já terminados. */
                    long lines = 0;
                    for (int j = 0; j < n_workers; j++)
                        lines += statuses[j].lines_processed;
                    /* Soma as linhas processadas por todos os workers activos. */
                    long eps = (t_now - t0 > 0) ? (long)(lines / (t_now - t0)) : 0;
                    /* Calcula eventos por segundo desde o início. */
                    if (!verbose)
                        dashboard_draw(statuses, n_workers,
                                       t_now - t0, eps, errs);
                    /* Redesenha o dashboard (só fora de modo verbose). */
                    t_last = t_now;                           /* Regista o momento deste draw. */
                }
            } else if (lpos < (int)sizeof(line) - 1) {
                line[lpos++] = c;                             /* Acumula o carácter na linha actual. */
            }
        }
    }
    return received;                                          /* Devolve o total de resultados recebidos. */
}

/* ==========================================================================
 * REQUISITO B / C / E — Processo FILHO
 * ========================================================================== */

/* Função executada pelo processo filho após o fork(). Em modo sockets, ignora
 * o pipe e liga-se ao servidor do pai via Unix Domain Socket. Chama process_files()
 * para processar os ficheiros atribuídos, serializa o resultado, grava-o em disco
 * (Req. B) e envia-o ao pai pelo canal de comunicação (Req. C/E). Termina com exit(). */
static void run_worker(int id, const FileList *fl, const Config *cfg,
                       int write_fd, bool use_sockets)
{
    int comm_fd = write_fd;                     /* Por omissão usa o pipe passado pelo pai. */

    if (use_sockets) {
        int sk = connect_to_parent_socket();    /* Liga ao socket do servidor do pai. */
        if (sk < 0) {
            perror("connect");
            exit(EXIT_FAILURE);                 /* Não conseguiu conectar: termina com erro. */
        }
        comm_fd = sk;                           /* Substitui o pipe pelo socket ligado. */
    }

    WorkerResult r = process_files(id, fl, cfg, comm_fd);
    /* Processa todos os ficheiros atribuídos a este worker e acumula as métricas. */

    char buf[2048];                             /* Buffer na stack para o resultado serializado. */
    worker_result_serialize(&r, buf, sizeof(buf)); /* Serializa WorkerResult numa linha de texto. */
    write_worker_result_file(&r, buf);          /* Grava o resultado em results_<pid>.txt (Req. B). */
    writen(comm_fd, buf, strlen(buf));          /* Envia o resultado ao pai pelo pipe/socket. */

    if (use_sockets)
        close(comm_fd);                         /* Fecha a ligação socket do lado do worker. */
    exit(EXIT_SUCCESS);                         /* Termina o processo filho normalmente. */
}

/* ==========================================================================
 * REQUISITO B.1 — Processo PAI: descobrir ficheiros .log/.json
 * ========================================================================== */

/* Percorre o directório configurado em cfg->log_dir e preenche a FileList com
 * todos os ficheiros .log e .json encontrados. Se o número de workers pedido
 * for maior que o número de ficheiros, ajusta-o para evitar workers sem trabalho.
 * Devolve 0 em caso de sucesso ou -1 se não encontrar ficheiros. */
int phase1_parent_discover_log_files(Config *cfg, FileList *fl)
{
    if (discover_files(cfg->log_dir, fl) <= 0) {          /* Procura ficheiros no directório. */
        fprintf(stderr, "Erro: nenhum ficheiro .log/.json encontrado em '%s'\n",
                cfg->log_dir);
        return -1;                                         /* Nenhum ficheiro encontrado. */
    }

    printf("[INFO] %d ficheiro(s) encontrado(s)\n", fl->count); /* Informa quantos ficheiros há. */

    if (cfg->num_procs > fl->count) {
        cfg->num_procs = fl->count;                        /* Não faz sentido ter mais workers do que ficheiros. */
        printf("[INFO] Workers ajustados para %d (nº de ficheiros)\n",
               cfg->num_procs);
    }

    return 0;                                              /* Sucesso. */
}

/* ==========================================================================
 * REQUISITO D — Processo PAI: preparar estados para o dashboard
 * ========================================================================== */

/* Inicializa o array de WorkerStatus antes de lançar os workers. Para cada worker,
 * usa split_files() para saber quais ficheiros lhe pertencem e conta as linhas
 * totais desses ficheiros com count_lines(). Esse valor é usado pelo dashboard
 * para calcular a percentagem de progresso de cada worker em tempo real. */
void phase1_parent_prepare_worker_statuses(const FileList *fl, const Config *cfg,
                                           WorkerStatus *statuses)
{
    for (int i = 0; i < cfg->num_procs; i++) {
        int s, e;                                          /* Índices de início e fim dos ficheiros. */
        split_files(fl, i, cfg->num_procs, &s, &e);       /* Calcula o intervalo deste worker. */

        long est = 0;                                      /* Acumulador de linhas estimadas. */
        for (int j = s; j < e; j++)
            est += count_lines(fl->paths[j]);              /* Conta linhas de cada ficheiro atribuído. */

        statuses[i].total_lines = est > 0 ? est : 1;      /* Guarda total; mínimo 1 para evitar divisão por zero. */
        statuses[i].state = STATE_IDLE;                    /* Worker ainda não começou. */
    }
}

/* ==========================================================================
 * REQUISITO C / E — Processo PAI: criar comunicação IPC
 * ========================================================================== */

/* Cria o canal de comunicação entre o pai e os workers. Em modo pipe (Req. C),
 * cria um pipe anónimo com pipe() e devolve os descritores de leitura e escrita.
 * Em modo socket (Req. E), cria um Unix Domain Socket, faz bind() ao caminho
 * /tmp/loganalyzer.sock e coloca-o em listen(), pronto a aceitar conexões.
 * Devolve 0 em caso de sucesso ou -1 em caso de erro. */
int phase1_parent_setup_ipc(bool use_sockets, int num_procs,
                            int *pipe_rd, int *pipe_wr, int *server_fd)
{
    *pipe_rd = -1;    /* Inicializa descritores com -1 (inválido). */
    *pipe_wr = -1;
    *server_fd = -1;

    if (use_sockets) {
        unlink(SOCKET_PATH);                               /* Remove socket anterior, se existir. */
        *server_fd = socket(AF_UNIX, SOCK_STREAM, 0);      /* Cria socket de servidor UNIX. */
        if (*server_fd < 0) {
            perror("socket");
            return -1;
        }

        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));                    /* Zera a estrutura de endereço. */
        addr.sun_family = AF_UNIX;                         /* Família UNIX (não rede). */
        strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1); /* Define o caminho. */

        if (bind(*server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            perror("bind");                                /* Liga o socket ao caminho no sistema. */
            return -1;
        }
        if (listen(*server_fd, num_procs + 2) < 0) {
            perror("listen");                              /* Coloca em escuta com fila de num_procs+2. */
            return -1;
        }
    } else {// Criação de pipe anónimo para comunicação entre pai e filhos.
        int fds[2];                                        /* Array para os dois descritores do pipe. */
        if (pipe(fds) < 0) {
            perror("pipe");
            return -1;
        }
        *pipe_rd = fds[0];                                 /* fds[0] = extremidade de leitura (pai). */
        *pipe_wr = fds[1];                                 /* fds[1] = extremidade de escrita (workers). */
    }

    return 0;                                              /* Canal criado com sucesso. */
}

/* ==========================================================================
 * REQUISITO B.2 — Processo PAI: criar N filhos e distribuir trabalho
 * ========================================================================== */

/* Cria N processos filho com fork(), um por worker. O filho fecha o descritor
 * que não precisa (leitura do pipe ou o server_fd do socket) e chama run_worker(),
 * que nunca retorna (termina com exit). O pai guarda o PID de cada filho e marca
 * o seu estado como WORKING no array de statuses para o dashboard.
 * Devolve 0 em caso de sucesso ou -1 se algum fork() falhar. */
int phase1_parent_spawn_workers(const Config *cfg, const FileList *fl,
                                pid_t *pids, WorkerStatus *statuses,
                                int pipe_rd, int pipe_wr, int server_fd,
                                bool use_sockets)
{
    for (int i = 0; i < cfg->num_procs; i++) {
        pid_t pid = fork();                                /* Cria um processo filho. */
        if (pid < 0) {
            perror("fork");
            return -1;                                     /* fork() falhou. */
        }

        if (pid == 0) {                                    /* Código executado APENAS pelo filho. */
            if (!use_sockets)
                close(pipe_rd);                            /* Filho não precisa de ler do pipe. */
            else
                close(server_fd);                          /* Filho não precisa do socket de servidor. */

            run_worker(i, fl, cfg, pipe_wr, use_sockets);  /* Processa os ficheiros e termina. */
            /* run_worker chama exit() — o código abaixo nunca é atingido pelo filho. */
        }

        /* Código executado APENAS pelo pai após o fork(). */
        pids[i] = pid;                                     /* Guarda o PID do filho criado. */
        statuses[i].pid = pid;                             /* Regista o PID no array de estados. */
        statuses[i].state = STATE_WORKING;                 /* Worker está activo. */
    }

    return 0;                                              /* Todos os workers criados com sucesso. */
}

/* ==========================================================================
 * REQUISITO C / E — Processo PAI: recolher resultados dos filhos
 * ========================================================================== */

/* Recolhe os resultados enviados pelos workers. Em modo pipe (Req. C), fecha
 * a extremidade de escrita e lê tudo com collect_from_fd() num único fd.
 * Em modo socket (Req. E), faz accept() para cada worker (N ligações), lê
 * os dados de cada ligação separadamente e fecha-a no fim. Após receber todos
 * os resultados, fecha e remove o socket. Devolve o número de resultados recebidos. */
int phase1_parent_collect_worker_results(const Config *cfg, pid_t *pids,
                                         WorkerResult *results,
                                         WorkerStatus *statuses,
                                         int pipe_rd, int pipe_wr,
                                         int server_fd, bool use_sockets,
                                         double t0)
{
    int received = 0;                                      /* Contador de resultados recebidos. */

    if (use_sockets) {
        for (int i = 0; i < cfg->num_procs; i++) {
            int cli = accept(server_fd, NULL, NULL);       /* Aguarda ligação de um worker. */
            if (cli < 0) {
                if (errno == EINTR) {
                    i--;                                   /* accept() interrompido por sinal: repete. */
                    continue;
                }
                perror("accept");

                for (int j = 0; j < cfg->num_procs; j++)
                    kill(pids[j], SIGKILL);                /* Erro grave: mata todos os workers. */

                close(server_fd);
                unlink(SOCKET_PATH);                       /* Remove o ficheiro do socket. */
                server_fd = -1;
                break;
            }

            received += collect_from_fd(cli, results + received,
                                        cfg->num_procs - received,
                                        statuses, cfg->num_procs,
                                        t0, cfg->verbose);
            /* Lê mensagens desta ligação até ao EOF e acumula em results[]. */
            close(cli);                                    /* Fecha a ligação com este worker. */
        }

        if (server_fd >= 0) {
            close(server_fd);                              /* Fecha o socket de servidor. */
            unlink(SOCKET_PATH);                           /* Remove o ficheiro do socket do sistema. */
        }
    } else {
        close(pipe_wr);                                    /* Pai fecha o lado de escrita do pipe. */
        /* Necessário para que o read() do pai receba EOF quando todos os filhos fecharem. */
        received = collect_from_fd(pipe_rd, results, cfg->num_procs,
                                   statuses, cfg->num_procs, t0, cfg->verbose);
        /* Lê todas as mensagens do pipe até EOF e guarda os resultados. */
        close(pipe_rd);                                    /* Fecha o lado de leitura após terminar. */
    }

    return received;                                       /* Devolve quantos resultados foram recebidos. */
}

/* ==========================================================================
 * REQUISITO B.3 — Processo PAI: aguardar filhos com waitpid()
 * ========================================================================== */

/* Aguarda a terminação de cada processo filho com waitpid(), evitando que
 * fiquem processos zombie no sistema. Após cada filho terminar, marca o seu
 * estado como DONE e a percentagem de progresso como 100% no dashboard. */
void phase1_parent_wait_for_workers(pid_t *pids, WorkerStatus *statuses,
                                    int num_procs)
{
    for (int i = 0; i < num_procs; i++) {
        int status;
        if (waitpid(pids[i], &status, 0) < 0)
            perror("waitpid");                             /* Aguarda que o filho i termine. */
        /* waitpid bloqueia até o processo pids[i] terminar, recolhendo o exit status. */
        /* Sem waitpid, o filho ficaria em estado zombie no sistema. */

        statuses[i].state = STATE_DONE;                    /* Marca o worker como concluído. */
        statuses[i].progress_pct = 100.0f;                 /* Garante 100% no dashboard final. */
    }
}

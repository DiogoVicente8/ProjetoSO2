#define _GNU_SOURCE                               /* Ativa extensões GNU (getenv, useconds_t). */
#include <stdio.h>                                /* perror. */
#include <stdlib.h>                               /* getenv, atol, exit, EXIT_FAILURE. */
#include <string.h>                               /* memset, strncpy, strcmp, strncmp. */
#include <unistd.h>                               /* read, close, usleep, useconds_t. */
#include <fcntl.h>                                /* open, O_RDONLY. */
#include <errno.h>                                /* errno, EINTR. */
#include <ctype.h>                                /* isdigit. */
 
#include "../include/thread_worker.h"             /* ThreadArg, ThreadIPEntry, protótipos. */
#include "../include/log_parser.h"                /* Parsers dos formatos de log. */
#include "../include/event_classifier.h"          /* Classificação de eventos. */
#include "../include/ipc.h"                       /* WorkerResult, TOP_IPS, MAX_IP_LEN. */
#include "../include/files.h"                     /* FileList. */
 
#define DEFAULT_DEMO_DELAY_US 50000               /* Atraso opcional p/ tornar o dashboard visível. */
 
/* ==========================================================================
 * REQUISITO 2-A — Tabela de IPs local à thread (sem partilha)
 *
 * Ao contrário da Fase 1 (que usa processos isolados), aqui várias threads
 * partilham o mesmo espaço de endereçamento. Para evitar contenção de mutex,
 * cada thread mantém a SUA própria tabela de IPs local na stack — não há
 * necessidade de sincronização porque nenhuma outra thread lhe acede.
 * ========================================================================== */
typedef struct {
    ThreadIPEntry e[THREAD_IP_TABLE];             /* Array de entradas (IP + contagem). */
    int           used;                           /* Número de entradas ocupadas. */
} LocalIPTable;
 
/* Lê a variável de ambiente LOG_ANALYZER_SLOW_US para introduzir um atraso
 * artificial. Serve apenas para demonstração: abranda o processamento para
 * que o dashboard em tempo real seja visível mesmo em datasets pequenos. */
static useconds_t demo_delay_us(void)
{
    const char *env = getenv("LOG_ANALYZER_SLOW_US");        /* Lê a variável (NULL se não definida). */
    long delay = env ? atol(env) : DEFAULT_DEMO_DELAY_US;    /* Usa o valor lido ou o default. */
    return delay > 0 ? (useconds_t)delay : 0;                /* Garante valor não-negativo. */
}
 
/* REQUISITO 2-A: adicionar ou incrementar a contagem de um IP na tabela local.
 * Se o IP já existe incrementa a contagem; se não existe e há espaço insere-o. */
static void ip_add(LocalIPTable *t, const char *ip)
{
    if (!ip || !ip[0]) return;                    /* Ignora IP vazio ou NULL. */
    for (int i = 0; i < t->used; i++) {           /* Percorre as entradas já registadas. */
        if (strcmp(t->e[i].ip, ip) == 0) { t->e[i].count++; return; }  /* Já existe: incrementa. */
    }
    if (t->used < THREAD_IP_TABLE) {                          /* Há espaço na tabela? */
        strncpy(t->e[t->used].ip, ip, MAX_IP_LEN - 1);        /* Copia o IP. */
        t->e[t->used].ip[MAX_IP_LEN - 1] = '\0';              /* Terminação nula segura. */
        t->e[t->used].count = 1;                              /* Primeira ocorrência. */
        t->used++;                                            /* Mais uma entrada usada. */
    }
}
 
/* REQUISITO 2-A: encontrar o IP mais frequente (fallback se o top10 estiver vazio). */
static void ip_top(const LocalIPTable *t, char *out_ip, long *out_count)
{
    *out_count = 0;                               /* Inicializa contagem máxima. */
    out_ip[0]  = '\0';                            /* Inicializa IP de saída vazio. */
    for (int i = 0; i < t->used; i++) {           /* Percorre todas as entradas. */
        if (t->e[i].count > *out_count) {         /* Encontrou um IP com mais ocorrências? */
            *out_count = t->e[i].count;           /* Atualiza o máximo. */
            strncpy(out_ip, t->e[i].ip, MAX_IP_LEN - 1);   /* Guarda o IP. */
            out_ip[MAX_IP_LEN - 1] = '\0';        /* Terminação nula. */
        }
    }
}
 
/* REQUISITO 2-A: calcular o top-10 de IPs por seleção repetida do máximo.
 * Marca cada IP já escolhido em used[] para não o repetir na ronda seguinte. */
static void ip_top10(const LocalIPTable *t, WorkerResult *res)
{
    int used[THREAD_IP_TABLE];                    /* Marca quais entradas já entraram no top. */
    memset(used, 0, sizeof(used));                /* Começa tudo a zero (nenhuma escolhida). */
 
    for (int rank = 0; rank < TOP_IPS; rank++) {  /* Para cada posição do top-10... */
        int best = -1;                            /* Índice do melhor candidato desta ronda. */
        for (int i = 0; i < t->used; i++) {       /* Procura o IP mais frequente ainda não usado. */
            if (used[i]) continue;                /* Salta os já colocados no top. */
            if (best < 0 || t->e[i].count > t->e[best].count)
                best = i;                         /* Atualiza o melhor candidato. */
        }
        if (best < 0) break;                      /* Não há mais IPs: termina. */
        used[best] = 1;                           /* Marca este IP como já usado. */
        strncpy(res->top_ips[rank], t->e[best].ip, MAX_IP_LEN - 1);  /* Guarda no resultado. */
        res->top_ips[rank][MAX_IP_LEN - 1] = '\0';                   /* Terminação nula. */
        res->top_ip_counts[rank] = t->e[best].count;                 /* Guarda a contagem. */
    }
    if (res->top_ips[0][0]) {                                /* Se o top-10 tem pelo menos 1 IP... */
        strncpy(res->top_ip, res->top_ips[0], MAX_IP_LEN - 1);  /* ...o top_ip é o primeiro. */
        res->top_ip[MAX_IP_LEN - 1] = '\0';                  /* Terminação nula. */
        res->top_ip_count = res->top_ip_counts[0];           /* Contagem do mais frequente. */
    } else {
        ip_top(t, res->top_ip, &res->top_ip_count);          /* Fallback: cálculo simples. */
    }
}
 
/* ==========================================================================
 * Deteção de formato (idêntica à Fase 1)
 *
 * Examina os primeiros caracteres da linha para inferir o formato do log,
 * permitindo que o mesmo worker processe ficheiros Apache, JSON, Syslog e
 * Nginx misturados.
 * ========================================================================== */
static LogFmt detect_fmt(const char *line)
{
    if (!line || !line[0]) return FMT_UNKNOWN;    /* Linha vazia ou NULL: formato desconhecido. */
    if (line[0] == '{')    return FMT_JSON;       /* Começa com '{': é JSON. */
    if (isdigit((unsigned char)line[0]) && isdigit((unsigned char)line[1]) &&
        isdigit((unsigned char)line[2]) && isdigit((unsigned char)line[3]) &&
        line[4] == '/')                           /* "YYYY/" no início: log de erro Nginx. */
        return FMT_NGINX;
    if (line[0] == '<')    return FMT_SYSLOG;     /* Começa com '<priority>': Syslog. */
    const char *months[] = {"Jan","Feb","Mar","Apr","May","Jun",
                             "Jul","Aug","Sep","Oct","Nov","Dec"};  /* Meses do Syslog sem prioridade. */
    for (int i = 0; i < 12; i++)
        if (strncmp(line, months[i], 3) == 0) return FMT_SYSLOG;    /* Começa com mês: Syslog. */
    if (isdigit((unsigned char)line[0])) return FMT_APACHE;        /* Começa com IP (dígito): Apache. */
    return FMT_UNKNOWN;                           /* Nenhum padrão reconhecido. */
}
 
/* ==========================================================================
 * REQUISITO 2-A — Processar uma linha e atualizar o resultado da thread
 *
 * Faz parse conforme o formato, classifica o evento e (se passar o filtro
 * de modo) incrementa os contadores no WorkerResult desta thread. Como o
 * WorkerResult é privado da thread, não é preciso mutex aqui.
 * ========================================================================== */
static void process_line(const char *line, WorkerResult *res,
                          LocalIPTable *ipt, const Config *cfg)
{
    LogFmt fmt = detect_fmt(line);                /* Deteta o formato da linha. */
    if (fmt == FMT_UNKNOWN) return;               /* Formato desconhecido: ignora. */
 
    ClassifiedEvent ev;                           /* Evento classificado resultante. */
    int types = 0;                                /* Bitmask de tipos de evento. */
 
    switch (fmt) {
        case FMT_APACHE: {                                       /* --- Formato Apache --- */
            ApacheLogEntry e;
            if (parse_apache_log(line, &e) != 0) return;         /* Falha no parse: ignora. */
            types = classify_apache_event(&e, &ev);              /* Classifica. */
            res->lines_parsed++;                                 /* Conta linha parseada. */
            ip_add(ipt, e.ip);                                   /* Regista o IP de origem. */
            if (e.status_code >= 400 && e.status_code < 500) res->errors_4xx++;  /* Erro cliente. */
            if (e.status_code >= 500 && e.status_code < 600) res->errors_5xx++;  /* Erro servidor. */
            break;
        }
        case FMT_JSON: {                                         /* --- Formato JSON --- */
            JSONLogEntry e;
            if (parse_json_log(line, &e) != 0) return;
            types = classify_json_event(&e, &ev);
            res->lines_parsed++;
            ip_add(ipt, e.ip);
            break;
        }
        case FMT_SYSLOG: {                                       /* --- Formato Syslog --- */
            SyslogEntry e;
            if (parse_syslog(line, &e) != 0) return;
            types = classify_syslog_event(&e, &ev);
            res->lines_parsed++;
            break;
        }
        case FMT_NGINX: {                                        /* --- Formato Nginx --- */
            NginxErrorEntry e;
            if (parse_nginx_error(line, &e) != 0) return;
            types = classify_nginx_event(&e, &ev);
            res->lines_parsed++;
            ip_add(ipt, e.client_ip);
            break;
        }
        default: return;                                         /* Caso impossível: ignora. */
    }
 
    if (types == 0) return;                       /* Sem tipo atribuído: ignora. */
    if (!event_matches_mode(&ev, cfg->mode)) return;   /* Não corresponde ao modo pedido: ignora. */
 
    /* Contadores por severidade (0/1=INFO, 2=WARN, 3=ERROR, 4=CRITICAL) */
    switch (ev.severity) {
        case 0: case 1: res->count_info++;     break;   /* INFO / LOW. */
        case 2:         res->count_warn++;     break;   /* MEDIUM. */
        case 3:         res->count_error++;    break;   /* HIGH. */
        default:        res->count_critical++; break;   /* CRITICAL. */
    }
    if (types & EVENT_SECURITY)    res->security_events++;   /* Evento de segurança. */
    if (types & EVENT_PERFORMANCE) res->perf_events++;       /* Evento de performance. */
}
 
/* ==========================================================================
 * REQUISITO 2-A — Processar um ficheiro completo (open/read POSIX, sem fopen)
 *
 * Lê o ficheiro em blocos de 8 KB e reconstrói as linhas manualmente,
 * cumprindo a regra do enunciado de usar apenas syscalls POSIX. Atualiza
 * periodicamente o WorkerStatus partilhado (sob mutex) para o dashboard.
 * ========================================================================== */
static void process_file(const char *path, WorkerResult *res,
                          LocalIPTable *ipt, const Config *cfg,
                          WorkerStatus *status, pthread_mutex_t *status_mutex)
{
    int fd = open(path, O_RDONLY);                /* Abre o ficheiro só para leitura. */
    if (fd < 0) { perror("open"); return; }       /* Erro a abrir: reporta e desiste deste ficheiro. */
 
    char    rbuf[8192];                           /* Buffer de leitura (8 KB). */
    char    line[MAX_LINE_LENGTH];                /* Linha em construção. */
    int     lpos  = 0;                            /* Posição atual na linha. */
    ssize_t nread;                                /* Bytes lidos por read(). */
 
    while (1) {
        nread = read(fd, rbuf, sizeof(rbuf));     /* Lê um bloco. */
        if (nread < 0) {                          /* Erro de leitura... */
            if (errno == EINTR) continue;         /* ...interrompido por sinal: repete. */
            perror("read"); break;                /* ...erro real: reporta e sai. */
        }
        if (nread == 0) {                         /* EOF: fim do ficheiro. */
            if (lpos > 0) {                       /* Há uma linha pendente sem '\n' final? */
                line[lpos] = '\0';                /* Fecha a linha. */
                res->lines_total++;               /* Conta a linha. */
                process_line(line, res, ipt, cfg);    /* Processa-a. */
 
                /* Atualização final do progresso da linha residual no dashboard. */
                if (pthread_mutex_lock(status_mutex) == 0) {     /* Adquire o lock dos statuses. */
                    status->lines_processed = res->lines_total;  /* Publica linhas processadas. */
                    if (status->total_lines > 0)
                        status->progress_pct = (float)res->lines_total / status->total_lines * 100.0f;
                    pthread_mutex_unlock(status_mutex);          /* Liberta o lock. */
                }
            }
            break;                                /* Termina o loop de leitura. */
        }
 
        for (ssize_t i = 0; i < nread; i++) {     /* Percorre os bytes do bloco. */
            char c = rbuf[i];
            if (c == '\n' || c == '\r') {         /* Fim de linha? */
                if (lpos > 0) {                   /* Só processa se a linha não estiver vazia. */
                    line[lpos] = '\0';            /* Fecha a linha. */
                    lpos = 0;                     /* Reinicia para a próxima. */
                    res->lines_total++;           /* Conta a linha. */
                    process_line(line, res, ipt, cfg);    /* Processa-a. */
 
                    /* OTIMIZAÇÃO DE CONTENÇÃO: em vez de bloquear o mutex a cada
                     * linha (o que serializaria as threads e mataria o paralelismo),
                     * só atualizamos o status partilhado a cada 500 linhas. */
                    if (res->lines_total % 500 == 0) {
                        if (pthread_mutex_lock(status_mutex) == 0) {
                            status->lines_processed = res->lines_total;
                            if (status->total_lines > 0)
                                status->progress_pct =
                                    (float)res->lines_total / status->total_lines * 100.0f;
                            pthread_mutex_unlock(status_mutex);
                        }
                        useconds_t delay = demo_delay_us();   /* Atraso opcional de demonstração. */
                        if (delay > 0)
                            usleep(delay);                    /* Abranda para o dashboard ser visível. */
                    }
                }
            } else if (lpos < MAX_LINE_LENGTH - 1) {  /* Caráter normal: acumula na linha. */
                line[lpos++] = c;
            }
        }
    }
 
    close(fd);                                    /* Fecha o ficheiro. */
}
 
/* ==========================================================================
 * REQUISITO 2-A — thread_worker_run: entry point de cada worker thread
 *
 * Função passada a pthread_create(). Processa todos os ficheiros que lhe
 * foram atribuídos pelo assignment[] e escreve as métricas no seu próprio
 * ThreadArg->result. Usa o status_mutex apenas para publicar progresso.
 * ========================================================================== */
void *thread_worker_run(void *arg)
{
    ThreadArg *ta = (ThreadArg *)arg;             /* Converte o argumento genérico. */
 
    memset(&ta->result, 0, sizeof(ta->result));   /* Zera o resultado desta thread. */
    ta->result.pid = (pid_t)ta->thread_id;        /* Usa o thread_id como identificador. */
 
    LocalIPTable ipt;                             /* Tabela de IPs privada da thread. */
    memset(&ipt, 0, sizeof(ipt));                 /* Inicializa-a a zero. */
 
    /* Marca a thread como "a trabalhar" (validando o retorno do mutex). */
    if (pthread_mutex_lock(ta->status_mutex) != 0) {     /* Falha no lock é fatal. */
        perror("pthread_mutex_lock");
        exit(EXIT_FAILURE);
    }
    ta->status->state = STATE_WORKING;            /* Atualiza o estado para o dashboard. */
    pthread_mutex_unlock(ta->status_mutex);
 
    /* Processa todos os ficheiros cujo assignment aponta para esta thread. */
    for (int i = 0; i < ta->fl->count; i++) {
        if (ta->assignment[i] != ta->thread_id) continue;   /* Não é meu: salta. */
        process_file(ta->fl->paths[i], &ta->result, &ipt,
                     ta->cfg, ta->status, ta->status_mutex);
    }
 
    ip_top10(&ipt, &ta->result);                  /* Calcula o top-10 de IPs no fim. */
 
    /* Marca a thread como concluída de forma atómica (sob mutex). */
    if (pthread_mutex_lock(ta->status_mutex) == 0) {
        ta->status->state          = STATE_DONE;          /* Estado final. */
        ta->status->progress_pct   = 100.0f;              /* 100% concluído. */
        ta->status->lines_processed = ta->result.lines_total;  /* Total final. */
        pthread_mutex_unlock(ta->status_mutex);
    }
 
    return NULL;                                  /* pthread espera retorno void*. */
}
#define _GNU_SOURCE                               /* Ativa extensões GNU para getpid() e outros. */
#include <stdio.h>                                /* perror, snprintf. */
#include <stdlib.h>                               /* malloc, free, exit, NULL. */
#include <string.h>                               /* memset, strncpy, strcmp, strstr, strncmp. */
#include <unistd.h>                               /* read, close, getpid. */
#include <fcntl.h>                                /* open, O_RDONLY. */
#include <errno.h>                                /* errno. */
#include <ctype.h>                                /* isdigit, isspace. */
#include <time.h>                                 /* localtime, struct tm, strftime. */

#include "../include/worker.h"                   /* Tipos e protótipos do worker. */
#include "../include/log_parser.h"               /* Parsers dos formatos de log. */
#include "../include/event_classifier.h"         /* Classificação de eventos. */
#include "../include/ipc.h"                      /* writen, comunicação com o pai. */
#include "../include/files.h"                    /* FileList e split_files(). */

/* ==========================================================================
 * REQUISITO B / C — Tabela de IPs (hash simples para top-IP por worker)
 *
 * Cada worker mantém a sua própria IPTable local durante o processamento.
 * No final, o top10 é serializado e enviado ao pai via pipe/socket.
 * ========================================================================== */
#define IP_TABLE 512                              /* Número máximo de IPs distintos na tabela. */

typedef struct { char ip[MAX_IP_LEN]; long count; } IPEntry;   /* Uma entrada: IP + contagem. */
typedef struct { IPEntry e[IP_TABLE]; int used; } IPTable;      /* Tabela com todas as entradas. */

/* REQUISITO B: adicionar ou incrementar a contagem de um IP na tabela local.
 * Se o IP já existe incrementa a contagem; se não existe e há espaço insere-o. */
static void ip_add(IPTable *t, const char *ip)
{
    if (!ip || !ip[0]) return;                 /* Ignora IP vazio ou NULL. */

    for (int i = 0; i < t->used; i++) {        /* Percorre as entradas já registadas. */
        if (strcmp(t->e[i].ip, ip) == 0) {     /* Se encontrar o IP na tabela... */
            t->e[i].count++;                   /* ...incrementa a contagem e termina. */
            return;
        }
    }

    if (t->used < IP_TABLE) {                              /* Verifica se há espaço na tabela. */
        strncpy(t->e[t->used].ip, ip, MAX_IP_LEN - 1);    /* Copia o IP para a nova entrada. */
        t->e[t->used].ip[MAX_IP_LEN - 1] = '\0';          /* Garante terminação nula segura. */
        t->e[t->used].count = 1;                           /* Primeira ocorrência: contagem = 1. */
        t->used++;                                         /* Incrementa o número de entradas usadas. */
    }
}

/* REQUISITO B: encontrar o IP mais frequente da tabela.
 * Usado como fallback se o top10 estiver vazio. */
static void ip_top(const IPTable *t, char *out_ip, long *out_count)
{
    *out_count = 0;                            /* Inicializa contagem máxima a zero. */
    out_ip[0] = '\0';                         /* Inicializa IP de saída como string vazia. */

    for (int i = 0; i < t->used; i++) {        /* Percorre todas as entradas da tabela. */
        if (t->e[i].count > *out_count) {      /* Se esta entrada tem mais ocorrências... */
            *out_count = t->e[i].count;        /* ...actualiza o máximo encontrado. */
            strncpy(out_ip, t->e[i].ip, MAX_IP_LEN - 1);  /* Guarda o IP correspondente. */
            out_ip[MAX_IP_LEN - 1] = '\0';    /* Garante terminação nula. */
        }
    }
}

/* REQUISITO B / C: seleccionar os TOP_IPS mais frequentes da tabela
 * e copiá-los para o WorkerResult (enviado ao pai via pipe/socket). */
static void ip_top10(const IPTable *t, WorkerResult *res)
{
    int used[IP_TABLE];
    memset(used, 0, sizeof(used));             /* Marca quais entradas já foram escolhidas. */

    for (int rank = 0; rank < TOP_IPS; rank++) {   /* Para cada posição do ranking... */
        int best = -1;                             /* Índice da melhor entrada ainda não usada. */
        for (int i = 0; i < t->used; i++) {
            if (used[i]) continue;              /* Ignora entradas já incluídas no ranking. */
            if (best < 0 || t->e[i].count > t->e[best].count)
                best = i;                       /* Actualiza o melhor candidato. */
        }
        if (best < 0) break;                    /* Não há mais IPs para ranquear. */

        used[best] = 1;                         /* Marca esta entrada como já usada. */
        strncpy(res->top_ips[rank], t->e[best].ip, MAX_IP_LEN - 1); /* Copia o IP para o resultado. */
        res->top_ips[rank][MAX_IP_LEN - 1] = '\0';                  /* Garante terminação nula. */
        res->top_ip_counts[rank] = t->e[best].count;                /* Copia a contagem. */
    }

    if (res->top_ips[0][0]) {                                /* Se o top1 foi preenchido... */
        strncpy(res->top_ip, res->top_ips[0], MAX_IP_LEN - 1); /* ...copia-o para top_ip. */
        res->top_ip[MAX_IP_LEN - 1] = '\0';
        res->top_ip_count = res->top_ip_counts[0];           /* Copia a contagem do top1. */
    } else {
        ip_top(t, res->top_ip, &res->top_ip_count); /* Fallback: usa o IP mais frequente global. */
    }
}

/* ==========================================================================
 * REQUISITO D — Envio de progresso em tempo real ao pai
 *
 * O worker envia mensagens PROGRESS a cada 500 linhas processadas.
 * O pai usa estas mensagens para actualizar as barras do dashboard.
 * Protocolo: PROGRESS;PID:<pid>;LINES:<n>\n
 * ========================================================================== */

/* REQUISITO D: envia uma mensagem de progresso ao pai via pipe ou socket.
 * Chamada a cada 500 linhas para que o dashboard mostre percentagem actualizada. */
static void send_progress(int fd, long lines)
{
    if (fd < 0) return;                       /* Se não há canal de comunicação, não envia. */

    char msg[128];                            /* Buffer para construir a mensagem de texto. */
    int len = snprintf(msg, sizeof(msg),
                       "PROGRESS;PID:%d;LINES:%ld\n", (int)getpid(), lines);
    /* Formata: "PROGRESS;PID:<pid>;LINES:<n>\n" com o PID deste worker. */
    if (len > 0 && len < (int)sizeof(msg))
        writen(fd, msg, (size_t)len);         /* Envia a mensagem completa pelo pipe/socket. */
}

/* ==========================================================================
 * REQUISITO B — Detecção de formato do ficheiro de log
 * ========================================================================== */

/* REQUISITO B: deteta automaticamente o formato da linha de log.
 * Suporta Apache Combined, JSON estruturado, Syslog e Nginx Error.
 * Chamada para cada linha antes de escolher o parser correcto. */
LogFmt detect_format(const char *line)
{
    if (!line || !line[0]) return FMT_UNKNOWN; /* Linha vazia ou NULL: formato desconhecido. */
    if (line[0] == '{') return FMT_JSON;       /* JSON começa sempre com '{'. */

    /* Nginx Error Log: começa com "YYYY/MM/DD" — quatro dígitos seguidos de '/'. */
    if (isdigit(line[0]) && isdigit(line[1]) && isdigit(line[2]) &&
        isdigit(line[3]) && line[4] == '/')
        return FMT_NGINX;

    /* Syslog com prioridade: começa com '<' (ex: <34>). */
    if (line[0] == '<') return FMT_SYSLOG;

    /* Syslog sem prioridade: começa com o mês em 3 letras (ex: "Jan", "Feb"). */
    const char *months[] = {"Jan","Feb","Mar","Apr","May","Jun",
                             "Jul","Aug","Sep","Oct","Nov","Dec"};
    for (int i = 0; i < 12; i++)
        if (strncmp(line, months[i], 3) == 0) return FMT_SYSLOG;

    /* Apache Combined Log: começa com o IP do cliente (dígito). */
    if (isdigit(line[0])) return FMT_APACHE;

    return FMT_UNKNOWN;                        /* Nenhum formato reconhecido. */
}

/* ==========================================================================
 * REQUISITO D — Envio de eventos verbose em tempo real
 *
 * Em modo --verbose, cada evento HIGH ou CRITICAL é enviado imediatamente
 * ao pai pelo pipe/socket para impressão em tempo real.
 * Protocolo: VERBOSE;PID:<pid>;TS:<ts>;TYPE:<t>;SEV:<s>;MSG:<m>;IP:<ip>\n
 * ========================================================================== */

/* REQUISITO D: transmite eventos críticos ao pai em tempo real.
 * Só envia eventos com severity >= 3 (HIGH e CRITICAL).
 * O pai imprime-os imediatamente no terminal sem esperar pelo resultado final. */
static void send_verbose(int fd, const ClassifiedEvent *ev,
                          const char *ip, int event_types)
{
    if (fd < 0 || ev->severity < 3) return;    /* Ignora se sem canal ou severidade baixa. */

    char ts[32] = "N/A";                       /* Buffer para o timestamp formatado. */
    struct tm *tm_info = localtime(&ev->timestamp); /* Converte time_t para struct tm local. */
    if (tm_info)
        strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S", tm_info); /* Formata ISO 8601. */

    char msg[640];                             /* Buffer para a mensagem completa. */
    int len = snprintf(msg, sizeof(msg),
        "VERBOSE;PID:%d;TS:%s;TYPE:%s;SEV:%s;MSG:%.300s;IP:%s\n",
        (int)getpid(),                         /* PID deste worker. */
        ts,                                    /* Timestamp do evento. */
        get_event_type_name(event_types),      /* Tipo: SECURITY, PERFORMANCE, etc. */
        get_severity_name(ev->severity),       /* Severidade: HIGH ou CRITICAL. */
        ev->description,                       /* Descrição do evento (truncada a 300 chars). */
        ip ? ip : "N/A");                      /* IP de origem, ou "N/A" se não disponível. */

    if (len > 0 && len < (int)sizeof(msg))
        writen(fd, msg, (size_t)len);           /* Envia a mensagem verbose ao pai. */
}

/* ==========================================================================
 * REQUISITO B — Processar um único ficheiro de log
 *
 * Usa open/read/close (syscalls POSIX) — sem fopen/fread/fwrite.
 * Reconstrói linhas completas a partir de blocos lidos com read().
 * Para cada linha: detecta formato → parseia → classifica → acumula métricas.
 * ========================================================================== */

/* REQUISITO B / C / D: processa um ficheiro de log linha a linha.
 * Envia PROGRESS a cada 500 linhas (Req. D) e VERBOSE para eventos
 * críticos se --verbose (Req. D). Resultado acumulado em *res (Req. C). */
static void process_one_file(const char *path, const Config *cfg,
                              int comm_fd, WorkerResult *res, IPTable *ipt)
{
    int fd = open(path, O_RDONLY);            
    if (fd < 0) { perror("open"); return; }   /* Se falhar, mostra erro e abandona. */

    char read_buf[8192];                      /* Buffer para ler blocos de até 8KB do ficheiro. */
    char line[4096];                          /* Buffer para acumular os bytes de uma linha. */
    int line_pos = 0;                         /* Posição actual de escrita em line[]. */
    ssize_t nread;                            /* Número de bytes devolvidos pelo read(). */

    while (1) {                               /* Loop principal: repete até EOF ou erro. */
        nread = read(fd, read_buf, sizeof(read_buf)); /* Lê até 8KB do ficheiro. */
        if (nread < 0) {
            if (errno == EINTR) continue;      /* Sinal interrompeu o read(): tenta de novo. */
            perror("read");                    /* Outro erro: mostra mensagem e sai. */
            break;
        }
        if (nread == 0) {                      /* EOF: chegou ao fim do ficheiro. */
            if (line_pos > 0) {               /* Se ficou uma linha sem '\n' no fim... */
                line[line_pos] = '\0';        /* ...termina-a manualmente... */
                goto process_line;            /* ...e processa-a antes de sair. */
            }
            break;                            /* Ficheiro completamente lido. */
        }

        for (ssize_t i = 0; i < nread; i++) { /* Itera byte a byte no bloco lido. */
            char c = read_buf[i];             /* Carácter actual do bloco. */
            if (c == '\n' || c == '\r') {     
                if (line_pos > 0) {           /* Se a linha tem conteúdo (não está vazia)... */
                    line[line_pos] = '\0';    /* ...termina a string com '\0'... */
                    line_pos = 0;             /* ...reset do índice para a próxima linha... */
                    goto process_line;        /* ...e vai processar esta linha. */
                }
                continue;                    /* Linha vazia (ex: '\r\n'): ignora e continua. */
            }
            if (line_pos < (int)sizeof(line) - 1)
                line[line_pos++] = c;         /* Acrescenta o carácter à linha em construção. */
            continue;                         /* Volta ao próximo byte do bloco. */

        process_line:;                        /* Label para onde o goto salta quando a linha está pronta. */
            if (!line[0]) continue;           /* Ignora linha completamente vazia. */
            res->lines_total++;               /* Conta mais uma linha lida neste ficheiro. */

            if (!cfg->verbose && comm_fd >= 0 &&
                (res->lines_total % 500 == 0))
                send_progress(comm_fd, res->lines_total); /* Envia PROGRESS a cada 500 linhas. */

            LogFmt fmt = detect_format(line);  /* Detecta o formato desta linha de log. */
            ClassifiedEvent ev;               /* Estrutura para guardar o evento classificado. */
            int types = 0;                    /* Bitmask dos tipos de evento detectados. */
            const char *ip = NULL;            /* Ponteiro para o IP extraído (se existir). */

            switch (fmt) {                    /* Escolhe o parser conforme o formato detectado. */
                case FMT_APACHE: {
                    ApacheLogEntry e;
                    if (parse_apache_log(line, &e) == 0) {    /* Parseia linha Apache. */
                        types = classify_apache_event(&e, &ev); /* Classifica o evento. */
                        res->lines_parsed++;                  /* Conta linha parseada com sucesso. */
                        ip = e.ip;                            /* Guarda o IP do cliente. */
                        ip_add(ipt, e.ip);                    /* Adiciona o IP à tabela local. */
                        if (e.status_code >= 400 && e.status_code < 500)
                            res->errors_4xx++;                /* Incrementa contador de erros 4xx. */
                        if (e.status_code >= 500 && e.status_code < 600)
                            res->errors_5xx++;                /* Incrementa contador de erros 5xx. */
                    }
                    break;
                }
                case FMT_JSON: {
                    JSONLogEntry e;
                    if (parse_json_log(line, &e) == 0) {      /* Parseia linha JSON. */
                        types = classify_json_event(&e, &ev); /* Classifica o evento. */
                        res->lines_parsed++;                  /* Conta linha parseada com sucesso. */
                        ip = e.ip;                            /* Guarda o IP extraído do JSON. */
                        ip_add(ipt, e.ip);                    /* Adiciona à tabela de IPs. */
                    }
                    break;
                }
                case FMT_SYSLOG: {
                    SyslogEntry e;
                    if (parse_syslog(line, &e) == 0) {           /* Parseia linha Syslog. */
                        types = classify_syslog_event(&e, &ev);  /* Classifica o evento. */
                        res->lines_parsed++;                     /* Conta linha parseada. */
                    }
                    break;                    /* Syslog não tem campo IP directo. */
                }
                case FMT_NGINX: {
                    NginxErrorEntry e;
                    if (parse_nginx_error(line, &e) == 0) {      /* Parseia linha Nginx Error. */
                        types = classify_nginx_event(&e, &ev);   /* Classifica o evento. */
                        res->lines_parsed++;                     /* Conta linha parseada. */
                        ip = e.client_ip;                        /* IP do cliente Nginx. */
                        ip_add(ipt, e.client_ip);                /* Adiciona à tabela. */
                    }
                    break;
                }
                default:
                    break;                    /* Formato desconhecido: ignora a linha. */
            }

            if (types == 0) continue;         /* Nenhum tipo de evento detectado: ignora. */

            if (!event_matches_mode(&ev, cfg->mode)) continue;
            /* Evento não corresponde ao modo de análise configurado: ignora. */

            switch (ev.severity) {            /* Classifica por severidade e incrementa contador. */
                case 0: case 1: res->count_info++;     break; /* INFO e LOW. */
                case 2:         res->count_warn++;     break; /* MEDIUM. */
                case 3:         res->count_error++;    break; /* HIGH. */
                default:        res->count_critical++; break; /* CRITICAL. */
            }

            if (types & EVENT_SECURITY)    res->security_events++;   /* Conta evento de segurança. */
            if (types & EVENT_PERFORMANCE) res->perf_events++;        /* Conta evento de performance. */

            if (cfg->verbose && comm_fd >= 0)
                send_verbose(comm_fd, &ev, ip, types); /* Em --verbose, envia evento ao pai. */
        }
    }

    if (!cfg->verbose && comm_fd >= 0)
        send_progress(comm_fd, res->lines_total); /* Envia progresso final deste ficheiro. */

    close(fd);                               /* Fecha o descritor do ficheiro (syscall close). */
}

/* ==========================================================================
 * REQUISITO B — Entry point do worker (processa todos os ficheiros atribuídos)
 *
 * Chamado por run_worker() após o fork(). Determina o intervalo de ficheiros
 * deste worker com split_files() e processa-os sequencialmente.
 * ========================================================================== */

/* REQUISITO B / C: processa os ficheiros atribuídos a este worker e
 * devolve o WorkerResult com as métricas acumuladas ao processo pai. */
WorkerResult process_files(int worker_id, const FileList *fl,
                            const Config *cfg, int comm_fd)
{
    WorkerResult res;
    memset(&res, 0, sizeof(res));            /* Inicializa toda a estrutura de resultados a zero. */
    res.pid = getpid();                      /* Regista o PID deste processo worker. */

    IPTable ipt;
    memset(&ipt, 0, sizeof(ipt));            /* Inicializa a tabela de IPs vazia. */

    int start, end;
    split_files(fl, worker_id, cfg->num_procs, &start, &end);
    /* Calcula o intervalo [start, end[ de ficheiros que pertencem a este worker. */

    for (int i = start; i < end; i++)
        process_one_file(fl->paths[i], cfg, comm_fd, &res, &ipt);
    /* Processa cada ficheiro atribuído sequencialmente, acumulando em res. */

    ip_top10(&ipt, &res);                    /* Calcula os top IPs e copia-os para o resultado. */
    return res;                              /* Devolve o WorkerResult ao chamador (run_worker). */
}

#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/ipc.h"

/* ==========================================================================
 * REQUISITO C — Comunicação pai-filho via pipe anónimo (readn / writen)
 *
 * readn / writen garantem leituras e escritas completas mesmo em caso de
 * writes parciais ou interrupções por sinais (EINTR).
 * ========================================================================== */

/* REQUISITO C: ler exactamente N bytes de um pipe ou socket.
 * Repete read() até obter todos os bytes ou atingir EOF.
 * Trata EINTR transparentemente (sinal interrompeu a syscall).
 * Syscall: read */
ssize_t readn(int fd, void *ptr, size_t n)
{
    size_t  nleft = n;           /* Bytes que ainda faltam ler */
    ssize_t nread;               /* Bytes lidos pela chamada read() */
    char   *p = (char *)ptr;     /* Ponteiro onde os dados vão ser escritos */

    while (nleft > 0) {
        nread = read(fd, p, nleft);       /* Lê do pipe/socket */
        if (nread < 0) {
            if (errno == EINTR) continue; /* Repetir se o read for interrompido por sinal */
            return -1;                    /* Retorna erro em caso de falha real */
        }
        if (nread == 0) break;            /* EOF atingido */
        nleft -= (size_t)nread;           /* Reduz os bytes restantes */
        p     += nread;                   /* Avança o ponteiro de escrita */
    }
    return (ssize_t)(n - nleft);         /* Retorna o total de bytes lidos */
}

/* REQUISITO C: escrever exactamente N bytes num pipe ou socket.
 * Repete write() até enviar todos os bytes (handles writes parciais).
 * Trata EINTR transparentemente.
 * Syscall: write */
ssize_t writen(int fd, const void *ptr, size_t n)
{
    size_t      nleft = n;             /* Bytes que ainda faltam escrever */
    ssize_t     nwritten;              /* Bytes escritos pela chamada write() */
    const char *p = (const char *)ptr;  /* Ponteiro para os dados a enviar */

    while (nleft > 0) {
        nwritten = write(fd, p, nleft); /* Escreve para pipe/socket */
        if (nwritten < 0) {
            if (errno == EINTR) continue; /* Repetir se o write for interrompido */
            return -1;                    /* Erro de escrita */
        }
        nleft -= (size_t)nwritten;       /* Diminuir bytes restantes */
        p     += nwritten;               /* Avança o ponteiro de dados */
    }
    return (ssize_t)n;                    /* Retorna bytes escritos no total */
}

/* ==========================================================================
 * REQUISITO C — Serialização / desserialização do WorkerResult
 *
 * O resultado de cada worker é serializado numa linha de texto terminada
 * em '\n' e enviado ao pai via pipe ou socket.
 *
 * Formato:
 *   RESULT;PID:<n>;LINES:<n>;PARSED:<n>;INFO:<n>;WARN:<n>;ERROR:<n>;
 *   CRIT:<n>;4XX:<n>;5XX:<n>;SEC:<n>;PERF:<n>;TOP_IP:<ip>;TOP_N:<n>
 *   [;IP1:<ip>;IP1_N:<n>;...] (até TOP_IPS entradas)
 * ========================================================================== */

/* REQUISITO C: serializa o WorkerResult numa linha de texto única
 * para envio ao pai pelo pipe ou socket. */
void worker_result_serialize(const WorkerResult *r, char *buf, size_t bufsz)
{
    int len = snprintf(buf, bufsz,
        "RESULT;"
        "PID:%d;"
        "LINES:%ld;"
        "PARSED:%ld;"
        "INFO:%ld;"
        "WARN:%ld;"
        "ERROR:%ld;"
        "CRIT:%ld;"
        "4XX:%ld;"
        "5XX:%ld;"
        "SEC:%ld;"
        "PERF:%ld;"
        "TOP_IP:%s;"
        "TOP_N:%ld",
        (int)r->pid,                    /* PID do worker */
        r->lines_total,                 /* Total de linhas processadas */
        r->lines_parsed,                /* Total de linhas parseadas */
        r->count_info,                  /* Contagem INFO */
        r->count_warn,                  /* Contagem WARN */
        r->count_error,                 /* Contagem ERROR */
        r->count_critical,              /* Contagem CRITICAL */
        r->errors_4xx,                  /* Erros 4xx */
        r->errors_5xx,                  /* Erros 5xx */
        r->security_events,             /* Eventos de segurança */
        r->perf_events,                 /* Eventos de performance */
        r->top_ip[0] ? r->top_ip : "N/A", /* Top IP ou N/A */
        r->top_ip_count);               /* Contagem do top IP */

    /* REQUISITO C: appenda os top IPs ao resultado serializado */
    for (int i = 0; i < TOP_IPS && len > 0 && (size_t)len < bufsz; i++) {
        if (!r->top_ips[i][0]) break;      /* Para no fim dos top IPs */
        len += snprintf(buf + len, bufsz - (size_t)len,
                        ";IP%d:%s;IP%d_N:%ld",
                        i + 1,                   /* Índice do IP */
                        r->top_ips[i],          /* Endereço IP */
                        i + 1,                   /* Índice da contagem */
                        r->top_ip_counts[i]);    /* Contagem do IP */
    }

    if (len > 0 && (size_t)len < bufsz - 1) {
        buf[len++] = '\n';              /* Adiciona nova linha no fim */
        buf[len] = '\0';                /* Termina a string */
    } else if (bufsz > 0) {
        buf[bufsz - 1] = '\0';          /* Garante terminação nula segura */
    }
}

/* --------------------------------------------------------------------------
 * Helpers internos de extracção de campos
 * -------------------------------------------------------------------------- */

/* Extrai um campo long de "KEY:<valor>;" dentro de uma string */
static long extract_long(const char *line, const char *key)
{
    char search[64];
    snprintf(search, sizeof(search), "%s:", key); /* Constroi a chave a procurar */
    const char *p = strstr(line, search);            /* Procura a chave na linha */
    if (!p) return 0;                               /* Retorna 0 se não encontrar */
    p += strlen(search);                            /* Avança para o valor */
    return atol(p);                                 /* Converte texto para long */
}

static void extract_str(const char *line, const char *key,
                         char *out, size_t outsz)
{
    char search[64];
    snprintf(search, sizeof(search), "%s:", key); /* Constroi a chave a procurar */
    const char *p = strstr(line, search);            /* Procura a chave na linha */
    if (!p) { out[0] = '\0'; return; }              /* Se não houver, devolve string vazia */
    p += strlen(search);                             /* Avança para o início do valor */
    size_t i = 0;
    while (*p && *p != ';' && *p != '\n' && i < outsz - 1)
        out[i++] = *p++;                             /* Copia até ao delimitador */
    out[i] = '\0';                                  /* Termina a string extraída */
}

/* REQUISITO C: desserializa a linha RESULT recebida do worker
 * e preenche a estrutura WorkerResult no processo pai. */
int worker_result_parse(const char *line, WorkerResult *r)
{
    if (strncmp(line, "RESULT;", 7) != 0) return -1; /* Verifica prefixo válido */
    memset(r, 0, sizeof(WorkerResult));              /* Inicializa a estrutura */

    r->pid             = (pid_t)extract_long(line, "PID");     /* PID do worker */
    r->lines_total     = extract_long(line, "LINES");          /* Linhas totais */
    r->lines_parsed    = extract_long(line, "PARSED");         /* Linhas parseadas */
    r->count_info      = extract_long(line, "INFO");           /* INFO */
    r->count_warn      = extract_long(line, "WARN");           /* WARN */
    r->count_error     = extract_long(line, "ERROR");          /* ERROR */
    r->count_critical  = extract_long(line, "CRIT");           /* CRITICAL */
    r->errors_4xx      = extract_long(line, "4XX");            /* Erros 4xx */
    r->errors_5xx      = extract_long(line, "5XX");            /* Erros 5xx */
    r->security_events = extract_long(line, "SEC");            /* Eventos de segurança */
    r->perf_events     = extract_long(line, "PERF");           /* Eventos de performance */
    r->top_ip_count    = extract_long(line, "TOP_N");          /* Contagem do top IP */
    extract_str(line, "TOP_IP", r->top_ip, sizeof(r->top_ip)); /* Extrai top IP */

    /* REQUISITO C: desserializar top IPs (até TOP_IPS entradas) */
    for (int i = 0; i < TOP_IPS; i++) {
        char key[16];
        snprintf(key, sizeof(key), "IP%d", i + 1);              /* Chave IPi */
        extract_str(line, key, r->top_ips[i], sizeof(r->top_ips[i]));
        snprintf(key, sizeof(key), "IP%d_N", i + 1);            /* Chave IPi_N */
        r->top_ip_counts[i] = extract_long(line, key);            /* Contagem do IP */
    }
    return 0;                                                   /* Retorna sucesso */
}

/* ==========================================================================
 * REQUISITO C — Agregação global dos WorkerResult no processo pai
 * ========================================================================== */

/* Helper interno: adiciona um IP ao top global, faz merge se já existir
 * e reordena por contagem descendente (bubble sort simples). */
static void global_ip_add(GlobalResult *gr, const char *ip, long count)
{
    if (!ip || !ip[0] || strcmp(ip, "N/A") == 0 || count <= 0) return; /* Ignora valores inválidos */

    /* Se o IP já existe, incrementar a contagem existente */
    for (int i = 0; i < TOP_IPS; i++) {
        if (strcmp(gr->top_ips[i], ip) == 0) {
            gr->top_ip_counts[i] += count; /* Atualiza contagem do IP */
            goto sort;                    /* Ordena o ranking depois */
        }
    }

    /* Se houver espaço vazio, insere o novo IP no ranking */
    for (int i = 0; i < TOP_IPS; i++) {
        if (!gr->top_ips[i][0]) {
            strncpy(gr->top_ips[i], ip, MAX_IP_LEN - 1); /* Copia o IP */
            gr->top_ips[i][MAX_IP_LEN - 1] = '\0';      /* Termina a string */
            gr->top_ip_counts[i] = count;                /* Define a contagem */
            goto sort;                                  /* Ordena após inserção */
        }
    }

    /* Se ranking cheio, substitui o IP de menor contagem se necessário */
    for (int i = 0; i < TOP_IPS; i++) {
        if (count > gr->top_ip_counts[i]) {
            strncpy(gr->top_ips[i], ip, MAX_IP_LEN - 1); /* Substitui IP menos frequente */
            gr->top_ips[i][MAX_IP_LEN - 1] = '\0';
            gr->top_ip_counts[i] = count;                 /* Atualiza a contagem */
            break;
        }
    }

sort:
    /* Reordenar o ranking por contagem descendente */
    for (int i = 0; i < TOP_IPS - 1; i++) {
        for (int j = i + 1; j < TOP_IPS; j++) {
            if (gr->top_ip_counts[j] > gr->top_ip_counts[i]) {
                long c = gr->top_ip_counts[i];
                char ipbuf[MAX_IP_LEN];
                snprintf(ipbuf, sizeof(ipbuf), "%s", gr->top_ips[i]); /* Guarda IP temporário */
                gr->top_ip_counts[i] = gr->top_ip_counts[j];              /* Troca contagens */
                snprintf(gr->top_ips[i], MAX_IP_LEN, "%s", gr->top_ips[j]);
                gr->top_ip_counts[j] = c;                                 /* Move contagem menor */
                snprintf(gr->top_ips[j], MAX_IP_LEN, "%s", ipbuf);       /* Move IP menor */
            }
        }
    }
}

/* REQUISITO C: combina todos os WorkerResult num GlobalResult centralizado.
 * Chamado pelo pai após receber todos os resultados dos workers. */
void aggregate(const WorkerResult *results, int n, GlobalResult *gr)
{
    memset(gr, 0, sizeof(GlobalResult)); /* Inicializa o GlobalResult antes de agregar */
    for (int i = 0; i < n; i++) {
        gr->total_lines    += results[i].lines_total;      /* Adiciona linhas totais do worker */
        gr->total_parsed   += results[i].lines_parsed;     /* Adiciona linhas parseadas */
        gr->total_info     += results[i].count_info;       /* Adiciona INFO */
        gr->total_warn     += results[i].count_warn;       /* Adiciona WARN */
        gr->total_error    += results[i].count_error;      /* Adiciona ERROR */
        gr->total_critical += results[i].count_critical;   /* Adiciona CRITICAL */
        gr->total_4xx      += results[i].errors_4xx;       /* Adiciona erros 4xx */
        gr->total_5xx      += results[i].errors_5xx;       /* Adiciona erros 5xx */
        gr->total_security += results[i].security_events;  /* Adiciona eventos de segurança */
        gr->total_perf     += results[i].perf_events;      /* Adiciona eventos de performance */

        /* REQUISITO C: merge dos top IPs de cada worker no ranking global */
        for (int j = 0; j < TOP_IPS; j++)
            global_ip_add(gr, results[i].top_ips[j], results[i].top_ip_counts[j]);
        if (!results[i].top_ips[0][0]) /* Fallback se top_ips não estiver preenchido */
            global_ip_add(gr, results[i].top_ip, results[i].top_ip_count);
    }
}
// src/event_classifier.c
#define _GNU_SOURCE  
#include "../include/event_classifier.h"
#include <string.h>
#include <strings.h>
#include <stdarg.h> 

/* Helper interno: converte um struct tm (const) para time_t chamando mktime().
 * mktime() exige um ponteiro não-const e pode modificar os campos do tm,
 * por isso copia a estrutura para uma variável local antes de chamar. */
static time_t safe_mktime(const struct tm* tm) {
    struct tm tmp = *tm;
    return mktime(&tmp);
}

/* ==========================================================================
 * REQUISITO B — Classificação de eventos Apache Combined Log
 * ========================================================================== */

/* REQUISITO B: analisa um ApacheLogEntry já parseado e classifica o evento.
 * Detecta: tentativas de acesso não autorizado (401/403), SQL Injection,
 * XSS, path traversal, scanners (Nikto, sqlmap...), respostas grandes e
 * erros de servidor 5xx. Preenche ClassifiedEvent com severity, tipos e
 * descrição. Devolve um bitmask de EVENT_* com os tipos detectados. */
int classify_apache_event(const ApacheLogEntry* entry, ClassifiedEvent* event) {
    if (!entry || !event) return 0;
    
    memset(event, 0, sizeof(ClassifiedEvent));
    event->data.apache = *entry;
    event->timestamp = safe_mktime(&entry->timestamp);
    
    int types = 0;
    event->severity = 0;  // INFO por defeito
    
    // ========== SECURITY ==========
    
    // Status 401/403 - Tentativa de acesso não autorizado
    if (entry->status_code == 401 || entry->status_code == 403) {
        types |= EVENT_SECURITY;
        event->severity = 2;  // MEDIUM
        // Truncar URL se muito grande
        char url_truncated[128];
        strncpy(url_truncated, entry->url, sizeof(url_truncated) - 1);
        url_truncated[sizeof(url_truncated) - 1] = '\0';
        
        snprintf(event->description, sizeof(event->description),
                 "Unauthorized access: %.100s from %.40s", 
                 url_truncated, entry->ip);
    }
    
    // SQL Injection patterns na URL
    if (strcasestr(entry->url, "' OR '") ||
        strcasestr(entry->url, "UNION SELECT") ||
        strcasestr(entry->url, "DROP TABLE") ||
        strcasestr(entry->url, "1=1") ||
        strcasestr(entry->url, "admin'--")) {
        types |= EVENT_SECURITY;
        event->severity = 4;  // CRITICAL
        snprintf(event->description, sizeof(event->description),
                 "SQL Injection attempt: %.220s", entry->url);
    }
    
    // XSS patterns
    if (strcasestr(entry->url, "<script") ||
        strcasestr(entry->url, "javascript:") ||
        strcasestr(entry->url, "onerror=") ||
        strcasestr(entry->url, "onload=")) {
        types |= EVENT_SECURITY;
        event->severity = 3;  // HIGH
        snprintf(event->description, sizeof(event->description),
                 "XSS attempt: %.230s", entry->url);
    }
    
    // Path traversal
    if (strstr(entry->url, "../") || strstr(entry->url, "..\\")) {
        types |= EVENT_SECURITY;
        event->severity = 3;  // HIGH
        snprintf(event->description, sizeof(event->description),
                 "Path traversal: %.228s", entry->url);
    }
    
    // Suspicious user agents (bots, scanners)
    if (strcasestr(entry->user_agent, "nikto") ||
        strcasestr(entry->user_agent, "sqlmap") ||
        strcasestr(entry->user_agent, "nmap") ||
        strcasestr(entry->user_agent, "masscan")) {
        types |= EVENT_SECURITY;
        event->severity = 3;  // HIGH
        snprintf(event->description, sizeof(event->description),
                 "Scanner detected: %.230s", entry->user_agent);
    }
    
    // ========== PERFORMANCE ==========
    
    // Respostas muito grandes (possível DoS ou problema de performance)
    if (entry->response_size > 10 * 1024 * 1024) {  // > 10MB
        types |= EVENT_PERFORMANCE;
        event->severity = 2;  // MEDIUM
        snprintf(event->description, sizeof(event->description),
                 "Large response: %ld bytes for %.180s", 
                 entry->response_size, entry->url);
    }
    
    // Erros 5xx - Problemas de servidor
    if (entry->status_code >= 500 && entry->status_code < 600) {
        types |= EVENT_PERFORMANCE | EVENT_ERROR;
        event->severity = 3;  // HIGH
        snprintf(event->description, sizeof(event->description),
                 "Server error %d: %.230s", entry->status_code, entry->url);
    }
    
    // Status 503 - Service Unavailable (overload)
    if (entry->status_code == 503) {
        types |= EVENT_PERFORMANCE;
        event->severity = 4;  // CRITICAL
        snprintf(event->description, sizeof(event->description),
                 "Service unavailable: possible overload");
    }
    
    // ========== TRAFFIC ==========
    
    // Sempre é tráfego
    types |= EVENT_TRAFFIC;
    
    // 404 - Not Found (análise de tráfego)
    if (entry->status_code == 404) {
        types |= EVENT_TRAFFIC;
        event->severity = 1;  // LOW
        if (event->description[0] == '\0') {
            snprintf(event->description, sizeof(event->description),
                     "Not found: %.240s", entry->url);
        }
    }
    
    // POST/PUT/DELETE - Operações modificadoras
    if (strcmp(entry->method, "POST") == 0 ||
        strcmp(entry->method, "PUT") == 0 ||
        strcmp(entry->method, "DELETE") == 0) {
        types |= EVENT_TRAFFIC;
    }
    
    // Se não tem descrição, criar uma genérica
    if (event->description[0] == '\0') {
        snprintf(event->description, sizeof(event->description),
                 "%.15s %.220s - Status %d", 
                 entry->method, entry->url, entry->status_code);
    }
    
    event->event_types = types;
    return types;
}

/* ==========================================================================
 * REQUISITO B — Classificação de eventos JSON Log
 * ========================================================================== */

/* REQUISITO B: analisa um JSONLogEntry e classifica o evento com base
 * no nível de log (DEBUG/INFO/WARN/ERROR/CRITICAL), no serviço (auth,
 * security, database, api...) e nas palavras-chave da mensagem.
 * Detecta: falhas de autenticação, timeouts, slow queries, rate limiting.
 * Devolve um bitmask de EVENT_* com os tipos detectados. */
int classify_json_event(const JSONLogEntry* entry, ClassifiedEvent* event) {
    if (!entry || !event) return 0;
    
    memset(event, 0, sizeof(ClassifiedEvent));
    event->data.json = *entry;
    event->timestamp = safe_mktime(&entry->timestamp);
    
    int types = 0;
    
    // Mapear log level para severity
    event->severity = entry->level;  // DEBUG=0, INFO=1, WARN=2, ERROR=3, CRITICAL=4
    
    // ========== SECURITY ==========
    
    // Mensagens relacionadas com autenticação/autorização
    if (strcasestr(entry->message, "authentication failed") ||
        strcasestr(entry->message, "invalid credentials") ||
        strcasestr(entry->message, "unauthorized") ||
        strcasestr(entry->message, "access denied") ||
        strcasestr(entry->message, "permission denied")) {
        types |= EVENT_SECURITY;
        event->severity = 3;  // HIGH
    }
    
    // Serviços críticos de segurança
    if (strcasestr(entry->service, "auth") ||
        strcasestr(entry->service, "security") ||
        strcasestr(entry->service, "firewall")) {
        types |= EVENT_SECURITY;
    }
    
    // ========== PERFORMANCE ==========
    
    // Mensagens de performance
    // Corrigir precedência de operadores com parênteses
    if (strcasestr(entry->message, "timeout") ||
        strcasestr(entry->message, "slow query") ||
        strcasestr(entry->message, "high latency") ||
        strcasestr(entry->message, "connection pool exhausted") ||
        strcasestr(entry->message, "out of memory") ||
        strcasestr(entry->message, "cpu") ||
        (strcasestr(entry->message, "took") && strcasestr(entry->message, "ms"))) {
        types |= EVENT_PERFORMANCE;
    }
    
    // Serviços de database/cache (relevantes para performance)
    if (strcasestr(entry->service, "database") ||
        strcasestr(entry->service, "cache") ||
        strcasestr(entry->service, "redis") ||
        strcasestr(entry->service, "postgres") ||
        strcasestr(entry->service, "mysql")) {
        types |= EVENT_PERFORMANCE;
    }
    
    // ========== TRAFFIC ==========
    
    // Logs de APIs são tráfego
    if (strcasestr(entry->service, "api") ||
        strcasestr(entry->service, "gateway") ||
        strcasestr(entry->service, "proxy")) {
        types |= EVENT_TRAFFIC;
    }
    
    // Rate limiting
    if (strcasestr(entry->message, "rate limit") ||
        strcasestr(entry->message, "throttled")) {
        types |= EVENT_TRAFFIC | EVENT_SECURITY;
    }
    
    // ========== ERROR ==========
    
    if (entry->level >= LOG_ERROR) {
        types |= EVENT_ERROR;
    }
    
    // Descrição (truncar para evitar overflow)
    snprintf(event->description, sizeof(event->description),
             "[%.60s] %s: %.160s", entry->service, 
             get_severity_name(entry->level), entry->message);
    
    event->event_types = types;
    return types;
}

/* ==========================================================================
 * REQUISITO B — Classificação de eventos Syslog RFC 3164
 * ========================================================================== */

/* REQUISITO B: analisa um SyslogEntry e classifica o evento.
 * Converte a prioridade Syslog (0=emerg a 7=debug) para a escala interna
 * de severity (0-4). Usa as flags do parser (is_auth_failure, is_sudo_attempt,
 * is_firewall_block) e palavras-chave (Failed password, kernel panic, segfault)
 * para detectar eventos de segurança e erros críticos de sistema.
 * Devolve um bitmask de EVENT_* com os tipos detectados. */
int classify_syslog_event(const SyslogEntry* entry, ClassifiedEvent* event) {
    if (!entry || !event) return 0;
    
    memset(event, 0, sizeof(ClassifiedEvent));
    event->data.syslog = *entry;
    event->timestamp = safe_mktime(&entry->timestamp);
    
    int types = 0;
    
    // Priority para severity
    int severity_level = entry->priority & 0x07;  // Últimos 3 bits
    
    // Mapear syslog severity (0=emerg, 7=debug) para nossa escala (0-4)
    if (severity_level <= 1) event->severity = 4;      // emerg/alert -> CRITICAL
    else if (severity_level <= 3) event->severity = 3; // crit/err -> HIGH
    else if (severity_level <= 4) event->severity = 2; // warning -> MEDIUM
    else if (severity_level <= 6) event->severity = 1; // notice/info -> LOW
    else event->severity = 0;                          // debug -> INFO
    
    // ========== SECURITY ==========
    
    // Flags já detetadas pelo parser
    if (entry->is_auth_failure) {
        types |= EVENT_SECURITY;
        event->severity = 3;  // HIGH
        snprintf(event->description, sizeof(event->description),
                 "Auth failure: %.228s", entry->message);
    }
    
    if (entry->is_sudo_attempt) {
        types |= EVENT_SECURITY;
        // Sudo bem-sucedido ou falhado?
        if (strcasestr(entry->message, "authentication failure") ||
            strcasestr(entry->message, "incorrect password")) {
            event->severity = 4;  // CRITICAL
        }
    }
    
    if (entry->is_firewall_block) {
        types |= EVENT_SECURITY;
        event->severity = 2;  // MEDIUM
    }
    
    // Serviços de segurança
    if (strcasecmp(entry->service, "sshd") == 0 ||
        strcasecmp(entry->service, "sudo") == 0 ||
        strcasecmp(entry->service, "pam") == 0 ||
        strcasestr(entry->service, "firewall") ||
        strcasestr(entry->service, "iptables")) {
        types |= EVENT_SECURITY;
    }
    
    // Múltiplas tentativas falhadas (brute force indicator)
    if (strcasestr(entry->message, "Failed password") ||
        strcasestr(entry->message, "invalid user")) {
        types |= EVENT_SECURITY;
        event->severity = 4;  // CRITICAL
    }
    
    // ========== PERFORMANCE ==========
    
    // Kernel panics, OOM
    if (strcasestr(entry->message, "kernel panic") ||
        strcasestr(entry->message, "out of memory") ||
        strcasestr(entry->message, "OOM")) {
        types |= EVENT_PERFORMANCE | EVENT_ERROR;
        event->severity = 4;  // CRITICAL
    }
    
    // Serviços crashed
    if (strcasestr(entry->message, "segmentation fault") ||
        strcasestr(entry->message, "core dumped") ||
        strcasestr(entry->message, "died") ||
        strcasestr(entry->message, "crashed")) {
        types |= EVENT_PERFORMANCE | EVENT_ERROR;
        event->severity = 4;  // CRITICAL
    }
    
    // ========== TRAFFIC ==========
    
    // Serviços de rede
    if (strcasestr(entry->service, "nginx") ||
        strcasestr(entry->service, "apache") ||
        strcasestr(entry->service, "http")) {
        types |= EVENT_TRAFFIC;
    }
    
    // Conexões
    if (strcasestr(entry->message, "connection") ||
        strcasestr(entry->message, "connect")) {
        types |= EVENT_TRAFFIC;
    }
    
    // Se descrição ainda vazia
    if (event->description[0] == '\0') {
        snprintf(event->description, sizeof(event->description),
                 "%.60s[%d]: %.180s", entry->service, entry->pid, entry->message);
    }
    
    event->event_types = types;
    return types;
}

/* ==========================================================================
 * REQUISITO B — Classificação de eventos Nginx Error Log
 * ========================================================================== */

/* REQUISITO B: analisa um NginxErrorEntry e classifica o evento.
 * Mapeia o nível Nginx (debug/info/notice/warn/error/crit/alert/emerg)
 * para a escala interna de severity. Detecta: acessos negados, erros
 * SSL/TLS, upstream timeouts, rate limiting e respostas demasiado grandes.
 * Todos os eventos Nginx são sempre marcados como EVENT_TRAFFIC.
 * Devolve um bitmask de EVENT_* com os tipos detectados. */
int classify_nginx_event(const NginxErrorEntry* entry, ClassifiedEvent* event) {
    if (!entry || !event) return 0;
    
    memset(event, 0, sizeof(ClassifiedEvent));
    event->data.nginx = *entry;
    event->timestamp = safe_mktime(&entry->timestamp);
    
    int types = 0;
    
    // Mapear nginx level para severity
    if (entry->level == NGINX_EMERG || entry->level == NGINX_ALERT) {
        event->severity = 4;  // CRITICAL
    } else if (entry->level == NGINX_CRIT || entry->level == NGINX_ERROR) {
        event->severity = 3;  // HIGH
    } else if (entry->level == NGINX_WARN) {
        event->severity = 2;  // MEDIUM
    } else if (entry->level == NGINX_NOTICE || entry->level == NGINX_INFO) {
        event->severity = 1;  // LOW
    } else {
        event->severity = 0;  // INFO
    }
    
    // ========== SECURITY ==========
    
    // Client access errors
    if (strcasestr(entry->message, "access forbidden") ||
        strcasestr(entry->message, "denied") ||
        strcasestr(entry->message, "not allowed")) {
        types |= EVENT_SECURITY;
        event->severity = 2;  // MEDIUM
    }
    
    // SSL/TLS errors
    if (strcasestr(entry->message, "SSL") ||
        strcasestr(entry->message, "certificate")) {
        types |= EVENT_SECURITY;
    }
    
    // ========== PERFORMANCE ==========
    
    // Connection/upstream errors (problemas de performance)
    if (strcasestr(entry->message, "upstream timed out") ||
        strcasestr(entry->message, "connection refused") ||
        strcasestr(entry->message, "connection reset") ||
        strcasestr(entry->message, "no live upstreams")) {
        types |= EVENT_PERFORMANCE;
        event->severity = 3;  // HIGH
    }
    
    // Rate limiting
    if (strcasestr(entry->message, "limiting requests")) {
        types |= EVENT_PERFORMANCE | EVENT_TRAFFIC;
        event->severity = 2;  // MEDIUM
    }
    
    // Body too large
    if (strcasestr(entry->message, "too large")) {
        types |= EVENT_PERFORMANCE | EVENT_TRAFFIC;
    }
    
    // ========== TRAFFIC ==========
    
    // Todos os erros nginx são relevantes para tráfego
    types |= EVENT_TRAFFIC;
    
    // Descrição (truncar para evitar overflow)
    snprintf(event->description, sizeof(event->description),
             "Nginx [%s]: %.180s (%.40s)", 
             get_severity_name(event->severity),
             entry->message, entry->client_ip);
    
    event->event_types = types;
    return types;
}

/* ==========================================================================
 * REQUISITO B — Funções auxiliares de consulta
 * ========================================================================== */

/* REQUISITO B: verifica se um evento classificado deve ser contabilizado
 * no modo de análise configurado pelo utilizador (security, performance,
 * traffic ou full). Em modo full todos os eventos passam; nos outros
 * modos filtra pelo bitmask de event_types do ClassifiedEvent. */
bool event_matches_mode(const ClassifiedEvent* event, AnalysisMode mode) {
    if (mode == MODE_FULL) return true;
    return (event->event_types & mode) != 0;
}

/* REQUISITO B: converte um bitmask de tipos de evento (EVENT_SECURITY,
 * EVENT_PERFORMANCE, EVENT_TRAFFIC, EVENT_ERROR, EVENT_NORMAL) numa
 * string legível com os nomes separados por espaço. Usado pelo worker
 * ao formatar mensagens VERBOSE enviadas ao pai pelo pipe/socket. */
const char* get_event_type_name(int event_type) {
    static char buffer[128];
    buffer[0] = '\0';
    
    if (event_type & EVENT_SECURITY) strcat(buffer, "SECURITY ");
    if (event_type & EVENT_PERFORMANCE) strcat(buffer, "PERFORMANCE ");
    if (event_type & EVENT_TRAFFIC) strcat(buffer, "TRAFFIC ");
    if (event_type & EVENT_ERROR) strcat(buffer, "ERROR ");
    if (event_type & EVENT_NORMAL) strcat(buffer, "NORMAL ");
    
    // Remover último espaço
    size_t len = strlen(buffer);
    if (len > 0 && buffer[len-1] == ' ') {
        buffer[len-1] = '\0';
    }
    
    return buffer;
}

/* REQUISITO B: converte o valor numérico de severity (0-4) para a string
 * correspondente (INFO, LOW, MEDIUM, HIGH, CRITICAL). Usado nas mensagens
 * VERBOSE e no relatório final para tornar os níveis legíveis. */
const char* get_severity_name(int severity) {
    switch (severity) {
        case 0: return "INFO";
        case 1: return "LOW";
        case 2: return "MEDIUM";
        case 3: return "HIGH";
        case 4: return "CRITICAL";
        default: return "UNKNOWN";
    }
}

// src/log_parser_simple.c - Versão sem regex (mais portável)
#include "log_parser.h"
#include <ctype.h>

// ============================================================================
// PARSER: Apache Combined Log (SEM REGEX)
// ============================================================================

int parse_apache_log(const char* line, ApacheLogEntry* entry) {
    if (!line || !entry) return -1;
    
    // Limpar estrutura
    memset(entry, 0, sizeof(ApacheLogEntry));
    
    const char* ptr = line;
    
    // 1. Extrair IP (até o primeiro espaço)
    int i = 0;
    while (*ptr && *ptr != ' ' && i < MAX_IP_LENGTH - 1) {
        entry->ip[i++] = *ptr++;
    }
    entry->ip[i] = '\0';
    
    if (*ptr != ' ') return -1;
    
    // 2. Skip " - - "
    while (*ptr == ' ') ptr++;
    if (*ptr == '-') ptr++;
    while (*ptr == ' ') ptr++;
    if (*ptr == '-') ptr++;
    while (*ptr == ' ') ptr++;
    
    // 3. Extrair timestamp [13/Feb/2024:10:23:45 +0000]
    if (*ptr != '[') return -1;
    ptr++; // Skip '['
    
    char timestamp_str[64];
    i = 0;
    while (*ptr && *ptr != ']' && i < 63) {
        timestamp_str[i++] = *ptr++;
    }
    timestamp_str[i] = '\0';
    
    if (*ptr != ']') return -1;
    ptr++; // Skip ']'
    
    // Parse timestamp
    parse_apache_timestamp(timestamp_str, &entry->timestamp);
    
    // 4. Skip espaços até primeira aspas
    while (*ptr == ' ') ptr++;
    
    // 5. Extrair método, URL e versão HTTP "GET /api/users HTTP/1.1"
    if (*ptr != '"') return -1;
    ptr++; // Skip '"'
    
    // Método (GET, POST, etc.)
    i = 0;
    while (*ptr && *ptr != ' ' && i < 15) {
        entry->method[i++] = *ptr++;
    }
    entry->method[i] = '\0';
    
    while (*ptr == ' ') ptr++;
    
    // URL
    i = 0;
    while (*ptr && *ptr != ' ' && *ptr != '"' && i < MAX_URL_LENGTH - 1) {
        entry->url[i++] = *ptr++;
    }
    entry->url[i] = '\0';
    
    while (*ptr == ' ') ptr++;
    
    // HTTP Version (HTTP/1.1)
    if (strncmp(ptr, "HTTP/", 5) == 0) {
        ptr += 5;
        i = 0;
        while (*ptr && *ptr != '"' && i < 15) {
            entry->http_version[i++] = *ptr++;
        }
        entry->http_version[i] = '\0';
    }
    
    // Skip até próximas aspas
    while (*ptr && *ptr != '"') ptr++;
    if (*ptr == '"') ptr++;
    
    // 6. Extrair status code
    while (*ptr == ' ') ptr++;
    entry->status_code = atoi(ptr);
    
    // Skip dígitos do status
    while (*ptr && isdigit(*ptr)) ptr++;
    
    // 7. Extrair response size
    while (*ptr == ' ') ptr++;
    entry->response_size = atol(ptr);

    while (*ptr && *ptr != ' ') ptr++;
    while (*ptr == ' ') ptr++;

    // 8. Extrair referer "https://example.com" ou "-"
    if (*ptr == '"') {
        ptr++;
        i = 0;
        while (*ptr && *ptr != '"' && i < MAX_URL_LENGTH - 1)
            entry->referer[i++] = *ptr++;
        entry->referer[i] = '\0';
        if (*ptr == '"') ptr++;
    }

    while (*ptr == ' ') ptr++;

    // 9. Extrair user-agent "Mozilla/5.0 ..."
    if (*ptr == '"') {
        ptr++;
        i = 0;
        while (*ptr && *ptr != '"' && i < (int)sizeof(entry->user_agent) - 1)
            entry->user_agent[i++] = *ptr++;
        entry->user_agent[i] = '\0';
    }
    
    return 0;
}

// ============================================================================
// PARSER: JSON Log (simplificado)
// ============================================================================

static char* extract_json_value(const char* json, const char* key, char* value, size_t max_len) {
    char search_key[128];
    snprintf(search_key, sizeof(search_key), "\"%s\":", key);
    
    const char* pos = strstr(json, search_key);
    if (!pos) return NULL;
    
    pos += strlen(search_key);
    while (*pos && isspace(*pos)) pos++;
    
    if (*pos == '"') {
        pos++;
        const char* end = strchr(pos, '"');
        if (!end) return NULL;
        
        size_t len = end - pos;
        if (len >= max_len) len = max_len - 1;
        strncpy(value, pos, len);
        value[len] = '\0';
    } else {
        const char* end = pos;
        while (*end && *end != ',' && *end != '}' && *end != '\n') end++;
        
        size_t len = end - pos;
        if (len >= max_len) len = max_len - 1;
        strncpy(value, pos, len);
        value[len] = '\0';
    }
    
    return value;
}

int parse_json_log(const char* line, JSONLogEntry* entry) {
    if (!line || !entry) return -1;
    
    memset(entry, 0, sizeof(JSONLogEntry));
    
    char value[MAX_MSG_LENGTH];
    
    if (extract_json_value(line, "timestamp", value, sizeof(value))) {
        parse_iso8601_timestamp(value, &entry->timestamp);
    }
    
    if (extract_json_value(line, "level", value, sizeof(value))) {
        if (strcmp(value, "DEBUG") == 0) entry->level = LOG_DEBUG;
        else if (strcmp(value, "INFO") == 0) entry->level = LOG_INFO;
        else if (strcmp(value, "WARN") == 0 || strcmp(value, "WARNING") == 0) 
            entry->level = LOG_WARN;
        else if (strcmp(value, "ERROR") == 0) entry->level = LOG_ERROR;
        else if (strcmp(value, "CRITICAL") == 0 || strcmp(value, "FATAL") == 0) 
            entry->level = LOG_CRITICAL;
    }
    
    if (extract_json_value(line, "service", value, sizeof(value))) {
    strncpy(entry->service, value, sizeof(entry->service) - 1);
    entry->service[sizeof(entry->service) - 1] = '\0';  // Garantir null terminator
    }
    
    if (extract_json_value(line, "message", value, sizeof(value))) {
    strncpy(entry->message, value, sizeof(entry->message) - 1);
    entry->message[sizeof(entry->message) - 1] = '\0';  // Garantir null terminator
    }
    
    const char* metadata = strstr(line, "\"metadata\"");
    if (metadata) {
        if (extract_json_value(metadata, "ip", value, sizeof(value))) {
    	strncpy(entry->ip, value, sizeof(entry->ip) - 1);
    	entry->ip[sizeof(entry->ip) - 1] = '\0';  // Garantir null terminator
    }
        
        if (extract_json_value(metadata, "user_id", value, sizeof(value))) {
            entry->user_id = atoi(value);
        }
    }
    
    return 0;
}

// ============================================================================
// PARSER: Syslog
// ============================================================================

int parse_syslog(const char* line, SyslogEntry* entry) {
    if (!line || !entry) return -1;
    
    memset(entry, 0, sizeof(SyslogEntry));
    
    const char* ptr = line;
    
    // Parse priority <nnn>
    if (*ptr == '<') {
        ptr++;
        entry->priority = atoi(ptr);
        while (*ptr && *ptr != '>') ptr++;
        if (*ptr == '>') ptr++;
    }
    
    // Parse timestamp (formato syslog: "Feb 13 10:23:45")
    char timestamp_str[32];
    int i = 0;
    
    // Mês (3 letras)
    while (*ptr && i < 3 && isalpha(*ptr)) {
        timestamp_str[i++] = *ptr++;
    }
    timestamp_str[i++] = ' ';
    
    while (*ptr == ' ') ptr++;
    
    // Dia
    while (*ptr && isdigit(*ptr) && i < 31) {
        timestamp_str[i++] = *ptr++;
    }
    timestamp_str[i++] = ' ';
    
    while (*ptr == ' ') ptr++;
    
    // Hora HH:MM:SS
    int colon_count = 0;
    while (*ptr && colon_count < 2 && i < 31) {
        timestamp_str[i++] = *ptr;
        if (*ptr == ':') colon_count++;
        ptr++;
    }
    // Pegar segundos
    while (*ptr && isdigit(*ptr) && i < 31) {
        timestamp_str[i++] = *ptr++;
    }
    timestamp_str[i] = '\0';
    
    parse_syslog_timestamp(timestamp_str, &entry->timestamp);
    
    while (*ptr && isspace(*ptr)) ptr++;
    
    // Parse hostname
    i = 0;
    while (*ptr && *ptr != ' ' && i < 255) {
        entry->hostname[i++] = *ptr++;
    }
    entry->hostname[i] = '\0';
    
    while (*ptr && isspace(*ptr)) ptr++;
    
    // Parse service[pid]:
    i = 0;
    while (*ptr && *ptr != '[' && *ptr != ':' && i < 63) {
        entry->service[i++] = *ptr++;
    }
    entry->service[i] = '\0';
    
    // Parse PID se existir
    if (*ptr == '[') {
        ptr++;
        entry->pid = atoi(ptr);
        while (*ptr && *ptr != ']') ptr++;
        if (*ptr == ']') ptr++;
    }
    
    // Skip ':' e whitespace
    if (*ptr == ':') ptr++;
    while (*ptr && isspace(*ptr)) ptr++;
    
    // Resto é a mensagem
    strncpy(entry->message, ptr, sizeof(entry->message) - 1);
    
    // Análise de segurança
    entry->is_auth_failure = (strstr(entry->message, "authentication failure") != NULL ||
                               strstr(entry->message, "Failed password") != NULL ||
                               strstr(entry->message, "invalid user") != NULL);
    
    entry->is_sudo_attempt = (strstr(entry->service, "sudo") != NULL);
    
    entry->is_firewall_block = (strstr(entry->message, "REJECT") != NULL ||
                                 strstr(entry->message, "DROP") != NULL);
    
    return 0;
}

// ============================================================================
// PARSER: Nginx Error Log
// ============================================================================

int parse_nginx_error(const char* line, NginxErrorEntry* entry) {
    if (!line || !entry) return -1;
    
    memset(entry, 0, sizeof(NginxErrorEntry));
    
    // Parse timestamp: "YYYY/MM/DD HH:MM:SS"
    struct tm tm = {0};
    if (sscanf(line, "%d/%d/%d %d:%d:%d", 
               &tm.tm_year, &tm.tm_mon, &tm.tm_mday,
               &tm.tm_hour, &tm.tm_min, &tm.tm_sec) == 6) {
        tm.tm_year -= 1900;
        tm.tm_mon -= 1;
        entry->timestamp = tm;
    }
    
    // Parse level: [error], [warn], etc.
    const char* level_start = strchr(line, '[');
    if (level_start) {
        level_start++;
        if (strncmp(level_start, "debug", 5) == 0) entry->level = NGINX_DEBUG;
        else if (strncmp(level_start, "info", 4) == 0) entry->level = NGINX_INFO;
        else if (strncmp(level_start, "notice", 6) == 0) entry->level = NGINX_NOTICE;
        else if (strncmp(level_start, "warn", 4) == 0) entry->level = NGINX_WARN;
        else if (strncmp(level_start, "error", 5) == 0) entry->level = NGINX_ERROR;
        else if (strncmp(level_start, "crit", 4) == 0) entry->level = NGINX_CRIT;
        else if (strncmp(level_start, "alert", 5) == 0) entry->level = NGINX_ALERT;
        else if (strncmp(level_start, "emerg", 5) == 0) entry->level = NGINX_EMERG;
    }
    
    // Parse PID#TID
    const char* pid_start = strchr(line, ']');
    if (pid_start) {
        pid_start += 2;
        sscanf(pid_start, "%d#%d", &entry->pid, &entry->tid);
    }
    
    // Parse connection ID: *1234
    const char* conn_start = strchr(line, '*');
    if (conn_start) {
        entry->connection_id = atol(conn_start + 1);
    }
    
    // Parse client IP
    const char* client_start = strstr(line, "client: ");
    if (client_start) {
        client_start += 8;
        int i = 0;
        while (*client_start && *client_start != ',' && *client_start != ' ' && i < MAX_IP_LENGTH - 1) {
            entry->client_ip[i++] = *client_start++;
        }
        entry->client_ip[i] = '\0';
    }
    
    // Parse message
    const char* msg_start = strchr(pid_start, ':');
    if (msg_start) {
        msg_start += 2;
        const char* msg_end = strstr(msg_start, ", client:");
        if (!msg_end) msg_end = msg_start + strlen(msg_start);
        
        size_t len = msg_end - msg_start;
        if (len >= sizeof(entry->message)) len = sizeof(entry->message) - 1;
        strncpy(entry->message, msg_start, len);
        entry->message[len] = '\0';
    }
    
    return 0;
}

// ============================================================================
// Funções auxiliares de timestamp (mantêm-se iguais)
// ============================================================================

int parse_apache_timestamp(const char* timestamp_str, struct tm* tm_out) {
    char month_str[4];
    int day, year, hour, min, sec;
    
    if (sscanf(timestamp_str, "%d/%3s/%d:%d:%d:%d", 
               &day, month_str, &year, &hour, &min, &sec) != 6) {
        return -1;
    }
    
    const char* months[] = {"Jan","Feb","Mar","Apr","May","Jun",
                            "Jul","Aug","Sep","Oct","Nov","Dec"};
    int month = -1;
    for (int i = 0; i < 12; i++) {
        if (strcmp(month_str, months[i]) == 0) {
            month = i;
            break;
        }
    }
    
    if (month == -1) return -1;
    
    tm_out->tm_mday = day;
    tm_out->tm_mon = month;
    tm_out->tm_year = year - 1900;
    tm_out->tm_hour = hour;
    tm_out->tm_min = min;
    tm_out->tm_sec = sec;
    
    return 0;
}

int parse_iso8601_timestamp(const char* timestamp_str, struct tm* tm_out) {
    int year, month, day, hour, min, sec;
    
    if (sscanf(timestamp_str, "%d-%d-%dT%d:%d:%d", 
               &year, &month, &day, &hour, &min, &sec) != 6) {
        return -1;
    }
    
    tm_out->tm_year = year - 1900;
    tm_out->tm_mon = month - 1;
    tm_out->tm_mday = day;
    tm_out->tm_hour = hour;
    tm_out->tm_min = min;
    tm_out->tm_sec = sec;
    
    return 0;
}

int parse_syslog_timestamp(const char* timestamp_str, struct tm* tm_out) {
    char month_str[4];
    int day, hour, min, sec;
    
    if (sscanf(timestamp_str, "%3s %d %d:%d:%d", 
               month_str, &day, &hour, &min, &sec) != 5) {
        return -1;
    }
    
    const char* months[] = {"Jan","Feb","Mar","Apr","May","Jun",
                            "Jul","Aug","Sep","Oct","Nov","Dec"};
    int month = -1;
    for (int i = 0; i < 12; i++) {
        if (strcmp(month_str, months[i]) == 0) {
            month = i;
            break;
        }
    }
    
    if (month == -1) return -1;
    
    time_t now = time(NULL);
    struct tm* now_tm = localtime(&now);
    
    tm_out->tm_year = now_tm->tm_year;
    tm_out->tm_mon = month;
    tm_out->tm_mday = day;
    tm_out->tm_hour = hour;
    tm_out->tm_min = min;
    tm_out->tm_sec = sec;
    
    return 0;
}

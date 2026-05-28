#ifndef LOG_PARSER_H
#define LOG_PARSER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <stdbool.h>

#define MAX_LINE_LENGTH 4096
#define MAX_IP_LENGTH 46
#define MAX_URL_LENGTH 512
#define MAX_MSG_LENGTH 1024

typedef struct {
    char ip[MAX_IP_LENGTH];
    struct tm timestamp;
    char method[16];
    char url[MAX_URL_LENGTH];
    char http_version[16];
    int status_code;
    long response_size;
    char referer[MAX_URL_LENGTH];
    char user_agent[256];
} ApacheLogEntry;

typedef struct {
    struct tm timestamp;
    enum {
        LOG_DEBUG = 0,
        LOG_INFO = 1,
        LOG_WARN = 2,
        LOG_ERROR = 3,
        LOG_CRITICAL = 4
    } level;
    char service[64];
    char message[MAX_MSG_LENGTH];
    char ip[MAX_IP_LENGTH];
    int user_id;
} JSONLogEntry;

typedef struct {
    int priority;
    struct tm timestamp;
    char hostname[256];
    char service[64];
    int pid;
    char message[MAX_MSG_LENGTH];
    bool is_auth_failure;
    bool is_sudo_attempt;
    bool is_firewall_block;
} SyslogEntry;

typedef struct {
    struct tm timestamp;
    enum {
        NGINX_DEBUG = 0,
        NGINX_INFO = 1,
        NGINX_NOTICE = 2,
        NGINX_WARN = 3,
        NGINX_ERROR = 4,
        NGINX_CRIT = 5,
        NGINX_ALERT = 6,
        NGINX_EMERG = 7
    } level;
    int pid;
    int tid;
    long connection_id;
    char message[MAX_MSG_LENGTH];
    char client_ip[MAX_IP_LENGTH];
    char server[256];
    char request[MAX_URL_LENGTH];
} NginxErrorEntry;

int parse_apache_log(const char* line, ApacheLogEntry* entry);
int parse_json_log(const char* line, JSONLogEntry* entry);
int parse_syslog(const char* line, SyslogEntry* entry);
int parse_nginx_error(const char* line, NginxErrorEntry* entry);

int parse_apache_timestamp(const char* timestamp_str, struct tm* tm_out);
int parse_iso8601_timestamp(const char* timestamp_str, struct tm* tm_out);
int parse_syslog_timestamp(const char* timestamp_str, struct tm* tm_out);

#endif

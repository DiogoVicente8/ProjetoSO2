// src/event_classifier.h
#ifndef EVENT_CLASSIFIER_H
#define EVENT_CLASSIFIER_H

#include "log_parser.h"
#include <stdbool.h>

// ============================================================================
// TIPOS DE EVENTOS
// ============================================================================

typedef enum {
    EVENT_SECURITY = 1 << 0,      // 0001 - Eventos de segurança
    EVENT_PERFORMANCE = 1 << 1,   // 0010 - Eventos de performance
    EVENT_TRAFFIC = 1 << 2,       // 0100 - Eventos de tráfego
    EVENT_ERROR = 1 << 3,         // 1000 - Eventos de erro
    EVENT_NORMAL = 1 << 4         // Normal operation
} EventType;

// Modo de análise (pode combinar com OR bitwise)
typedef enum {
    MODE_SECURITY = EVENT_SECURITY,
    MODE_PERFORMANCE = EVENT_PERFORMANCE,
    MODE_TRAFFIC = EVENT_TRAFFIC,
    MODE_FULL = EVENT_SECURITY | EVENT_PERFORMANCE | EVENT_TRAFFIC | EVENT_ERROR
} AnalysisMode;

// ============================================================================
// ESTRUTURAS DE EVENTOS CLASSIFICADOS
// ============================================================================

typedef struct {
    // Tipo de evento (pode ter múltiplas flags)
    int event_types;  // Bitmask de EventType
    
    // Severity (0=INFO, 1=LOW, 2=MEDIUM, 3=HIGH, 4=CRITICAL)
    int severity;
    
    // Descrição do evento
    char description[256];
    
    // Dados originais
    union {
        ApacheLogEntry apache;
        JSONLogEntry json;
        SyslogEntry syslog;
        NginxErrorEntry nginx;
    } data;
    
    // Timestamp normalizado (para ordenação)
    time_t timestamp;
    
} ClassifiedEvent;

// ============================================================================
// FUNÇÕES DE CLASSIFICAÇÃO
// ============================================================================

/**
 * Classifica evento Apache
 * Retorna: bitmask de EventType
 */
int classify_apache_event(const ApacheLogEntry* entry, ClassifiedEvent* event);

/**
 * Classifica evento JSON
 */
int classify_json_event(const JSONLogEntry* entry, ClassifiedEvent* event);

/**
 * Classifica evento Syslog
 */
int classify_syslog_event(const SyslogEntry* entry, ClassifiedEvent* event);

/**
 * Classifica evento Nginx
 */
int classify_nginx_event(const NginxErrorEntry* entry, ClassifiedEvent* event);

/**
 * Verifica se evento corresponde ao modo de análise
 */
bool event_matches_mode(const ClassifiedEvent* event, AnalysisMode mode);

/**
 * Obtém nome do tipo de evento
 */
const char* get_event_type_name(int event_type);

/**
 * Obtém nome da severidade
 */
const char* get_severity_name(int severity);

#endif // EVENT_CLASSIFIER_H

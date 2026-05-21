/**
 * Gerador de syslog com eventos de segurança realistas
 * Compila: gcc -O2 generate_syslog.c -o gen_syslog
 * Uso: ./gen_syslog 5000000 > syslog_security.log
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static const char* hostnames[] = {
    "web-server-01", "web-server-02", "db-primary", "db-replica",
    "firewall", "gateway", "backup-server"
};
#define HOST_COUNT (sizeof(hostnames) / sizeof(hostnames[0]))

typedef struct {
    const char* service;
    const char* message_template;
    int priority;
    int weight;
} LogTemplate;

static LogTemplate templates[] = {
    // SSH normal
    {"sshd", "Accepted publickey for admin from %s port %d ssh2", 38, 50},
    {"sshd", "pam_unix(sshd:session): session opened for user admin", 38, 30},
    
    // SSH ataques (CRÍTICO)
    {"sshd", "Failed password for root from %s port %d ssh2", 38, 15},
    {"sshd", "Failed password for invalid user admin from %s port %d", 38, 12},
    {"sshd", "Connection closed by %s port %d [preauth]", 38, 10},
    
    // Sudo
    {"sudo", "admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/ls", 44, 20},
    {"sudo", "pam_unix(sudo:auth): authentication failure; user=hacker", 44, 8},
    
    // Firewall
    {"kernel", "iptables: IN=eth0 OUT= SRC=%s DST=10.0.0.1 PROTO=TCP DPT=22 REJECT", 36, 18},
    {"kernel", "iptables: IN=eth0 OUT= SRC=%s DST=10.0.0.1 PROTO=TCP DPT=3389 DROP", 36, 10},
    
    // Sistema
    {"systemd", "Started User Manager for UID 1000", 46, 25},
    {"cron", "pam_unix(cron:session): session opened for user root", 46, 15},
    
    // Serviços web
    {"nginx", "limiting requests, excess: 5.123 by zone \"req_limit_per_ip\"", 38, 12},
    {"apache2", "client denied by server configuration", 38, 8},
};
#define TEMPLATE_COUNT (sizeof(templates) / sizeof(templates[0]))

// IPs de atacantes conhecidos (para simular tentativas de invasão)
static const char* attacker_ips[] = {
    "203.0.113.45", "198.51.100.88", "93.184.216.199",
    "185.220.100.240", "45.33.32.156"
};
#define ATTACKER_COUNT (sizeof(attacker_ips) / sizeof(attacker_ips[0]))

int weighted_random(int count) {
    int total = 0;
    for (int i = 0; i < count; i++) total += templates[i].weight;
    
    int r = rand() % total;
    int sum = 0;
    for (int i = 0; i < count; i++) {
        sum += templates[i].weight;
        if (r < sum) return i;
    }
    return 0;
}

void generate_syslog_entry(time_t timestamp) {
    struct tm* tm = localtime(&timestamp);
    char time_str[32];
    strftime(time_str, sizeof(time_str), "%b %d %H:%M:%S", tm);
    
    const char* hostname = hostnames[rand() % HOST_COUNT];
    
    int tmpl_idx = weighted_random(TEMPLATE_COUNT);
    LogTemplate* tmpl = &templates[tmpl_idx];
    
    char message[512];
    
    // Se mensagem contém %s (IP), inserir IP
    if (strstr(tmpl->message_template, "%s")) {
        const char* ip;
        // 20% das tentativas SSH falhadas vêm de IPs atacantes conhecidos
        // CORREÇÃO: verificar message_template em vez de message
        if (strstr(tmpl->message_template, "Failed") && rand() % 100 < 20) {
            ip = attacker_ips[rand() % ATTACKER_COUNT];
        } else {
            static char random_ip[20];  // Aumentar buffer
	    snprintf(random_ip, sizeof(random_ip), "192.168.%d.%d",
         rand() % 256, rand() % 256);
            ip = random_ip;
        }
        
        int port = 1024 + (rand() % 64512);
        snprintf(message, sizeof(message), tmpl->message_template, ip, port);
    } else {
        strcpy(message, tmpl->message_template);
    }
    
    int pid = 1000 + (rand() % 30000);
    
    printf("<%d>%s %s %s[%d]: %s\n",
           tmpl->priority, time_str, hostname, tmpl->service, pid, message);
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Uso: %s <num_linhas>\n", argv[0]);
        return 1;
    }
    
    long num_lines = atol(argv[1]);
    srand(time(NULL));
    
    time_t now = time(NULL);
    time_t start = now - (14 * 24 * 60 * 60);  // 14 dias
    
    fprintf(stderr, "Gerando %ld linhas de syslog...\n", num_lines);
    
    for (long i = 0; i < num_lines; i++) {
        time_t timestamp = start + (i * 14 * 24 * 60 * 60 / num_lines);
        timestamp += (rand() % 600) - 300;  // ±5 minutos
        
        generate_syslog_entry(timestamp);
        
        if ((i + 1) % 50000 == 0) {
            fprintf(stderr, "\rProgresso: %ld/%ld", i + 1, num_lines);
        }
    }
    
    fprintf(stderr, "\nConcluído!\n");
    return 0;
}

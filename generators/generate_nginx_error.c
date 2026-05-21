#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static const char* levels[] = {"debug", "info", "notice", "warn", "error", "crit"};

typedef struct {
    const char* message;
    int level_idx;
    int weight;
} ErrorTemplate;

static ErrorTemplate errors[] = {
    {"connect() failed (111: Connection refused) while connecting to upstream", 4, 20},
    {"upstream timed out (110: Connection timed out) while reading response header", 4, 15},
    {"recv() failed (104: Connection reset by peer) while reading response header", 4, 12},
    {"no live upstreams while connecting to upstream", 5, 8},
    {"SSL_do_handshake() failed (SSL: error:14094410:SSL)", 4, 10},
    {"limiting requests, excess: 5.123 by zone \"req_limit_per_ip\"", 3, 18},
    {"client intended to send too large body: 11534336 bytes", 4, 7},
    {"upstream sent too big header while reading response header from upstream", 4, 9},
    {"*1 directory index of \"/var/www/html/\" is forbidden", 4, 6},
    {"open() \"/var/www/html/favicon.ico\" failed (2: No such file or directory)", 4, 15},
};
#define ERROR_COUNT (sizeof(errors) / sizeof(errors[0]))

int weighted_random_error() {
    int total = 0;
    for (int i = 0; i < ERROR_COUNT; i++) total += errors[i].weight;
    
    int r = rand() % total;
    int sum = 0;
    for (int i = 0; i < ERROR_COUNT; i++) {
        sum += errors[i].weight;
        if (r < sum) return i;
    }
    return 0;
}

void generate_nginx_error(time_t timestamp) {
    struct tm* tm = gmtime(&timestamp);
    
    int err_idx = weighted_random_error();
    ErrorTemplate* err = &errors[err_idx];
    
    int pid = 1000 + (rand() % 100);
    int tid = 0;
    long conn_id = rand() % 1000000;
    
    char client_ip[20];  // Aumentar buffer
    snprintf(client_ip, sizeof(client_ip), "192.168.%d.%d",
         rand() % 256, rand() % 256);
    
    printf("%04d/%02d/%02d %02d:%02d:%02d [%s] %d#%d: *%ld %s, "
           "client: %s, server: example.com, request: \"GET / HTTP/1.1\"\n",
           tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
           tm->tm_hour, tm->tm_min, tm->tm_sec,
           levels[err->level_idx], pid, tid, conn_id,
           err->message, client_ip);
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Uso: %s <num_linhas>\n", argv[0]);
        return 1;
    }
    
    long num_lines = atol(argv[1]);
    srand(time(NULL));
    
    time_t now = time(NULL);
    time_t start = now - (7 * 24 * 60 * 60);
    
    fprintf(stderr, "Gerando %ld linhas...\n", num_lines);
    
    for (long i = 0; i < num_lines; i++) {
        time_t timestamp = start + (rand() % (7 * 24 * 60 * 60));
        generate_nginx_error(timestamp);
        
        if ((i + 1) % 50000 == 0) {
            fprintf(stderr, "\rProgresso: %ld/%ld", i + 1, num_lines);
        }
    }
    
    fprintf(stderr, "\nConcluído!\n");
    return 0;
}

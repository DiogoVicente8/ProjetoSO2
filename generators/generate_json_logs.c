#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>

static const char* services[] = {
    "auth-api", "user-service", "payment-gateway", 
    "notification-service", "analytics-engine",
    "database-proxy", "cache-manager", "load-balancer"
};
#define SERVICE_COUNT (sizeof(services) / sizeof(services[0]))

static const char* log_levels[] = {"DEBUG", "INFO", "WARN", "ERROR", "CRITICAL"};

typedef struct {
    const char* template;
    int level;
} MessageTemplate;

static MessageTemplate messages[] = {
    {"Request processed successfully", 1},
    {"User authentication successful", 1},
    {"Cache hit for key: %d", 0},
    {"Cache miss for key: %d", 0},
    {"Database query took %dms", 1},
    {"Slow query detected: %dms", 2},
    {"Connection timeout after %ds", 3},
    {"Database connection failed", 3},
    {"Out of memory allocating %d bytes", 4},
    {"Segmentation fault in module %d", 4},
    {"Invalid API key provided", 2},
    {"Rate limit exceeded for user %d", 2},
    {"Payment processing failed", 3},
    {"SSL certificate expired", 4},
};
#define MSG_COUNT (sizeof(messages) / sizeof(messages[0]))

void generate_json_log(FILE* fp, time_t timestamp, int user_id) {
    struct tm* tm = gmtime(&timestamp);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%Y-%m-%dT%H:%M:%SZ", tm);
    
    const char* service = services[rand() % SERVICE_COUNT];
    
    int msg_idx = rand() % MSG_COUNT;
    MessageTemplate* tmpl = &messages[msg_idx];
    
    char message[512];
    if (strstr(tmpl->template, "%d")) {
        snprintf(message, sizeof(message), tmpl->template, rand() % 10000);
    } else {
        strcpy(message, tmpl->template);
    }
    
   char ip[20];  // Aumentar buffer para acomodar IPv4 completo
   snprintf(ip, sizeof(ip), "10.%d.%d.%d", 
         rand() % 256, rand() % 256, rand() % 256);
    
    fprintf(fp, "{\"timestamp\":\"%s\",\"level\":\"%s\",\"service\":\"%s\","
                "\"message\":\"%s\",\"metadata\":{\"ip\":\"%s\",\"user_id\":%d}}\n",
            time_str, log_levels[tmpl->level], service, message, ip, user_id);
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Uso: %s <total_linhas> <num_ficheiros> <diretorio>\n", argv[0]);
        return 1;
    }
    
    long total_lines = atol(argv[1]);
    int num_files = atoi(argv[2]);
    const char* output_dir = argv[3];
    
    mkdir(output_dir, 0755);
    
    srand(time(NULL));
    
    long lines_per_file = total_lines / num_files;
    time_t now = time(NULL);
    time_t start = now - (7 * 24 * 60 * 60);
    
    fprintf(stderr, "Gerando %ld linhas em %d ficheiros...\n", total_lines, num_files);
    
    for (int f = 0; f < num_files; f++) {
        char filename[512];
        snprintf(filename, sizeof(filename), "%s/app_%03d.json", output_dir, f + 1);
        
        FILE* fp = fopen(filename, "w");
        if (!fp) {
            perror("fopen");
            return 1;
        }
        
        for (long i = 0; i < lines_per_file; i++) {
            time_t timestamp = start + (rand() % (7 * 24 * 60 * 60));
            int user_id = 1000 + (rand() % 9000);
            generate_json_log(fp, timestamp, user_id);
        }
        
        fclose(fp);
        fprintf(stderr, "\rProgresso: %d/%d", f + 1, num_files);
    }
    
    fprintf(stderr, "\nConcluído!\n");
    return 0;
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static const char* ip_pool[] = {
    "192.168.1.100", "192.168.1.101", "192.168.1.102",
    "10.0.0.50", "10.0.0.51", "10.0.1.100",
    "172.16.0.10", "172.16.0.20",
    "203.0.113.45", "198.51.100.23", "93.184.216.34"
};
#define IP_POOL_SIZE (sizeof(ip_pool) / sizeof(ip_pool[0]))

static const char* user_agents[] = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "curl/7.68.0",
    "Python-urllib/3.8"
};
#define UA_POOL_SIZE (sizeof(user_agents) / sizeof(user_agents[0]))

typedef struct {
    const char* path;
    int weight;
    int min_status;
    int max_status;
} URLPattern;

static URLPattern url_patterns[] = {
    {"/", 100, 200, 200},
    {"/index.html", 80, 200, 200},
    {"/api/users", 50, 200, 200},
    {"/api/products", 40, 200, 200},
    {"/api/orders", 30, 200, 201},
    {"/admin/login", 20, 200, 403},
    {"/static/css/style.css", 60, 200, 200},
    {"/static/js/app.js", 60, 200, 200},
    {"/images/logo.png", 70, 200, 200},
    {"/api/search", 35, 200, 200},
    {"/notfound", 5, 404, 404},
    {"/api/internal", 3, 500, 503},
};
#define URL_POOL_SIZE (sizeof(url_patterns) / sizeof(url_patterns[0]))

static const char* methods[] = {"GET", "POST", "PUT", "DELETE", "PATCH"};
static int method_weights[] = {70, 20, 5, 3, 2};

static int weighted_random(const int* weights, int count) {
    int total = 0;
    for (int i = 0; i < count; i++) total += weights[i];
    
    int r = rand() % total;
    int sum = 0;
    for (int i = 0; i < count; i++) {
        sum += weights[i];
        if (r < sum) return i;
    }
    return 0;
}

void generate_apache_log(time_t timestamp) {
    const char* ip = ip_pool[rand() % IP_POOL_SIZE];
    
    struct tm* tm = gmtime(&timestamp);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%d/%b/%Y:%H:%M:%S +0000", tm);
    
    int method_idx = weighted_random(method_weights, 5);
    const char* method = methods[method_idx];
    
    int url_weights[URL_POOL_SIZE];
    for (int i = 0; i < URL_POOL_SIZE; i++) {
        url_weights[i] = url_patterns[i].weight;
    }
    int url_idx = weighted_random(url_weights, URL_POOL_SIZE);
    URLPattern* pattern = &url_patterns[url_idx];
    
    int status = pattern->min_status;
    if (pattern->max_status > pattern->min_status) {
        status += rand() % (pattern->max_status - pattern->min_status + 1);
    }
    
    int size;
    if (status == 404) {
        size = 150 + rand() % 100;
    } else if (status >= 500) {
        size = 200 + rand() % 150;
    } else {
        size = 500 + rand() % 50000;
    }
    
    const char* ua = user_agents[rand() % UA_POOL_SIZE];
    
    const char* referer = "-";
    if (rand() % 100 < 70) {
        referer = "https://example.com/";
    }
    
    printf("%s - - [%s] \"%s %s HTTP/1.1\" %d %d \"%s\" \"%s\"\n",
           ip, time_str, method, pattern->path, status, size, referer, ua);
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Uso: %s <num_linhas>\n", argv[0]);
        return 1;
    }
    
    long num_lines = atol(argv[1]);
    srand(time(NULL));
    
    time_t now = time(NULL);
    time_t start = now - (30 * 24 * 60 * 60);
    
    fprintf(stderr, "Gerando %ld linhas...\n", num_lines);
    
    for (long i = 0; i < num_lines; i++) {
        time_t timestamp = start + (i * 30 * 24 * 60 * 60 / num_lines);
        timestamp += (rand() % 1200) - 600;
        
        generate_apache_log(timestamp);
        
        if ((i + 1) % 100000 == 0) {
            fprintf(stderr, "\rProgresso: %ld/%ld", i + 1, num_lines);
        }
    }
    
    fprintf(stderr, "\nConcluído!\n");
    return 0;
}

# Makefile — Log Analyzer Fase 1 + Fase 2
# Sistemas Operativos — UFP 2026
 
CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -I.
 
# Ficheiros partilhados entre Fase 1 e Fase 2
SHARED_SRCS = config.c files.c ipc.c dashboard.c report.c \
              log_parser.c event_classifier.c
SHARED_OBJS = $(SHARED_SRCS:.c=.o)
 
# Fase 1 — processos
F1_SRCS     = logAnalyzer.c worker.c
F1_OBJS     = $(F1_SRCS:.c=.o)
TARGET      = logAnalyzer
TARGET_SOCK = logAnalyzer_sockets
 
# Fase 2A+B — threads básicas + dashboard dedicado
F2A_SRCS    = logAnalyzer_threads.c thread_worker.c dashboard_thread.c
F2A_OBJS    = $(F2A_SRCS:.c=.o)
TARGET_T    = logAnalyzer_threads
 
# Fase 2C — produtor-consumidor com bounded buffer
F2C_SRCS  = logAnalyzer_pc.c pc_worker.c bounded_buffer.c dashboard_thread.c
F2C_OBJS  = $(F2C_SRCS:.c=.o)
TARGET_PC = logAnalyzer_pc
 
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
    LDFLAGS = -lrt -pthread
endif
ifeq ($(UNAME_S),Darwin)
    LDFLAGS = -pthread
endif
 
GEN_DIR     = ../generators
DATASET_DIR = ../datasets
APACHE_DIR  = $(DATASET_DIR)/apache
JSON_DIR    = $(DATASET_DIR)/json_logs
SYSLOG_DIR  = $(DATASET_DIR)/syslog
NGINX_DIR   = $(DATASET_DIR)/nginx
 
GEN_APACHE = $(GEN_DIR)/gen_apache
GEN_JSON   = $(GEN_DIR)/gen_json
GEN_SYSLOG = $(GEN_DIR)/gen_syslog
GEN_NGINX  = $(GEN_DIR)/gen_nginx
 
.PHONY: all fase1 fase2 sockets generators datasets datasets-large test benchmark clean help
 
# -----------------------------------------------------------------------
# all: compila tudo
# -----------------------------------------------------------------------
all: fase1 fase2 fase2c
 
# -----------------------------------------------------------------------
# Fase 1 — processos (Requisitos A–D via pipes)
# -----------------------------------------------------------------------
fase1: $(TARGET)
 
$(TARGET): $(SHARED_OBJS) $(F1_OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)
	@echo "✓ Compilado: ./$(TARGET)  (processos — pipes)"
 
# -----------------------------------------------------------------------
# Fase 1 com sockets (Requisito E)
# -----------------------------------------------------------------------
sockets: $(TARGET_SOCK)
 
$(TARGET_SOCK): $(SHARED_SRCS) $(F1_SRCS)
	$(CC) $(CFLAGS) -DUSE_SOCKETS $^ -o $@ $(LDFLAGS)
	@echo "✓ Compilado: ./$(TARGET_SOCK)  (processos — sockets)"
 
# -----------------------------------------------------------------------
# Fase 2A — worker threads básicas (Requisito 2-A)
# -----------------------------------------------------------------------
fase2: $(TARGET_T)
 
$(TARGET_T): $(SHARED_OBJS) $(F2A_OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)
	@echo "✓ Compilado: ./$(TARGET_T)  (threads — Req 2-A + 2-B)"
 
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@
 
# -----------------------------------------------------------------------
# Geradores
# -----------------------------------------------------------------------
generators: $(GEN_APACHE) $(GEN_JSON) $(GEN_SYSLOG) $(GEN_NGINX)
 
$(GEN_APACHE): $(GEN_DIR)/generate_apache_logs.c
	$(CC) -O2 $< -o $@
$(GEN_JSON): $(GEN_DIR)/generate_json_logs.c
	$(CC) -O2 $< -o $@
$(GEN_SYSLOG): $(GEN_DIR)/generate_syslog.c
	$(CC) -O2 $< -o $@
$(GEN_NGINX): $(GEN_DIR)/generate_nginx_error.c
	$(CC) -O2 $< -o $@
 
# -----------------------------------------------------------------------
# Datasets de teste (~1 MB)
# -----------------------------------------------------------------------
datasets: generators
	@mkdir -p $(APACHE_DIR) $(JSON_DIR) $(SYSLOG_DIR) $(NGINX_DIR)
	$(GEN_APACHE) 5000   > $(APACHE_DIR)/access_5k.log
	$(GEN_JSON)   2000 20  $(JSON_DIR)/
	$(GEN_SYSLOG) 3000   > $(SYSLOG_DIR)/security_3k.log
	$(GEN_NGINX)  1500   > $(NGINX_DIR)/error_1k.log
	@echo "✓ Datasets prontos"
	@du -sh $(DATASET_DIR)/*/
 
# -----------------------------------------------------------------------
# Datasets grandes (~100 MB) para benchmarks de speedup
# -----------------------------------------------------------------------
datasets-large: generators
	@mkdir -p $(APACHE_DIR) $(JSON_DIR) $(SYSLOG_DIR) $(NGINX_DIR)
	$(GEN_APACHE) 100000    > $(APACHE_DIR)/access_100k.log
	$(GEN_JSON)   50000 500   $(JSON_DIR)/
	$(GEN_SYSLOG) 50000    > $(SYSLOG_DIR)/security_50k.log
	$(GEN_NGINX)  20000    > $(NGINX_DIR)/error_20k.log
	@echo "✓ Datasets grandes prontos"
	@du -sh $(DATASET_DIR)/*/
 
# -----------------------------------------------------------------------
# Testes automáticos
# -----------------------------------------------------------------------
test: all sockets datasets
	@echo ""
	@echo "=== TESTES FASE 1 (processos) ==="
	@echo "[1] security — 2 workers"
	./$(TARGET) $(DATASET_DIR) 2 security
	@echo ""
	@echo "[2] full — 4 workers — verbose"
	./$(TARGET) $(DATASET_DIR) 4 full --verbose
	@echo ""
	@echo "[3] sockets — nginx — 2 workers"
	./$(TARGET_SOCK) $(NGINX_DIR) 2 full
	@echo ""
	@echo "=== TESTES FASE 2A/B (threads) ==="
	@echo "[4] full — 4 threads"
	./$(TARGET_T) $(DATASET_DIR) 4 full
	@echo ""
	@echo "[5] security — 2 threads — verbose"
	./$(TARGET_T) $(DATASET_DIR) 2 security --verbose
	@echo ""
	@echo "[6] full — 4 threads — output JSON"
	./$(TARGET_T) $(DATASET_DIR) 4 full --output=/tmp/report_threads.json
	@cat /tmp/report_threads.json
	@echo ""
	@echo "=== TESTES FASE 2C (produtor-consumidor) ==="
	@echo "[7] traffic — 2 produtores — 2 consumidores"
	./$(TARGET_PC) $(APACHE_DIR) 2 traffic --consumers=2 --output=/tmp/report_pc.json
	@cat /tmp/report_pc.json
	@echo ""
	@echo "=== FIM ==="
 
# -----------------------------------------------------------------------
# Benchmark de speedup (requer datasets-large)
# -----------------------------------------------------------------------
benchmark: all datasets-large
	@echo "=== BENCHMARK FASE 1 (processos) ==="
	@echo "1 processo:"
	time ./$(TARGET) $(DATASET_DIR) 1 full
	@echo "4 processos:"
	time ./$(TARGET) $(DATASET_DIR) 4 full
	@echo ""
	@echo "=== BENCHMARK FASE 2A (threads) ==="
	@echo "1 thread:"
	time ./$(TARGET_T) $(DATASET_DIR) 1 full
	@echo "4 threads:"
	time ./$(TARGET_T) $(DATASET_DIR) 4 full
 
# -----------------------------------------------------------------------
clean:
	rm -f $(SHARED_OBJS) $(F1_OBJS) $(F2A_OBJS) $(F2C_OBJS)
	rm -f $(TARGET) $(TARGET_SOCK) $(TARGET_T) $(TARGET_PC)
	rm -f $(GEN_APACHE) $(GEN_JSON) $(GEN_SYSLOG) $(GEN_NGINX)
	@echo "✓ Limpo"
 
help:
	@echo "make              — compilar Fase 1 + Fase 2"
	@echo "make fase1        — compilar só Fase 1 (processos)"
	@echo "make fase2        — compilar só Fase 2A (threads)"
	@echo "make sockets      — compilar Fase 1 com Unix Domain Sockets"
	@echo "make generators   — compilar geradores de logs"
	@echo "make datasets     — gerar dados de teste (~1 MB)"
	@echo "make datasets-large — gerar dados grandes (~100 MB)"
	@echo "make test         — correr testes automáticos"
	@echo "make benchmark    — medir speedup Fase1 vs Fase2"
	@echo ""
	@echo "Uso Fase 1:  ./logAnalyzer <dir> <workers> <modo> [--verbose] [--output=f]"
	@echo "Uso Fase 2A: ./logAnalyzer_threads <dir> <threads> <modo> [--verbose] [--output=f]"
 
 
# -----------------------------------------------------------------------
# Fase 2C — produtor-consumidor com bounded buffer (Requisito 2-C)
# -----------------------------------------------------------------------
fase2c: $(TARGET_PC)
 
$(TARGET_PC): $(SHARED_OBJS) $(F2C_OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)
	@echo "✓ Compilado: ./$(TARGET_PC)  (produtor-consumidor — Req 2-C)"
 
.PHONY: fase2c
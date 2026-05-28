# Log Analyzer - Sistemas Operativos UFP 2026

Sistema paralelo de analise de logs com implementacoes por processos, Unix Domain Sockets, threads e produtor-consumidor.

## Autores

- Diogo Vicente- 2024115283
- João Reis- 2024118534

## Estrutura

```text
src/
├── logAnalyzer.c          # Fase 1: processos + pipes
├── logAnalyzer_threads.c  # Fase 2A/B: worker threads + dashboard dedicado
├── logAnalyzer_pc.c       # Fase 2C: produtor-consumidor
├── config.{h,c}           # Parse da linha de comandos
├── files.{h,c}            # Descoberta e divisao de ficheiros
├── ipc.{h,c}              # readn/writen, serializacao e agregacao
├── worker.{h,c}           # Workers por processo
├── thread_worker.{h,c}    # Workers por thread
├── pc_worker.{h,c}        # Produtores/consumidores
├── bounded_buffer.{h,c}   # Buffer circular com semaforos
├── dashboard*.{h,c}       # Dashboard ANSI
├── log_parser.{h,c}       # Parsers Apache, JSON, Syslog e Nginx
├── event_classifier.{h,c} # Classificacao security/performance/traffic
├── report.{h,c}           # Relatorio terminal e JSON
└── Makefile

generators/
├── generate_apache_logs.c
├── generate_json_logs.c
├── generate_syslog.c
└── generate_nginx_error.c
```

## Compilacao

```bash
cd src
make              # compila Fase 1 + Fase 2A/B + Fase 2C
make sockets      # compila versao Fase 1 com Unix Domain Sockets
make clean
```

Tambem existem alvos especificos:

```bash
make fase1
make fase2
make fase2c
make generators
make datasets
make datasets-large
```

## Execucao

Formato comum:

```bash
./logAnalyzer <diretorio_logs> <num_workers> <modo> [opcoes]
```

Modos:

- `security`
- `performance`
- `traffic`
- `full`

Opcoes:

- `--verbose`: mostra eventos criticos em tempo real
- `--output=<ficheiro>`: escreve relatorio JSON
- `--consumers=N`: apenas em `logAnalyzer_pc`

Exemplos:

```bash
# Fase 1: processos + pipes
./logAnalyzer ../datasets/apache 4 full
./logAnalyzer ../datasets 4 security --verbose
./logAnalyzer ../datasets/apache 2 traffic --output=/tmp/report.json

# Fase 1E: Unix Domain Sockets
./logAnalyzer_sockets ../datasets/nginx 4 full

# Fase 2A/B: threads + dashboard dedicado
./logAnalyzer_threads ../datasets/json_logs 4 security

# Fase 2C: produtor-consumidor
./logAnalyzer_pc ../datasets/apache 2 traffic --consumers=4
```

## Requisitos Implementados

### Fase 1

- CLI com validacao dos argumentos obrigatorios e opcionais.
- Descoberta recursiva de ficheiros `.log` e `.json`.
- Processamento paralelo com `fork()` e `waitpid()`.
- Comunicacao via pipe anonimo entre filhos e pai.
- Funcoes `readn()` e `writen()` com tratamento de `EINTR`.
- Modo verbose com envio imediato de eventos de severidade alta/critica.
- Dashboard ANSI com progresso por worker e progresso total.
- Variante com Unix Domain Sockets usando `socket()`, `bind()`, `listen()`, `accept()` e `connect()`.

### Fase 2

- `logAnalyzer_threads`: worker threads com `pthread_create()` e `pthread_join()`.
- Dashboard dedicado em thread propria.
- `logAnalyzer_pc`: arquitetura produtor-consumidor com bounded buffer.
- Buffer circular protegido por mutex e semaforos POSIX.
- Deteccao de padroes no produtor-consumidor:
  - falhas repetidas de autenticacao por IP
  - erros 5xx consecutivos

## Formatos Suportados

- Apache Combined Log Format
- JSON structured logs
- Syslog RFC 3164
- Nginx error log

As metricas incluem linhas totais, linhas parseadas, severidade, eventos de seguranca/performance, erros HTTP 4xx/5xx e Top 10 IPs.

## Testes

```bash
cd src
make test
```

Comandos rapidos usados para validacao:

```bash
make all sockets
./logAnalyzer ../datasets/apache 2 full --output=/tmp/la_process.json
./logAnalyzer_sockets ../datasets/nginx 2 full --output=/tmp/la_sockets.json
./logAnalyzer_threads ../datasets/json_logs 4 security --output=/tmp/la_threads.json
./logAnalyzer_pc ../datasets/apache 2 traffic --consumers=2 --output=/tmp/la_pc.json
```

## Benchmark

```bash
cd src
make benchmark
```

O benchmark compara 1 worker/thread contra 4 workers/threads e imprime tempos e throughput.

## Chamadas POSIX Usadas

- I/O: `open()`, `read()`, `write()`, `close()`
- Processos: `fork()`, `waitpid()`, `exit()`
- IPC: `pipe()`, Unix Domain Sockets
- Threads: `pthread_create()`, `pthread_join()`
- Sincronizacao: mutexes, semaforos POSIX
- Diretorios: `opendir()`, `readdir()`, `closedir()`, `stat()`

Nao sao usados `fopen()`, `fread()` ou `fwrite()` no processamento dos logs.

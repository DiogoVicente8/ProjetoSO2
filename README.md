# Log Analyzer - Sistemas Operativos UFP 2026

Projeto de análise paralela de logs com implementações em processos, threads e produtor-consumidor.

## Autores

- Diogo Vicente — <2024115283@ufp.edu.pt>
- João Reis — <2024118534@ufp.edu.pt>

## Estrutura do projeto

```text
src/
├── logAnalyzer.c          # Fase 1: main/orquestrador de processos
├── phase1_process.{h,c}   # Fase 1: fork, pipes, sockets, waitpid e dashboard
├── logAnalyzer_threads.c  # Fase 2A/B: workers com threads + dashboard dedicado
├── logAnalyzer_pc.c       # Fase 2C: produtor-consumidor com bounded buffer
├── config.{h,c}           # Parse da linha de comandos
├── files.{h,c}            # Descoberta recursiva de ficheiros e divisão de trabalho
├── ipc.{h,c}              # readn/writen, serialização e agregação de resultados
├── worker.{h,c}           # Workers por processo
├── thread_worker.{h,c}    # Workers por thread
├── pc_worker.{h,c}        # Produtores e consumidores
├── bounded_buffer.{h,c}   # Buffer circular com semáforos POSIX
├── dashboard.c            # Dashboard ANSI do processo pai
├── dashboard_thread.c     # Dashboard dedicado em thread para Fase 2
├── log_parser.{h,c}       # Parsers Apache, JSON, Syslog e Nginx
├── event_classifier.{h,c} # Classificação de eventos security/performance/traffic
├── report.{h,c}           # Relatório terminal e JSON
└── Makefile

generators/
├── generate_apache_logs.c
├── generate_json_logs.c
├── generate_syslog.c
└── generate_nginx_error.c
```

## Compilação

No directório `src`:

```bash
cd src
make              # compila Fase 1 + Fase 2A/B + Fase 2C
make sockets      # compila Fase 1 com Unix Domain Sockets
make clean        # remove binários e objetos
make clean-datasets # remove datasets gerados
```

Alvos específicos:

```bash
make fase1        # compila só Fase 1 (processos)
make fase2        # compila só Fase 2A/B (threads)
make fase2c       # compila só Fase 2C (produtor-consumidor)
make generators  # compila geradores de logs
make datasets     # gera datasets de teste (~1 MB)
make datasets-large # gera datasets grandes para benchmark (~100 MB)
make test         # executa testes automáticos de todas as fases
make benchmark    # executa benchmark de speedup
```

## Execução

### Fase 1 — processos + pipes

```bash
./logAnalyzer <diretorio_logs> <num_workers> <modo> [--verbose] [--output=<ficheiro>]
```

### Fase 1E — Unix Domain Sockets

```bash
./logAnalyzer_sockets <diretorio_logs> <num_workers> <modo> [--verbose] [--output=<ficheiro>]
```

### Fase 2A/B — threads + dashboard dedicado

```bash
./logAnalyzer_threads <diretorio_logs> <num_threads> <modo> [--verbose] [--output=<ficheiro>]
```

### Fase 2C — produtor-consumidor

```bash
./logAnalyzer_pc <diretorio_logs> <num_produtores> <modo> --consumers=<num_consumidores> [--verbose] [--output=<ficheiro>]
```

## Modos suportados

- `security`
- `performance`
- `traffic`
- `full`

### Opções comuns

- `--verbose` — imprime eventos críticos em tempo real
- `--output=<ficheiro>` — grava relatório JSON
- `--consumers=N` — apenas em `logAnalyzer_pc`

## Exemplos

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

## Requisitos implementados

### Fase 1

- CLI com validação dos argumentos obrigatórios e opcionais
- Descoberta recursiva de ficheiros `.log` e `.json`
- Processamento paralelo com `fork()` e `waitpid()`
- Comunicação entre pai e filhos via pipes anónimos
- Funções `readn()` e `writen()` com tratamento de `EINTR`
- Modo `--verbose` com envio imediato de eventos de severidade alta/critica
- Dashboard ANSI com progresso por worker e progresso total
- Variante com Unix Domain Sockets usando `socket()`, `bind()`, `listen()`, `accept()` e `connect()`

### Fase 2

- `logAnalyzer_threads`: workers com `pthread_create()` e `pthread_join()`
- Dashboard dedicado executado em thread própria
- `logAnalyzer_pc`: arquitetura produtor-consumidor com bounded buffer
- Buffer circular protegido por mutexes e semáforos POSIX
- Detecção de padrões na fase produtor-consumidor:
  - falhas repetidas de autenticação por IP
  - erros `5xx` consecutivos

## Formatos suportados

- Apache Combined Log Format
- JSON structured logs
- Syslog RFC 3164
- Nginx error log

## Métricas reportadas

- linhas totais
- linhas parseadas
- severidade dos eventos
- eventos de segurança
- eventos de performance
- erros HTTP `4xx` / `5xx`
- Top 10 IPs

## Testes

```bash
cd src
make test
```

O alvo `make test` gera datasets, compila os binários e executa casos de teste para Fase 1, Fase 2A/B e Fase 2C.

## Benchmark

```bash
cd src
make benchmark
```

O benchmark compara execução com 1 worker/thread e 4 workers/threads.

## Chamadas POSIX usadas

- I/O: `open()`, `read()`, `write()`, `close()`
- Processos: `fork()`, `waitpid()`, `exit()`
- IPC: `pipe()`, Unix Domain Sockets
- Threads: `pthread_create()`, `pthread_join()`
- Sincronização: mutexes POSIX, semáforos POSIX
- Diretórios: `opendir()`, `readdir()`, `closedir()`, `stat()`

O processamento de logs evita `fopen()`, `fread()` e `fwrite()`.

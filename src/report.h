#ifndef REPORT_H
#define REPORT_H

#include "ipc.h"
#include "config.h"

void print_report(const GlobalResult *gr, const WorkerResult *workers,
                  int n_workers, const Config *cfg, double elapsed);

void write_report_json(const GlobalResult *gr, const Config *cfg,
                       double elapsed, const char *path);

#endif

#ifndef CONFIG_H
#define CONFIG_H

#include <stdbool.h>
#include "event_classifier.h"

#define MAX_PATH_LEN  1024
#define MAX_WORKERS   64

typedef struct {
    char         log_dir[MAX_PATH_LEN];
    int          num_procs;
    AnalysisMode mode;
    bool         verbose;
    bool         has_output;
    char         output_file[MAX_PATH_LEN];
} Config;

int         parse_args(int argc, char *argv[], Config *cfg);
void        print_usage(const char *prog);
void        print_config(const Config *cfg);
const char *mode_to_string(AnalysisMode mode);

#endif

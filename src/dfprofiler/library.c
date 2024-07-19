
#include "library.h"
__attribute__((visibility("default"))) void dfprofiler_start() {}
__attribute__((visibility("default"))) void dfprofiler_stop() {}

void dfprofiler_init(void) { dfprofiler_start(); }

void dfprofiler_fini(void) { dfprofiler_stop(); }
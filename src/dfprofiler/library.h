#ifndef DFPROFILER_LIBRARY_H
#define DFPROFILER_LIBRARY_H
__attribute__((visibility("default"))) extern void dfprofiler_start();

__attribute__((visibility("default"))) extern void dfprofiler_stop();

extern void __attribute__((constructor)) dfprofiler_init(void);

extern void __attribute__((destructor)) dfprofiler_fini(void);

#endif // DFPROFILER_LIBRARY_H
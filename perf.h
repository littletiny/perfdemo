#ifndef _PERF_PERF_H
#define _PERF_PERF_H

#include <stdint.h>

#include <linux/perf_event.h>
#include <asm/perf_regs.h>

#define PERF_REG_MASK 0xff0fffULL
#define PERF_MAX_REGS PERF_REG_X86_64_MAX

#define kMaxCpuCount 512
#define kMaxBacktraceCount 128
#define kStackSize (63 * 1024)
#define kMaxStackSize (UINT16_MAX + 1)
#define kBufSize (512 * 1024) // 4096 * ((1 << 7)),  64 * 1024 * (1 << 3)

struct sample_event {
	uint32_t pid;
	uint32_t tid;
	uint64_t time;
	uint32_t cpu;
	uint32_t res;
	uint64_t nr;
	uint64_t *ips;
	uint64_t abi;
	uint64_t regs[PERF_MAX_REGS];
	uint64_t size;
	char *data;
};

struct perf_ctx {
	int cpus;
	int pagesize;
	uint64_t sampletype;
	struct perf_event_mmap_page **perf_mmap_buf;
	char *perf_mmap_ringbuffer;
	int *fds;
	struct sample_event *event;
};

#endif

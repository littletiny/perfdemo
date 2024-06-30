#include <unistd.h>
#include <fcntl.h>
#include <syscall.h>

#include <sys/types.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/sysinfo.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "perf.h"

bool consume_perf_sample_record(struct perf_event_header *hdr, int sampletype) {
	char *buf = (char *)&hdr[1];

	int pid, tid;
	uint64_t abi;
	uint64_t regs[PERF_MAX_REGS];

	if (sampletype & PERF_SAMPLE_TID) {
		pid = *(int *)buf;
		buf += 4;
		tid = *(int *)buf;
		buf += 4;
	}

	if (sampletype & PERF_SAMPLE_CALLCHAIN) {
		// callchain format {PERF_CONTEXT_KERNEL, kernel_callchains..., PERF_CONTEXT_USER, user_callchains...}
	}

	if (sampletype & PERF_SAMPLE_REGS_USER) {
		// we not support x86, only support x86_64
		abi = *(uint64_t *)buf;
		buf += 8;
		if (abi == PERF_SAMPLE_REGS_ABI_64) {
			int pos = 0;
			for (int i = 0; i < PERF_MAX_REGS; i++) {
				if (PERF_REG_MASK & (1ULL << i)) {
					regs[i] = ((uint64_t *)buf)[pos];
					pos++;
				}
			}
			buf += 8 * pos;
		} else if (abi == PERF_SAMPLE_REGS_ABI_NONE) {
			// kernel mode, none regs
			// memset(event->regs, 0, sizeof(event->regs));
		} else if (abi == PERF_SAMPLE_REGS_ABI_32) {
			// not support now
			return false;
		} else {
			return false;
		}
	}

	// TODO record events
	return true;
}

static char *perf_get_mmap_buf(struct perf_event_mmap_page *page, int pagesize) {
	return (char *)page + pagesize;
}

void consume_perf_event(struct perf_sample_ctx *ctx, int cpu) {
	char *base;
	char *cur, *begin, *end;

	struct perf_event_mmap_page *page = ctx->perf_mmap_buf[cpu];
	char *ringbuffer = ctx->perf_mmap_ringbuffer;

	uint64_t head, tail;
	tail = page->data_tail;
	__atomic_load(&page->data_head, (unsigned long long *)&head, __ATOMIC_ACQUIRE);

	base = perf_get_mmap_buf(page, ctx->pagesize);
	begin = base + tail % kBufSize;
	end = base + head % kBufSize;
	cur = begin;

	while (cur != end) {
		struct perf_event_header *hdr = (struct perf_event_header *)cur;
		if (cur + hdr->size > base + kBufSize) {
			int pattern_len = base + kBufSize - cur;
			memcpy(ringbuffer, cur, pattern_len);
			memcpy(ringbuffer + pattern_len, base, hdr->size - pattern_len);
			hdr = (struct perf_event_header *)ringbuffer;
			cur = base + hdr->size - pattern_len;
		} else if (cur + hdr->size == base + kBufSize) {
			cur = base;
		} else {
			cur += hdr->size;
		}

		if (hdr->size == 0) {
			// empty event
			break;
		}

		if (hdr->type == PERF_RECORD_SAMPLE) {
			printf("new event for cpu(%d)\n", cpu);
			// consume event
			consume_perf_sample_record(hdr, ctx->sampletype);
		}
	}
	__atomic_store(&page->data_tail, (unsigned long long *)&head, __ATOMIC_RELEASE);
}

static inline int sys_perf_event_open(struct perf_event_attr *attr, pid_t pid,
		int cpu, int group_fd,
		unsigned long flags) {
	attr->size = sizeof(*attr);
	return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

static int perf_event_open(int cpu, struct perf_event_attr *attr) {
	return sys_perf_event_open(attr, -1, cpu, -1, PERF_FLAG_FD_CLOEXEC);
}

static int perf_sample_attr_init_sw(struct perf_event_attr *attr, int freq) {
	memset(attr, 0, sizeof(*attr));
	attr->disabled = 1;
	attr->size = sizeof(*attr);
	attr->type = PERF_TYPE_SOFTWARE;
	attr->config = PERF_COUNT_SW_CPU_CLOCK;
	attr->sample_type = PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN;
	attr->exclude_hv = 1;
	attr->exclude_idle = 1;
	attr->freq = 1;
	attr->sample_freq = freq;
	attr->sample_regs_user = PERF_REG_MASK;
	attr->wakeup_watermark = kBufSize * 3 / 4;
	attr->watermark = 1;
	attr->sample_stack_user = kStackSize; // 8 byte aligned, max 2^16 - 1
	return attr->sample_type;
}

static int perf_sample_attr_init_hw(struct perf_event_attr *attr, int freq) {
	memset(attr, 0, sizeof(*attr));
	attr->disabled = 1;
	attr->size = sizeof(*attr);
	attr->type = PERF_TYPE_HARDWARE;
	attr->config = PERF_COUNT_HW_CPU_CYCLES;
	attr->sample_type = PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN;
	attr->exclude_hv = 1;
	attr->exclude_idle = 1;
	attr->freq = 1;
	attr->sample_freq = freq;
	attr->sample_regs_user = PERF_REG_MASK;
	attr->wakeup_watermark = kBufSize * 3 / 4;
	attr->watermark = 1;
	attr->sample_stack_user = kStackSize; // 8 byte aligned, max 2^16 - 1
	return attr->sample_type;
}

int perf_init_attr(struct perf_event_attr *attr, int freq) {
	return perf_sample_attr_init_hw(attr, freq);
}

static void consume_all_perf_event(struct perf_sample_ctx *ctx) {
	int cpus = ctx->cpus;
	for (;;) {
		for (int cpu = 0; cpu < cpus; cpu++) {
			printf("consume event on cpu(%d)\n", cpu);
			consume_perf_event(ctx, cpu);
		}
		usleep(100 * 1000);
	}
}

static struct perf_event_mmap_page *perf_mmap_event(int fd, int pagesize) {
	char *buf = (char *)mmap(NULL, kBufSize + pagesize,
			PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (buf == MAP_FAILED) {
		close(fd);
		return NULL;
	}
	return (struct perf_event_mmap_page *)buf;
}

static struct perf_sample_ctx *create_perf_ctx() {
	struct perf_sample_ctx *ctx = (struct perf_sample_ctx *)malloc(sizeof(struct perf_sample_ctx));

	ctx->cpus = get_nprocs();
	ctx->perf_mmap_ringbuffer = (char *)malloc(kBufSize);
	ctx->perf_mmap_buf = (struct perf_event_mmap_page **)malloc(ctx->cpus * sizeof(void *));
	ctx->fds = (int *)malloc(ctx->cpus * sizeof(int));

	for (int cpu = 0; cpu < ctx->cpus; cpu++) {
		ctx->fds[cpu] = -1;
		ctx->perf_mmap_buf = NULL;
	}

	ctx->event = (struct sample_event *)malloc(sizeof(struct sample_event));

	int pagesize = sysconf(_SC_PAGESIZE);
	if (pagesize < 0) {
		pagesize = 4096;
	}
	ctx->pagesize = pagesize;

	return ctx;
}

static perf_sample_ctx* perf_init_ctx(struct perf_sample_ctx *ctx) {
	struct perf_event_attr attr;
	perf_init_attr(&attr, 10);
	ctx->sampletype = attr.sample_type;

	for (int cpu = 0; cpu < ctx->cpus; cpu++) {
		int fd = perf_event_open(cpu, &attr);
		ctx->fds[cpu] = fd;
		if (fd < 0) {
			perror("perf_event_open");
			return NULL;
		}
		ctx->perf_mmap_buf[cpu] = perf_mmap_event(fd, ctx->pagesize);
		if (!ctx->perf_mmap_buf[cpu]) {
			perror("mmap");
			return NULL;
		}
		ioctl(fd, PERF_EVENT_IOC_RESET, 0);
		ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
	}
	return ctx;
}

struct perf_sample_ctx* perf_init(struct perf_sample_ctx *ctx) {
	return perf_init_ctx(ctx);
}

void perf_run(struct perf_sample_ctx *ctx) {
	consume_all_perf_event(ctx);
}

int perf_exit(struct perf_sample_ctx *ctx) {
	for (int cpu = 0; cpu < ctx->cpus; cpu++) {
		if (!ctx->perf_mmap_buf) {
			munmap(ctx->perf_mmap_buf[cpu], kBufSize + ctx->pagesize);
		}
		if (ctx->fds[cpu] != -1) {
			close(ctx->fds[cpu]);
		}
	}
	free(ctx->perf_mmap_ringbuffer);
	free(ctx->perf_mmap_buf);
	free(ctx->fds);
	free(ctx);
	return 0;
}

int main() {
	struct perf_sample_ctx *ctx = create_perf_ctx();
	if (!perf_init(ctx)) {
		perf_exit(ctx);
		return -1;
	}
	perf_run(ctx);
	perf_exit(ctx);
	return 0;
}

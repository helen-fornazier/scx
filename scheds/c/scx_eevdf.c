/* SPDX-License-Identifier: GPL-2.0 */

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <stdarg.h>
#include <bpf/bpf.h>
#include <scx/common.h>
#include "scx_eevdf.bpf.skel.h"

const char help_fmt[] =
"EEVDF sched_ext scheduler closer to the original paper.\n";

static volatile int exit_req;

struct stats {
	u64 VirtualTime;
	u64 LastDispatchedVDTime;
	u64 TotalWeight;
	u64 n_enqueued;
	u64 n_dispatched;
	u64 n_joined;
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static void sigint_handler(int simple)
{
	exit_req = 1;
}

int main(int argc, char **argv)
{
	struct scx_eevdf *skel;
	struct bpf_link *link;
	__u64 ecode;

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);
restart:
	skel = SCX_OPS_OPEN(eevdf_ops, scx_eevdf);

	SCX_OPS_LOAD(skel, eevdf_ops, scx_eevdf, uei);
	link = SCX_OPS_ATTACH(skel, eevdf_ops, scx_eevdf);

	while (!exit_req && !UEI_EXITED(skel, uei)) {
		__u32 key = 0;
		struct stats stats;

		if (bpf_map_lookup_elem(bpf_map__fd(skel->maps.stats_map), &key, &stats) < 0) {
			fprintf(stderr, "Failed to lookup stats\n");
			break;
		}
		s64 diff = stats.LastDispatchedVDTime - stats.VirtualTime;
		printf("VirtualTime=%lu LastDispatchedVDTime=%lu Diff=%ld TotalWeight=%lu n_enqueued=%lu n_dispatched=%lu n_joined=%lu\n",
		       stats.VirtualTime, stats.LastDispatchedVDTime, diff, stats.TotalWeight, stats.n_enqueued, stats.n_dispatched, stats.n_joined);
		fflush(stdout);
		sleep(1);
	}

	bpf_link__destroy(link);
	ecode = UEI_REPORT(skel, uei);
	scx_eevdf__destroy(skel);

	if (UEI_ECODE_RESTART(ecode))
		goto restart;
	return 0;
}

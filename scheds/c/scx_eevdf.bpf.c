/* SPDX-License-Identifier: GPL-2.0 */

/*
 * EEVDF scheduler closer to the original paper
 *
 * Names are preserved from the original paper.
 */

#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

int num_online_cpus() {
	return 22; // TODO: fixme
}


/* -----------------------------------------------------------------
 * Functions and data structures closer to the original paper as possible
 * -----------------------------------------------------------------
 */

#define time_v u64

/* client data structure */
typedef struct _client {
	int lag; /* client lag */
	int weight;

	time_v req_ve; /* virtual eligible time */
	time_v req_vd; /* virtual dead line */
	time_v req_min_vd; /* variable used in augmented data structure */

	bool joined;
	struct task_struct *p;
} client_struct;

void insert_req(client_struct *client);
time_v get_current_vt();
void delete_req(client_struct *client);
int allocate(client_struct *client);
void update_lag(client_struct *client, int used);
s64 compute_lag_adjustment(int lag, int weight);


/* global data */
time_v VirtualTime = 0; /* virtual time */
time_v QuantumSize = 10000000; /* 10ms - TODO: make it configurable */
int TotalWeight = 0; /* total weight of al l active clients */

void issue_new_request(client_struct *client)
{
	client->req_ve = VirtualTime;
	client->req_vd = client->req_ve + QuantumSize/(u64)client->weight;
	insert_req(client);
}

/* join competition */
static void join(client_struct *client)
{
	/* update total weight of al l active clients */
	TotalWeight += client->weight;
	/* update virtual time according to client lag */
	VirtualTime = get_current_vt() - compute_lag_adjustment(client->lag, TotalWeight);
	/* issue request */
	issue_new_request(client);
}

/* leave competition */
void leave(client_struct *client)
{
	/* update total weight of al l active clients */
	TotalWeight -= client->weight;
	/* update virtual time according to client lag */
	VirtualTime = get_current_vt() + compute_lag_adjustment(client->lag, TotalWeight);
	/* delete request */
	delete_req(client);
}

/* change client weight */
void change_weight(client_struct *client, int new_weight)
{
	/* partial update virtual time according to client lag */
	VirtualTime = get_current_vt() + compute_lag_adjustment(client->lag, TotalWeight - client->weight);
	/* update total weight of al l active clients */
	TotalWeight += new_weight - client->weight;
	/* update client's weight */
	client->weight = new_weight;
	/* update virtual time */
	VirtualTime -= compute_lag_adjustment(client->lag, TotalWeight);
}

/* dispatch function */
void EEVDF_dispatch(client_struct *client)
{
	int used;
	/* get eligible request with earliest virtual dead line */
	//client = get_req(get_curreent_vt()); // we don't need to do this, the queue takes care of it
	/* allocate resource to client with earliest eligible virtual dead line */
	used = allocate(client);
	/* update client's lag */
	update_lag(client, used);
	/* current request has been fulfilled; delete it */
	delete_req(client);
	/* issue new request */
	issue_new_request(client);
}

/* -----------------------------------------------------------------
 * non provided functions from the original paper
 * -----------------------------------------------------------------
 */

time_v last_t = 0;

#define SHARED_DSQ 0

time_v get_current_vt()
{
	time_v now = bpf_ktime_get_ns();
	time_v delta = now - last_t;
	last_t = now;

	/* Small tweak to consider the number of cpus */
	VirtualTime += (u64)num_online_cpus()*delta/(u64)TotalWeight;
	return VirtualTime;
}
void insert_req(client_struct *client)
{
	scx_bpf_dsq_insert_vtime(client->p, SHARED_DSQ, QuantumSize, client->req_vd, 0);
}

void delete_req(client_struct *client)
{
	/* there is no way to remove it from the DSQ */
}

int allocate(client_struct *client)
{
	return QuantumSize - client->p->scx.slice;
}

void update_lag(client_struct *client, int used)
{
	client->lag = QuantumSize - used;
}

/* Calculate VirtualTime adjustment based on client lag and weight
 * Returns signed adjustment value: positive if lag is positive, negative if lag is negative
 */
s64 compute_lag_adjustment(int lag, int weight)
{
	u64 lag_abs;
	u64 adjustment_abs;

	lag_abs = lag < 0 ? (u64)-lag : (u64)lag;
	adjustment_abs = (u64)num_online_cpus() * lag_abs / (u64)weight;

	return lag < 0 ? -(s64)adjustment_abs : (s64)adjustment_abs;
}

/* -----------------------------------------------------------------
 * bpf specifics
 * -----------------------------------------------------------------
 */

struct stats {
	time_v VirtualTime;
	time_v TotalWeight;
	u64 n_enqueued;
	u64 n_dispatched;
	u64 n_joined;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(struct stats));
	__uint(max_entries, 1);
 } stats_map SEC(".maps");

static void stat_update(int n_enqueued, int n_dispatched, int n_joined)
{
	__u32 key = 0;
	struct stats *stats = bpf_map_lookup_elem(&stats_map, &key);
	if (!stats) {
		scx_bpf_error("Failed to lookup stats");
		return;
	}
	stats->VirtualTime = VirtualTime;
	stats->TotalWeight = TotalWeight;
	stats->n_enqueued += n_enqueued;
	stats->n_dispatched += n_dispatched;
	stats->n_joined += n_joined;
 }

/*
 * According to the comment on scx_simple.bpf.c, the SCX_DSQ_GLOBAL cannot be
 * used with vtime, so we create a separate DSQ.
 */


UEI_DEFINE(uei);

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, client_struct);
} client_map SEC(".maps");

void BPF_STRUCT_OPS(eevdf_enqueue, struct task_struct *p, u64 enq_flags)
{
    client_struct *client = bpf_task_storage_get(&client_map, p, 0, 0);
    if (!client) {
        scx_bpf_error("Failed to get client");
        return;
    }
    if (!client->joined) {
	client->p = p;
	client->joined = true;
	join(client);
	stat_update(1, 0, 1);
	return;
    }

    EEVDF_dispatch(client);
    stat_update(1, 0, 0);
}

void BPF_STRUCT_OPS(eevdf_quiescent, struct task_struct *p, u64 deq_flags)
{
	client_struct *client = bpf_task_storage_get(&client_map, p, 0, 0);

	if (!(deq_flags & SCX_DEQ_SLEEP)) {
		leave(client);
		client->joined = false;
		stat_update(0, 0, -1);
	}
}

void BPF_STRUCT_OPS(eevdf_enable, struct task_struct *p)
{
	client_struct *client = bpf_task_storage_get(&client_map, p, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	client->p = p;
	client->lag = 0;
	client->weight = p->scx.weight;
	client->joined = false;
}

void BPF_STRUCT_OPS(eevdf_dispatch, s32 cpu, struct task_struct *prev)
{
	scx_bpf_dsq_move_to_local(SHARED_DSQ);
	stat_update(0, 1, 0);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(eevdf_init)
{
	return scx_bpf_create_dsq(SHARED_DSQ, -1);
}

void BPF_STRUCT_OPS(eevdf_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(eevdf_ops,
	       .enqueue		= (void *)eevdf_enqueue,
	       .dispatch		= (void *)eevdf_dispatch,
	       .quiescent	= (void *)eevdf_quiescent,
	       .enable		= (void *)eevdf_enable,
	       .init		= (void *)eevdf_init,
	       .exit		= (void *)eevdf_exit,
	       .name		= "eevdf");

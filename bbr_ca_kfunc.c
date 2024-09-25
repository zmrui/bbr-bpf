// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Facebook */

#include "vmlinux.h"
#include <bpf/bpf_tracing.h>

extern void bbr_init(struct sock *sk) __ksym;
extern void bbr_main(struct sock *sk, u32 ack, int flag, const struct rate_sample *rs) __ksym;
extern u32 bbr_sndbuf_expand(struct sock *sk) __ksym;
extern u32 bbr_undo_cwnd(struct sock *sk) __ksym;
extern void bbr_cwnd_event(struct sock *sk, enum tcp_ca_event event) __ksym;
extern u32 bbr_ssthresh(struct sock *sk) __ksym;
extern u32 bbr_min_tso_segs(struct sock *sk) __ksym;
extern void bbr_set_state(struct sock *sk, u8 new_state) __ksym;

SEC("struct_ops")
void BPF_PROG(init, struct sock *sk)
{
	bbr_init(sk);
}


SEC("struct_ops")
void BPF_PROG(cong_control, struct sock *sk, u32 ack, int flag, const struct rate_sample *rs)
{
	bbr_main(sk, ack, flag, rs);
}


SEC("struct_ops")
u32 BPF_PROG(sndbuf_expand, struct sock *sk)
{
	return bbr_sndbuf_expand(sk);
}

SEC("struct_ops")
u32 BPF_PROG(undo_cwnd, struct sock *sk)
{
	return bbr_undo_cwnd(sk);
}

SEC("struct_ops")
void BPF_PROG(cwnd_event, struct sock *sk, enum tcp_ca_event event)
{
	bbr_cwnd_event(sk, event);
}

SEC("struct_ops")
u32 BPF_PROG(ssthresh, struct sock *sk)
{
	return bbr_ssthresh(sk);
}

SEC("struct_ops")
u32 BPF_PROG(min_tso_segs, struct sock *sk)
{
	return bbr_min_tso_segs(sk);
}

SEC("struct_ops")
void BPF_PROG(set_state, struct sock *sk, u8 new_state)
{
	bbr_set_state(sk, new_state);
}


SEC(".struct_ops")
struct tcp_congestion_ops tcp_ca_kfunc = {
	.init		= (void *)init,
	.cong_control	= (void *)cong_control,
	.sndbuf_expand	= (void *)sndbuf_expand,
	.undo_cwnd	= (void *)undo_cwnd,
	.cwnd_event	= (void *)cwnd_event,
	.ssthresh	= (void *)ssthresh,
	.min_tso_segs	= (void *)min_tso_segs,
	.set_state	= (void *)set_state,
	.name		= "tcp_ca_kfunc",
};

char _license[] SEC("license") = "GPL";

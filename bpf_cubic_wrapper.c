#include "bpf_tracing_net.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

extern void cubictcp_init(struct sock *sk) __ksym;
extern void cubictcp_cwnd_event(struct sock *sk, enum tcp_ca_event event) __ksym;
extern __u32 cubictcp_recalc_ssthresh(struct sock *sk) __ksym;
extern void cubictcp_state(struct sock *sk, __u8 new_state) __ksym;
extern __u32 tcp_reno_undo_cwnd(struct sock *sk) __ksym;
extern void cubictcp_acked(struct sock *sk, const struct ack_sample *sample) __ksym;
extern void cubictcp_cong_avoid(struct sock *sk, __u32 ack, __u32 acked) __ksym;


SEC("struct_ops")
void BPF_PROG(bpf_cubic_init, struct sock *sk)
{
	cubictcp_init(sk);
}

SEC("struct_ops")
u32 BPF_PROG(bpf_cubictcp_recalc_ssthresh, struct sock *sk)
{
	return cubictcp_recalc_ssthresh(sk);
}

SEC("struct_ops")
void BPF_PROG(bpf_cubictcp_cong_avoid, struct sock *sk, __u32 ack, __u32 acked)
{
	cubictcp_cong_avoid(sk, ack, acked);
}

SEC("struct_ops")
void BPF_PROG(bpf_cubictcp_state, struct sock *sk, __u8 new_state)
{
	cubictcp_state(sk, new_state);
}

SEC("struct_ops")
void BPF_PROG(bpf_cubictcp_cwnd_event, struct sock *sk, enum tcp_ca_event event)
{
	cubictcp_cwnd_event(sk, event);

}

SEC("struct_ops")
__u32 BPF_PROG(bpf_cubic_undo_cwnd, struct sock *sk)
{
	return tcp_reno_undo_cwnd(sk);
}

SEC("struct_ops")
void BPF_PROG(bpf_cubictcp_acked, struct sock *sk, const struct ack_sample *sample)
{
	cubictcp_acked(sk, sample);
}

SEC(".struct_ops")
struct tcp_congestion_ops simple_cubic_ops = {
	.init		= (void *) bpf_cubic_init,
	.ssthresh	= (void *) bpf_cubictcp_recalc_ssthresh,
	.cong_avoid	= (void *) bpf_cubictcp_cong_avoid,
	.set_state	= (void *) bpf_cubictcp_state,
	.undo_cwnd	= (void *) bpf_cubic_undo_cwnd,
	.cwnd_event	= (void *) bpf_cubictcp_cwnd_event,
	.pkts_acked     = (void *) bpf_cubictcp_acked,
	// .owner		= THIS_MODULE,
	.name		= "cubic_wrp",
};
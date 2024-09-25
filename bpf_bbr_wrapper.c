#include "vmlinux.h"
#include <bpf/bpf_tracing.h>


// extern unsigned long CONFIG_HZ __kconfig;
// #define HZ CONFIG_HZ
// #define USEC_PER_MSEC	1000UL
// #define USEC_PER_SEC	1000000UL
// #define USEC_PER_JIFFY	(USEC_PER_SEC / HZ)
// #define NSEC_PER_USEC	1000L
// #define MSEC_PER_SEC	1000L
// #define GSO_LEGACY_MAX_SIZE	65536u
// #define LL_MAX_HEADER 32
// #define MAX_HEADER LL_MAX_HEADER
// #define MAX_TCP_HEADER	(128 + MAX_HEADER)
// #define TCP_INIT_CWND		10
// #define TCP_INFINITE_SSTHRESH	0x7fffffff

// #define WRITE_ONCE(x, val) ((*(volatile typeof(x) *) &(x)) = (val))
// #define READ_ONCE(x) (*(volatile typeof(x) *)&(x))
// #define unlikely(cond) (cond)
// #define clamp(val, lo, hi) min((typeof(val))max(val, lo), hi)
// #define min(a, b) ((a) < (b) ? (a) : (b))
// #define max(a, b) ((a) > (b) ? (a) : (b))
// static bool before(__u32 seq1, __u32 seq2)
// {
// 	return (__s32)(seq1-seq2) < 0;
// }
// #define after(seq2, seq1) 	before(seq1, seq2)
// #define max_t(type, x, y)	max((type)x, (type)y)
// #define min_t(type, x, y)	min((type)x, (type)y)

// u32 myabs(u32 a, u32 b){
// 	if (a > b)
// 		return a - b;
// 	else
// 		return b - a;
// }

// u32 div(u64* numer, int denom)
// {
//   u64 res  = *numer / denom;
//   u32 rem = *numer % denom;
//   *numer = res;
//   return rem;
// }
// #define do_div(n, base) div(&n, base);

// static inline u64 div_u64_rem(u64 dividend, u32 divisor, u32 *remainder)
// {
// 	*remainder = dividend % divisor;
// 	return dividend / divisor;
// }
// static inline u64 div_u64(u64 dividend, u32 divisor)
// {
// 	u32 remainder;
// 	return div_u64_rem(dividend, divisor, &remainder);
// }

// s64 sdiv(s64 a, s64 b) {
// 	// https://stackoverflow.com/questions/74227051/is-there-a-way-to-perform-signed-division-in-ebpf
//     bool aneg = a < 0;
//     bool bneg = b < 0;
//     // get the absolute positive value of both
//     u64 adiv = aneg ? -a : a;
//     u64 bdiv = bneg ? -b : b;
//     // Do udiv
//     u64 out = adiv / bdiv;
//     // Make output negative if one or the other is negative, not both
//     return aneg != bneg ? -out : out;
// }

// static inline s64 div64_s64(s64 dividend, s64 divisor)
// {
// 	return sdiv(dividend, divisor);
// }
// #define div64_long(x, y) div64_s64((x), (y))

// u32 cmpxchg(u32 * ptr, u32 old, u32 new){
//   if (*ptr == old){
//     *ptr = new;
//     return old;
//   }
//   else{
//     return new;
//   }
// }
// static u32 tcp_left_out(const struct tcp_sock *tp){
// 	return tp->sacked_out + tp->lost_out;
// }

// static u32 tcp_packets_in_flight(const struct tcp_sock *tp){
// 	return tp->packets_out - tcp_left_out(tp) + tp->retrans_out;
// }

// u32 tcp_stamp_us_delta(u64 t1, u64 t0){
// 	return max_t(s64, t1 - t0, 0);
// }

// u32 get_random_u32_below(u32 ceil){
// 	if(ceil > 0)
// 		return ceil -1;
// 	else
// 		return 0;
// }

// u32 minmax_get(const struct minmax *m){
// 	return m->s[0].v;
// }

// u32 tcp_min_rtt(const struct tcp_sock *tp){
// 	return minmax_get(&tp->rtt_min);
// }

// unsigned long msecs_to_jiffies(const unsigned int m)
// {
// 	return (m + (MSEC_PER_SEC / HZ) - 1) / (MSEC_PER_SEC / HZ);
// }

// u32 tcp_snd_cwnd(const struct tcp_sock *tp){
// 	return tp->snd_cwnd;
// }

// void tcp_snd_cwnd_set(struct tcp_sock *tp, u32 val){
// 	tp->snd_cwnd = val;
// }

// u32 minmax_reset(struct minmax *m, u32 t, u32 meas)
// {
// 	struct minmax_sample val = { .t = t, .v = meas };

// 	m->s[2] = m->s[1] = m->s[0] = val;
// 	return m->s[0].v;
// }
// u32 minmax_subwin_update(struct minmax *m, u32 win,
// 				const struct minmax_sample *val)
// {
// 	u32 dt = val->t - m->s[0].t;

// 	if (unlikely(dt > win)) {
// 		/*
// 		 * Passed entire window without a new val so make 2nd
// 		 * choice the new val & 3rd choice the new 2nd choice.
// 		 * we may have to iterate this since our 2nd choice
// 		 * may also be outside the window (we checked on entry
// 		 * that the third choice was in the window).
// 		 */
// 		m->s[0] = m->s[1];
// 		m->s[1] = m->s[2];
// 		m->s[2] = *val;
// 		if (unlikely(val->t - m->s[0].t > win)) {
// 			m->s[0] = m->s[1];
// 			m->s[1] = m->s[2];
// 			m->s[2] = *val;
// 		}
// 	} else if (unlikely(m->s[1].t == m->s[0].t) && dt > win/4) {
// 		/*
// 		 * We've passed a quarter of the window without a new val
// 		 * so take a 2nd choice from the 2nd quarter of the window.
// 		 */
// 		m->s[2] = m->s[1] = *val;
// 	} else if (unlikely(m->s[2].t == m->s[1].t) && dt > win/2) {
// 		/*
// 		 * We've passed half the window without finding a new val
// 		 * so take a 3rd choice from the last half of the window
// 		 */
// 		m->s[2] = *val;
// 	}
// 	return m->s[0].v;
// }

// u32 minmax_running_max(struct minmax *m, u32 win, u32 t, u32 meas)
// {
// 	struct minmax_sample val = { .t = t, .v = meas };

// 	if (unlikely(val.v >= m->s[0].v) ||	  /* found new max? */
// 	    unlikely(val.t - m->s[2].t > win))	  /* nothing left in window? */
// 		return minmax_reset(m, t, meas);  /* forget earlier samples */

// 	if (unlikely(val.v >= m->s[1].v))
// 		m->s[2] = m->s[1] = val;
// 	else if (unlikely(val.v >= m->s[2].v))
// 		m->s[2] = val;

// 	return minmax_subwin_update(m, win, &val);
// }

// char _license[] SEC("license") = "GPL";

// /* Scale factor for rate in pkt/uSec unit to avoid truncation in bandwidth
//  * estimation. The rate unit ~= (1500 bytes / 1 usec / 2^24) ~= 715 bps.
//  * This handles bandwidths from 0.06pps (715bps) to 256Mpps (3Tbps) in a u32.
//  * Since the minimum window is >=4 packets, the lower bound isn't
//  * an issue. The upper bound isn't an issue with existing technologies.
//  */
// #define BW_SCALE 24
// #define BW_UNIT (1 << BW_SCALE)

// #define BBR_SCALE 8	/* scaling factor for fractions in BBR (e.g. gains) */
// #define BBR_UNIT (1 << BBR_SCALE)

// /* BBR has the following modes for deciding how fast to send: */
// enum bbr_mode {
// 	BBR_STARTUP,	/* ramp up sending rate rapidly to fill pipe */
// 	BBR_DRAIN,	/* drain any queue created during startup */
// 	BBR_PROBE_BW,	/* discover, share bw: pace around estimated bw */
// 	BBR_PROBE_RTT,	/* cut inflight to min to probe min_rtt */
// };

// /* BBR congestion control block */
// struct bbr {
// 	u32	min_rtt_us;	        /* min RTT in min_rtt_win_sec window */
// 	u32	min_rtt_stamp;	        /* timestamp of min_rtt_us */
// 	u32	probe_rtt_done_stamp;   /* end time for BBR_PROBE_RTT mode */
// 	struct minmax bw;	/* Max recent delivery rate in pkts/uS << 24 */
// 	u32	rtt_cnt;	    /* count of packet-timed rounds elapsed */
// 	u32     next_rtt_delivered; /* scb->tx.delivered at end of round */
// 	u64	cycle_mstamp;	     /* time of this cycle phase start */
// 	u32     mode:3,		     /* current bbr_mode in state machine */
// 		prev_ca_state:3,     /* CA state on previous ACK */
// 		packet_conservation:1,  /* use packet conservation? */
// 		round_start:1,	     /* start of packet-timed tx->ack round? */
// 		idle_restart:1,	     /* restarting after idle? */
// 		probe_rtt_round_done:1,  /* a BBR_PROBE_RTT round at 4 pkts? */
// 		unused:13,
// 		lt_is_sampling:1,    /* taking long-term ("LT") samples now? */
// 		lt_rtt_cnt:7,	     /* round trips in long-term interval */
// 		lt_use_bw:1;	     /* use lt_bw as our bw estimate? */
// 	u32	lt_bw;		     /* LT est delivery rate in pkts/uS << 24 */
// 	u32	lt_last_delivered;   /* LT intvl start: tp->delivered */
// 	u32	lt_last_stamp;	     /* LT intvl start: tp->delivered_mstamp */
// 	u32	lt_last_lost;	     /* LT intvl start: tp->lost */
// 	u32	pacing_gain:10,	/* current gain for setting pacing rate */
// 		cwnd_gain:10,	/* current gain for setting cwnd */
// 		full_bw_reached:1,   /* reached full bw in Startup? */
// 		full_bw_cnt:2,	/* number of rounds without large bw gains */
// 		cycle_idx:3,	/* current index in pacing_gain cycle array */
// 		has_seen_rtt:1, /* have we seen an RTT sample yet? */
// 		unused_b:5;
// 	u32	prior_cwnd;	/* prior cwnd upon entering loss recovery */
// 	u32	full_bw;	/* recent bw, to estimate if pipe is full */

// 	/* For tracking ACK aggregation: */
// 	u64	ack_epoch_mstamp;	/* start of ACK sampling epoch */
// 	u16	extra_acked[2];		/* max excess data ACKed in epoch */
// 	u32	ack_epoch_acked:20,	/* packets (S)ACKed in sampling epoch */
// 		extra_acked_win_rtts:5,	/* age of extra_acked, in round trips */
// 		extra_acked_win_idx:1,	/* current index in extra_acked array */
// 		unused_c:6;
// };

// #define CYCLE_LEN	8	/* number of phases in a pacing gain cycle */

// /* Window length of bw filter (in rounds): */
// static const int bbr_bw_rtts = CYCLE_LEN + 2;
// /* Window length of min_rtt filter (in sec): */
// static const u32 bbr_min_rtt_win_sec = 10;
// /* Minimum time (in ms) spent at bbr_cwnd_min_target in BBR_PROBE_RTT mode: */
// static const u32 bbr_probe_rtt_mode_ms = 200;
// /* Skip TSO below the following bandwidth (bits/sec): */
// static const int bbr_min_tso_rate = 1200000;

// /* Pace at ~1% below estimated bw, on average, to reduce queue at bottleneck.
//  * In order to help drive the network toward lower queues and low latency while
//  * maintaining high utilization, the average pacing rate aims to be slightly
//  * lower than the estimated bandwidth. This is an important aspect of the
//  * design.
//  */
// static const int bbr_pacing_margin_percent = 1;

// /* We use a high_gain value of 2/ln(2) because it's the smallest pacing gain
//  * that will allow a smoothly increasing pacing rate that will double each RTT
//  * and send the same number of packets per RTT that an un-paced, slow-starting
//  * Reno or CUBIC flow would:
//  */
// static const int bbr_high_gain  = BBR_UNIT * 2885 / 1000 + 1;
// /* The pacing gain of 1/high_gain in BBR_DRAIN is calculated to typically drain
//  * the queue created in BBR_STARTUP in a single round:
//  */
// static const int bbr_drain_gain = BBR_UNIT * 1000 / 2885;
// /* The gain for deriving steady-state cwnd tolerates delayed/stretched ACKs: */
// static const int bbr_cwnd_gain  = BBR_UNIT * 2;
// /* The pacing_gain values for the PROBE_BW gain cycle, to discover/share bw: */
// static const int bbr_pacing_gain[] = {
// 	BBR_UNIT * 5 / 4,	/* probe for more available bw */
// 	BBR_UNIT * 3 / 4,	/* drain queue and/or yield bw to other flows */
// 	BBR_UNIT, BBR_UNIT, BBR_UNIT,	/* cruise at 1.0*bw to utilize pipe, */
// 	BBR_UNIT, BBR_UNIT, BBR_UNIT	/* without creating excess queue... */
// };
// /* Randomize the starting gain cycling phase over N phases: */
// static const u32 bbr_cycle_rand = 7;

// /* Try to keep at least this many packets in flight, if things go smoothly. For
//  * smooth functioning, a sliding window protocol ACKing every other packet
//  * needs at least 4 packets in flight:
//  */
// static const u32 bbr_cwnd_min_target = 4;

// /* To estimate if BBR_STARTUP mode (i.e. high_gain) has filled pipe... */
// /* If bw has increased significantly (1.25x), there may be more bw available: */
// static const u32 bbr_full_bw_thresh = BBR_UNIT * 5 / 4;
// /* But after 3 rounds w/o significant bw growth, estimate pipe is full: */
// static const u32 bbr_full_bw_cnt = 3;

// /* "long-term" ("LT") bandwidth estimator parameters... */
// /* The minimum number of rounds in an LT bw sampling interval: */
// static const u32 bbr_lt_intvl_min_rtts = 4;
// /* If lost/delivered ratio > 20%, interval is "lossy" and we may be policed: */
// static const u32 bbr_lt_loss_thresh = 50;
// /* If 2 intervals have a bw ratio <= 1/8, their bw is "consistent": */
// static const u32 bbr_lt_bw_ratio = BBR_UNIT / 8;
// /* If 2 intervals have a bw diff <= 4 Kbit/sec their bw is "consistent": */
// static const u32 bbr_lt_bw_diff = 4000 / 8;
// /* If we estimate we're policed, use lt_bw for this many round trips: */
// static const u32 bbr_lt_bw_max_rtts = 48;

// /* Gain factor for adding extra_acked to target cwnd: */
// static const int bbr_extra_acked_gain = BBR_UNIT;
// /* Window length of extra_acked window. */
// static const u32 bbr_extra_acked_win_rtts = 5;
// /* Max allowed val for ack_epoch_acked, after which sampling epoch is reset */
// static const u32 bbr_ack_epoch_acked_reset_thresh = 1U << 20;
// /* Time period for clamping cwnd increment due to ack aggregation */
// static const u32 bbr_extra_acked_max_us = 100 * 1000;

// static void bbr_check_probe_rtt_done(struct sock *sk);

// /* Do we estimate that STARTUP filled the pipe? */
// static bool bbr_full_bw_reached(const struct sock *sk)
// {
// 	const struct bbr *bbr = inet_csk_ca(sk);

// 	return bbr->full_bw_reached;
// }

// /* Return the windowed max recent bandwidth sample, in pkts/uS << BW_SCALE. */
// static u32 bbr_max_bw(const struct sock *sk)
// {
// 	struct bbr *bbr = inet_csk_ca(sk);

// 	return minmax_get(&bbr->bw);
// }

// /* Return the estimated bandwidth of the path, in pkts/uS << BW_SCALE. */
// static u32 bbr_bw(const struct sock *sk)
// {
// 	struct bbr *bbr = inet_csk_ca(sk);

// 	return bbr->lt_use_bw ? bbr->lt_bw : bbr_max_bw(sk);
// }

// /* Return maximum extra acked in past k-2k round trips,
//  * where k = bbr_extra_acked_win_rtts.
//  */
// static u16 bbr_extra_acked(const struct sock *sk)
// {
// 	struct bbr *bbr = inet_csk_ca(sk);

// 	return max(bbr->extra_acked[0], bbr->extra_acked[1]);
// }

// /* Return rate in bytes per second, optionally with a gain.
//  * The order here is chosen carefully to avoid overflow of u64. This should
//  * work for input rates of up to 2.9Tbit/sec and gain of 2.89x.
//  */
// static u64 bbr_rate_bytes_per_sec(struct sock *sk, u64 rate, int gain)
// {
// 	unsigned int mss = tcp_sk(sk)->mss_cache;

// 	rate *= mss;
// 	rate *= gain;
// 	rate >>= BBR_SCALE;
// 	rate *= USEC_PER_SEC / 100 * (100 - bbr_pacing_margin_percent);
// 	return rate >> BW_SCALE;
// }

// /* Convert a BBR bw and gain factor to a pacing rate in bytes per second. */
// static unsigned long bbr_bw_to_pacing_rate(struct sock *sk, u32 bw, int gain)
// {
// 	u64 rate = bw;

// 	rate = bbr_rate_bytes_per_sec(sk, rate, gain);
// 	rate = min_t(u64, rate, READ_ONCE(sk->sk_max_pacing_rate));
// 	return rate;
// }

// /* Initialize pacing rate to: high_gain * init_cwnd / RTT. */
// static void bbr_init_pacing_rate_from_rtt(struct sock *sk)
// {
// 	struct tcp_sock *tp = tcp_sk(sk);
// 	struct bbr *bbr = inet_csk_ca(sk);
// 	u64 bw;
// 	u32 rtt_us;

// 	if (tp->srtt_us) {		/* any RTT sample yet? */
// 		rtt_us = max(tp->srtt_us >> 3, 1U);
// 		bbr->has_seen_rtt = 1;
// 	} else {			 /* no RTT sample yet */
// 		rtt_us = USEC_PER_MSEC;	 /* use nominal default RTT */
// 	}
// 	bw = (u64)tcp_snd_cwnd(tp) * BW_UNIT;
// 	do_div(bw, rtt_us);
// 	WRITE_ONCE(sk->sk_pacing_rate,
// 		   bbr_bw_to_pacing_rate(sk, bw, bbr_high_gain));
// }

// /* Pace using current bw estimate and a gain factor. */
// static void bbr_set_pacing_rate(struct sock *sk, u32 bw, int gain)
// {
// 	struct tcp_sock *tp = tcp_sk(sk);
// 	struct bbr *bbr = inet_csk_ca(sk);
// 	unsigned long rate = bbr_bw_to_pacing_rate(sk, bw, gain);

// 	if (unlikely(!bbr->has_seen_rtt && tp->srtt_us))
// 		bbr_init_pacing_rate_from_rtt(sk);
// 	if (bbr_full_bw_reached(sk) || rate > READ_ONCE(sk->sk_pacing_rate))
// 		WRITE_ONCE(sk->sk_pacing_rate, rate);
// }

// /* override sysctl_tcp_min_tso_segs */
// static u32 dup_bbr_min_tso_segs(struct sock *sk)
// {
// 	return READ_ONCE(sk->sk_pacing_rate) < (bbr_min_tso_rate >> 3) ? 1 : 2;
// }



// static u32 bbr_tso_segs_goal(struct sock *sk)
// {
// 	struct tcp_sock *tp = tcp_sk(sk);
// 	u32 segs, bytes;

// 	/* Sort of tcp_tso_autosize() but ignoring
// 	 * driver provided sk_gso_max_size.
// 	 */
// 	bytes = min_t(unsigned long,
// 		      READ_ONCE(sk->sk_pacing_rate) >> READ_ONCE(sk->sk_pacing_shift),
// 		      GSO_LEGACY_MAX_SIZE - 1 - MAX_TCP_HEADER);
// 	segs = max_t(u32, bytes / tp->mss_cache, dup_bbr_min_tso_segs(sk));

// 	return min(segs, 0x7FU);
// }

// /* Save "last known good" cwnd so we can restore it after losses or PROBE_RTT */
// static void bbr_save_cwnd(struct sock *sk)
// {
// 	struct tcp_sock *tp = tcp_sk(sk);
// 	struct bbr *bbr = inet_csk_ca(sk);

// 	if (bbr->prev_ca_state < TCP_CA_Recovery && bbr->mode != BBR_PROBE_RTT)
// 		bbr->prior_cwnd = tcp_snd_cwnd(tp);  /* this cwnd is good enough */
// 	else  /* loss recovery or BBR_PROBE_RTT have temporarily cut cwnd */
// 		bbr->prior_cwnd = max(bbr->prior_cwnd, tcp_snd_cwnd(tp));
// }



// /* Calculate bdp based on min RTT and the estimated bottleneck bandwidth:
//  *
//  * bdp = ceil(bw * min_rtt * gain)
//  *
//  * The key factor, gain, controls the amount of queue. While a small gain
//  * builds a smaller queue, it becomes more vulnerable to noise in RTT
//  * measurements (e.g., delayed ACKs or other ACK compression effects). This
//  * noise may cause BBR to under-estimate the rate.
//  */
// static u32 bbr_bdp(struct sock *sk, u32 bw, int gain)
// {
// 	struct bbr *bbr = inet_csk_ca(sk);
// 	u32 bdp;
// 	u64 w;

// 	/* If we've never had a valid RTT sample, cap cwnd at the initial
// 	 * default. This should only happen when the connection is not using TCP
// 	 * timestamps and has retransmitted all of the SYN/SYNACK/data packets
// 	 * ACKed so far. In this case, an RTO can cut cwnd to 1, in which
// 	 * case we need to slow-start up toward something safe: TCP_INIT_CWND.
// 	 */
// 	if (unlikely(bbr->min_rtt_us == ~0U))	 /* no valid RTT samples yet? */
// 		return TCP_INIT_CWND;  /* be safe: cap at default initial cwnd*/

// 	w = (u64)bw * bbr->min_rtt_us;

// 	/* Apply a gain to the given value, remove the BW_SCALE shift, and
// 	 * round the value up to avoid a negative feedback loop.
// 	 */
// 	bdp = (((w * gain) >> BBR_SCALE) + BW_UNIT - 1) / BW_UNIT;

// 	return bdp;
// }

// /* To achieve full performance in high-speed paths, we budget enough cwnd to
//  * fit full-sized skbs in-flight on both end hosts to fully utilize the path:
//  *   - one skb in sending host Qdisc,
//  *   - one skb in sending host TSO/GSO engine
//  *   - one skb being received by receiver host LRO/GRO/delayed-ACK engine
//  * Don't worry, at low rates (bbr_min_tso_rate) this won't bloat cwnd because
//  * in such cases tso_segs_goal is 1. The minimum cwnd is 4 packets,
//  * which allows 2 outstanding 2-packet sequences, to try to keep pipe
//  * full even with ACK-every-other-packet delayed ACKs.
//  */
// static u32 bbr_quantization_budget(struct sock *sk, u32 cwnd)
// {
// 	struct bbr *bbr = inet_csk_ca(sk);

// 	/* Allow enough full-sized skbs in flight to utilize end systems. */
// 	cwnd += 3 * bbr_tso_segs_goal(sk);

// 	/* Reduce delayed ACKs by rounding up cwnd to the next even number. */
// 	cwnd = (cwnd + 1) & ~1U;

// 	/* Ensure gain cycling gets inflight above BDP even for small BDPs. */
// 	if (bbr->mode == BBR_PROBE_BW && bbr->cycle_idx == 0)
// 		cwnd += 2;

// 	return cwnd;
// }

// /* Find inflight based on min RTT and the estimated bottleneck bandwidth. */
// static u32 bbr_inflight(struct sock *sk, u32 bw, int gain)
// {
// 	u32 inflight;

// 	inflight = bbr_bdp(sk, bw, gain);
// 	inflight = bbr_quantization_budget(sk, inflight);

// 	return inflight;
// }

// /* With pacing at lower layers, there's often less data "in the network" than
//  * "in flight". With TSQ and departure time pacing at lower layers (e.g. fq),
//  * we often have several skbs queued in the pacing layer with a pre-scheduled
//  * earliest departure time (EDT). BBR adapts its pacing rate based on the
//  * inflight level that it estimates has already been "baked in" by previous
//  * departure time decisions. We calculate a rough estimate of the number of our
//  * packets that might be in the network at the earliest departure time for the
//  * next skb scheduled:
//  *   in_network_at_edt = inflight_at_edt - (EDT - now) * bw
//  * If we're increasing inflight, then we want to know if the transmit of the
//  * EDT skb will push inflight above the target, so inflight_at_edt includes
//  * bbr_tso_segs_goal() from the skb departing at EDT. If decreasing inflight,
//  * then estimate if inflight will sink too low just before the EDT transmit.
//  */
// static u32 bbr_packets_in_net_at_edt(struct sock *sk, u32 inflight_now)
// {
// 	struct tcp_sock *tp = tcp_sk(sk);
// 	struct bbr *bbr = inet_csk_ca(sk);
// 	u64 now_ns, edt_ns, interval_us;
// 	u32 interval_delivered, inflight_at_edt;

// 	now_ns = tp->tcp_clock_cache;
// 	edt_ns = max(tp->tcp_wstamp_ns, now_ns);
// 	interval_us = div_u64(edt_ns - now_ns, NSEC_PER_USEC);
// 	interval_delivered = (u64)bbr_bw(sk) * interval_us >> BW_SCALE;
// 	inflight_at_edt = inflight_now;
// 	if (bbr->pacing_gain > BBR_UNIT)              /* increasing inflight */
// 		inflight_at_edt += bbr_tso_segs_goal(sk);  /* include EDT skb */
// 	if (interval_delivered >= inflight_at_edt)
// 		return 0;
// 	return inflight_at_edt - interval_delivered;
// }

// /* Find the cwnd increment based on estimate of ack aggregation */
// static u32 bbr_ack_aggregation_cwnd(struct sock *sk)
// {
// 	u32 max_aggr_cwnd, aggr_cwnd = 0;

// 	if (bbr_extra_acked_gain && bbr_full_bw_reached(sk)) {
// 		max_aggr_cwnd = ((u64)bbr_bw(sk) * bbr_extra_acked_max_us)
// 				/ BW_UNIT;
// 		aggr_cwnd = (bbr_extra_acked_gain * bbr_extra_acked(sk))
// 			     >> BBR_SCALE;
// 		aggr_cwnd = min(aggr_cwnd, max_aggr_cwnd);
// 	}

// 	return aggr_cwnd;
// }

// /* An optimization in BBR to reduce losses: On the first round of recovery, we
//  * follow the packet conservation principle: send P packets per P packets acked.
//  * After that, we slow-start and send at most 2*P packets per P packets acked.
//  * After recovery finishes, or upon undo, we restore the cwnd we had when
//  * recovery started (capped by the target cwnd based on estimated BDP).
//  *
//  * TODO(ycheng/ncardwell): implement a rate-based approach.
//  */
// static bool bbr_set_cwnd_to_recover_or_restore(
// 	struct sock *sk, const struct rate_sample *rs, u32 acked, u32 *new_cwnd)
// {
// 	struct tcp_sock *tp = tcp_sk(sk);
// 	struct bbr *bbr = inet_csk_ca(sk);
// 	u8 prev_state = bbr->prev_ca_state, state = inet_csk(sk)->icsk_ca_state;
// 	u32 cwnd = tcp_snd_cwnd(tp);

// 	/* An ACK for P pkts should release at most 2*P packets. We do this
// 	 * in two steps. First, here we deduct the number of lost packets.
// 	 * Then, in bbr_set_cwnd() we slow start up toward the target cwnd.
// 	 */
// 	if (rs->losses > 0)
// 		cwnd = max_t(s32, cwnd - rs->losses, 1);

// 	if (state == TCP_CA_Recovery && prev_state != TCP_CA_Recovery) {
// 		/* Starting 1st round of Recovery, so do packet conservation. */
// 		bbr->packet_conservation = 1;
// 		bbr->next_rtt_delivered = tp->delivered;  /* start round now */
// 		/* Cut unused cwnd from app behavior, TSQ, or TSO deferral: */
// 		cwnd = tcp_packets_in_flight(tp) + acked;
// 	} else if (prev_state >= TCP_CA_Recovery && state < TCP_CA_Recovery) {
// 		/* Exiting loss recovery; restore cwnd saved before recovery. */
// 		cwnd = max(cwnd, bbr->prior_cwnd);
// 		bbr->packet_conservation = 0;
// 	}
// 	bbr->prev_ca_state = state;

// 	if (bbr->packet_conservation) {
// 		*new_cwnd = max(cwnd, tcp_packets_in_flight(tp) + acked);
// 		return true;	/* yes, using packet conservation */
// 	}
// 	*new_cwnd = cwnd;
// 	return false;
// }

// /* Slow-start up toward target cwnd (if bw estimate is growing, or packet loss
//  * has drawn us down below target), or snap down to target if we're above it.
//  */
// static void bbr_set_cwnd(struct sock *sk, const struct rate_sample *rs,
// 			 u32 acked, u32 bw, int gain)
// {
// 	struct tcp_sock *tp = tcp_sk(sk);
// 	struct bbr *bbr = inet_csk_ca(sk);
// 	u32 cwnd = tcp_snd_cwnd(tp), target_cwnd = 0;

// 	if (!acked)
// 		goto done;  /* no packet fully ACKed; just apply caps */

// 	if (bbr_set_cwnd_to_recover_or_restore(sk, rs, acked, &cwnd))
// 		goto done;

// 	target_cwnd = bbr_bdp(sk, bw, gain);

// 	/* Increment the cwnd to account for excess ACKed data that seems
// 	 * due to aggregation (of data and/or ACKs) visible in the ACK stream.
// 	 */
// 	target_cwnd += bbr_ack_aggregation_cwnd(sk);
// 	target_cwnd = bbr_quantization_budget(sk, target_cwnd);

// 	/* If we're below target cwnd, slow start cwnd toward target cwnd. */
// 	if (bbr_full_bw_reached(sk))  /* only cut cwnd if we filled the pipe */
// 		cwnd = min(cwnd + acked, target_cwnd);
// 	else if (cwnd < target_cwnd || tp->delivered < TCP_INIT_CWND)
// 		cwnd = cwnd + acked;
// 	cwnd = max(cwnd, bbr_cwnd_min_target);

// done:
// 	tcp_snd_cwnd_set(tp, min(cwnd, tp->snd_cwnd_clamp));	/* apply global cap */
// 	if (bbr->mode == BBR_PROBE_RTT)  /* drain queue, refresh min_rtt */
// 		tcp_snd_cwnd_set(tp, min(tcp_snd_cwnd(tp), bbr_cwnd_min_target));
// }

// /* End cycle phase if it's time and/or we hit the phase's in-flight target. */
// static bool bbr_is_next_cycle_phase(struct sock *sk,
// 				    const struct rate_sample *rs)
// {
// 	struct tcp_sock *tp = tcp_sk(sk);
// 	struct bbr *bbr = inet_csk_ca(sk);
// 	bool is_full_length =
// 		tcp_stamp_us_delta(tp->delivered_mstamp, bbr->cycle_mstamp) >
// 		bbr->min_rtt_us;
// 	u32 inflight, bw;

// 	/* The pacing_gain of 1.0 paces at the estimated bw to try to fully
// 	 * use the pipe without increasing the queue.
// 	 */
// 	if (bbr->pacing_gain == BBR_UNIT)
// 		return is_full_length;		/* just use wall clock time */

// 	inflight = bbr_packets_in_net_at_edt(sk, rs->prior_in_flight);
// 	bw = bbr_max_bw(sk);

// 	/* A pacing_gain > 1.0 probes for bw by trying to raise inflight to at
// 	 * least pacing_gain*BDP; this may take more than min_rtt if min_rtt is
// 	 * small (e.g. on a LAN). We do not persist if packets are lost, since
// 	 * a path with small buffers may not hold that much.
// 	 */
// 	if (bbr->pacing_gain > BBR_UNIT)
// 		return is_full_length &&
// 			(rs->losses ||  /* perhaps pacing_gain*BDP won't fit */
// 			 inflight >= bbr_inflight(sk, bw, bbr->pacing_gain));

// 	/* A pacing_gain < 1.0 tries to drain extra queue we added if bw
// 	 * probing didn't find more bw. If inflight falls to match BDP then we
// 	 * estimate queue is drained; persisting would underutilize the pipe.
// 	 */
// 	return is_full_length ||
// 		inflight <= bbr_inflight(sk, bw, BBR_UNIT);
// }

// static void bbr_advance_cycle_phase(struct sock *sk)
// {
// 	struct tcp_sock *tp = tcp_sk(sk);
// 	struct bbr *bbr = inet_csk_ca(sk);

// 	bbr->cycle_idx = (bbr->cycle_idx + 1) & (CYCLE_LEN - 1);
// 	bbr->cycle_mstamp = tp->delivered_mstamp;
// }

// /* Gain cycling: cycle pacing gain to converge to fair share of available bw. */
// static void bbr_update_cycle_phase(struct sock *sk,
// 				   const struct rate_sample *rs)
// {
// 	struct bbr *bbr = inet_csk_ca(sk);

// 	if (bbr->mode == BBR_PROBE_BW && bbr_is_next_cycle_phase(sk, rs))
// 		bbr_advance_cycle_phase(sk);
// }

// static void bbr_reset_startup_mode(struct sock *sk)
// {
// 	struct bbr *bbr = inet_csk_ca(sk);

// 	bbr->mode = BBR_STARTUP;
// }

// static void bbr_reset_probe_bw_mode(struct sock *sk)
// {
// 	struct bbr *bbr = inet_csk_ca(sk);

// 	bbr->mode = BBR_PROBE_BW;
// 	bbr->cycle_idx = CYCLE_LEN - 1 - get_random_u32_below(bbr_cycle_rand);
// 	bbr_advance_cycle_phase(sk);	/* flip to next phase of gain cycle */
// }

// static void bbr_reset_mode(struct sock *sk)
// {
// 	if (!bbr_full_bw_reached(sk))
// 		bbr_reset_startup_mode(sk);
// 	else
// 		bbr_reset_probe_bw_mode(sk);
// }

// /* Start a new long-term sampling interval. */
// static void bbr_reset_lt_bw_sampling_interval(struct sock *sk)
// {
// 	struct tcp_sock *tp = tcp_sk(sk);
// 	struct bbr *bbr = inet_csk_ca(sk);

// 	bbr->lt_last_stamp = div_u64(tp->delivered_mstamp, USEC_PER_MSEC);
// 	bbr->lt_last_delivered = tp->delivered;
// 	bbr->lt_last_lost = tp->lost;
// 	bbr->lt_rtt_cnt = 0;
// }

// /* Completely reset long-term bandwidth sampling. */
// static void bbr_reset_lt_bw_sampling(struct sock *sk)
// {
// 	struct bbr *bbr = inet_csk_ca(sk);

// 	bbr->lt_bw = 0;
// 	bbr->lt_use_bw = 0;
// 	bbr->lt_is_sampling = false;
// 	bbr_reset_lt_bw_sampling_interval(sk);
// }

// /* Long-term bw sampling interval is done. Estimate whether we're policed. */
// static void bbr_lt_bw_interval_done(struct sock *sk, u32 bw)
// {
// 	struct bbr *bbr = inet_csk_ca(sk);
// 	u32 diff;

// 	if (bbr->lt_bw) {  /* do we have bw from a previous interval? */
// 		/* Is new bw close to the lt_bw from the previous interval? */
// 		// diff = abs(bw - bbr->lt_bw);
// 		diff = myabs(bw, bbr->lt_bw);
// 		if ((diff * BBR_UNIT <= bbr_lt_bw_ratio * bbr->lt_bw) ||
// 		    (bbr_rate_bytes_per_sec(sk, diff, BBR_UNIT) <=
// 		     bbr_lt_bw_diff)) {
// 			/* All criteria are met; estimate we're policed. */
// 			bbr->lt_bw = (bw + bbr->lt_bw) >> 1;  /* avg 2 intvls */
// 			bbr->lt_use_bw = 1;
// 			bbr->pacing_gain = BBR_UNIT;  /* try to avoid drops */
// 			bbr->lt_rtt_cnt = 0;
// 			return;
// 		}
// 	}
// 	bbr->lt_bw = bw;
// 	bbr_reset_lt_bw_sampling_interval(sk);
// }

// /* Token-bucket traffic policers are common (see "An Internet-Wide Analysis of
//  * Traffic Policing", SIGCOMM 2016). BBR detects token-bucket policers and
//  * explicitly models their policed rate, to reduce unnecessary losses. We
//  * estimate that we're policed if we see 2 consecutive sampling intervals with
//  * consistent throughput and high packet loss. If we think we're being policed,
//  * set lt_bw to the "long-term" average delivery rate from those 2 intervals.
//  */
// static void bbr_lt_bw_sampling(struct sock *sk, const struct rate_sample *rs)
// {
// 	struct tcp_sock *tp = tcp_sk(sk);
// 	struct bbr *bbr = inet_csk_ca(sk);
// 	u32 lost, delivered;
// 	u64 bw;
// 	u32 t;

// 	if (bbr->lt_use_bw) {	/* already using long-term rate, lt_bw? */
// 		if (bbr->mode == BBR_PROBE_BW && bbr->round_start &&
// 		    ++bbr->lt_rtt_cnt >= bbr_lt_bw_max_rtts) {
// 			bbr_reset_lt_bw_sampling(sk);    /* stop using lt_bw */
// 			bbr_reset_probe_bw_mode(sk);  /* restart gain cycling */
// 		}
// 		return;
// 	}

// 	/* Wait for the first loss before sampling, to let the policer exhaust
// 	 * its tokens and estimate the steady-state rate allowed by the policer.
// 	 * Starting samples earlier includes bursts that over-estimate the bw.
// 	 */
// 	if (!bbr->lt_is_sampling) {
// 		if (!rs->losses)
// 			return;
// 		bbr_reset_lt_bw_sampling_interval(sk);
// 		bbr->lt_is_sampling = true;
// 	}

// 	/* To avoid underestimates, reset sampling if we run out of data. */
// 	if (rs->is_app_limited) {
// 		bbr_reset_lt_bw_sampling(sk);
// 		return;
// 	}

// 	if (bbr->round_start)
// 		bbr->lt_rtt_cnt++;	/* count round trips in this interval */
// 	if (bbr->lt_rtt_cnt < bbr_lt_intvl_min_rtts)
// 		return;		/* sampling interval needs to be longer */
// 	if (bbr->lt_rtt_cnt > 4 * bbr_lt_intvl_min_rtts) {
// 		bbr_reset_lt_bw_sampling(sk);  /* interval is too long */
// 		return;
// 	}

// 	/* End sampling interval when a packet is lost, so we estimate the
// 	 * policer tokens were exhausted. Stopping the sampling before the
// 	 * tokens are exhausted under-estimates the policed rate.
// 	 */
// 	if (!rs->losses)
// 		return;

// 	/* Calculate packets lost and delivered in sampling interval. */
// 	lost = tp->lost - bbr->lt_last_lost;
// 	delivered = tp->delivered - bbr->lt_last_delivered;
// 	/* Is loss rate (lost/delivered) >= lt_loss_thresh? If not, wait. */
// 	if (!delivered || (lost << BBR_SCALE) < bbr_lt_loss_thresh * delivered)
// 		return;

// 	/* Find average delivery rate in this sampling interval. */
// 	t = div_u64(tp->delivered_mstamp, USEC_PER_MSEC) - bbr->lt_last_stamp;
// 	if ((s32)t < 1)
// 		return;		/* interval is less than one ms, so wait */
// 	/* Check if can multiply without overflow */
// 	if (t >= ~0U / USEC_PER_MSEC) {
// 		bbr_reset_lt_bw_sampling(sk);  /* interval too long; reset */
// 		return;
// 	}
// 	t *= USEC_PER_MSEC;
// 	bw = (u64)delivered * BW_UNIT;
// 	do_div(bw, t);
// 	bbr_lt_bw_interval_done(sk, bw);
// }

// /* Estimate the bandwidth based on how fast packets are delivered */
// static void bbr_update_bw(struct sock *sk, const struct rate_sample *rs)
// {
// 	struct tcp_sock *tp = tcp_sk(sk);
// 	struct bbr *bbr = inet_csk_ca(sk);
// 	u64 bw;

// 	bbr->round_start = 0;
// 	if (rs->delivered < 0 || rs->interval_us <= 0)
// 		return; /* Not a valid observation */

// 	/* See if we've reached the next RTT */
// 	if (!before(rs->prior_delivered, bbr->next_rtt_delivered)) {
// 		bbr->next_rtt_delivered = tp->delivered;
// 		bbr->rtt_cnt++;
// 		bbr->round_start = 1;
// 		bbr->packet_conservation = 0;
// 	}

// 	bbr_lt_bw_sampling(sk, rs);

// 	/* Divide delivered by the interval to find a (lower bound) bottleneck
// 	 * bandwidth sample. Delivered is in packets and interval_us in uS and
// 	 * ratio will be <<1 for most connections. So delivered is first scaled.
// 	 */
// 	bw = div64_long((u64)rs->delivered * BW_UNIT, rs->interval_us);

// 	/* If this sample is application-limited, it is likely to have a very
// 	 * low delivered count that represents application behavior rather than
// 	 * the available network rate. Such a sample could drag down estimated
// 	 * bw, causing needless slow-down. Thus, to continue to send at the
// 	 * last measured network rate, we filter out app-limited samples unless
// 	 * they describe the path bw at least as well as our bw model.
// 	 *
// 	 * So the goal during app-limited phase is to proceed with the best
// 	 * network rate no matter how long. We automatically leave this
// 	 * phase when app writes faster than the network can deliver :)
// 	 */
// 	if (!rs->is_app_limited || bw >= bbr_max_bw(sk)) {
// 		/* Incorporate new sample into our max bw filter. */
// 		minmax_running_max(&bbr->bw, bbr_bw_rtts, bbr->rtt_cnt, bw);
// 	}
// }

// /* Estimates the windowed max degree of ack aggregation.
//  * This is used to provision extra in-flight data to keep sending during
//  * inter-ACK silences.
//  *
//  * Degree of ack aggregation is estimated as extra data acked beyond expected.
//  *
//  * max_extra_acked = "maximum recent excess data ACKed beyond max_bw * interval"
//  * cwnd += max_extra_acked
//  *
//  * Max extra_acked is clamped by cwnd and bw * bbr_extra_acked_max_us (100 ms).
//  * Max filter is an approximate sliding window of 5-10 (packet timed) round
//  * trips.
//  */
// static void bbr_update_ack_aggregation(struct sock *sk,
// 				       const struct rate_sample *rs)
// {
// 	u32 epoch_us, expected_acked, extra_acked;
// 	struct bbr *bbr = inet_csk_ca(sk);
// 	struct tcp_sock *tp = tcp_sk(sk);

// 	if (!bbr_extra_acked_gain || rs->acked_sacked <= 0 ||
// 	    rs->delivered < 0 || rs->interval_us <= 0)
// 		return;

// 	if (bbr->round_start) {
// 		bbr->extra_acked_win_rtts = min(0x1F,
// 						bbr->extra_acked_win_rtts + 1);
// 		if (bbr->extra_acked_win_rtts >= bbr_extra_acked_win_rtts) {
// 			bbr->extra_acked_win_rtts = 0;
// 			bbr->extra_acked_win_idx = bbr->extra_acked_win_idx ?
// 						   0 : 1;
// 			bbr->extra_acked[bbr->extra_acked_win_idx] = 0;
// 		}
// 	}

// 	/* Compute how many packets we expected to be delivered over epoch. */
// 	epoch_us = tcp_stamp_us_delta(tp->delivered_mstamp,
// 				      bbr->ack_epoch_mstamp);
// 	expected_acked = ((u64)bbr_bw(sk) * epoch_us) / BW_UNIT;

// 	/* Reset the aggregation epoch if ACK rate is below expected rate or
// 	 * significantly large no. of ack received since epoch (potentially
// 	 * quite old epoch).
// 	 */
// 	if (bbr->ack_epoch_acked <= expected_acked ||
// 	    (bbr->ack_epoch_acked + rs->acked_sacked >=
// 	     bbr_ack_epoch_acked_reset_thresh)) {
// 		bbr->ack_epoch_acked = 0;
// 		bbr->ack_epoch_mstamp = tp->delivered_mstamp;
// 		expected_acked = 0;
// 	}

// 	/* Compute excess data delivered, beyond what was expected. */
// 	bbr->ack_epoch_acked = min_t(u32, 0xFFFFF,
// 				     bbr->ack_epoch_acked + rs->acked_sacked);
// 	extra_acked = bbr->ack_epoch_acked - expected_acked;
// 	extra_acked = min(extra_acked, tcp_snd_cwnd(tp));
// 	if (extra_acked > bbr->extra_acked[bbr->extra_acked_win_idx])
// 		bbr->extra_acked[bbr->extra_acked_win_idx] = extra_acked;
// }

// /* Estimate when the pipe is full, using the change in delivery rate: BBR
//  * estimates that STARTUP filled the pipe if the estimated bw hasn't changed by
//  * at least bbr_full_bw_thresh (25%) after bbr_full_bw_cnt (3) non-app-limited
//  * rounds. Why 3 rounds: 1: rwin autotuning grows the rwin, 2: we fill the
//  * higher rwin, 3: we get higher delivery rate samples. Or transient
//  * cross-traffic or radio noise can go away. CUBIC Hystart shares a similar
//  * design goal, but uses delay and inter-ACK spacing instead of bandwidth.
//  */
// static void bbr_check_full_bw_reached(struct sock *sk,
// 				      const struct rate_sample *rs)
// {
// 	struct bbr *bbr = inet_csk_ca(sk);
// 	u32 bw_thresh;

// 	if (bbr_full_bw_reached(sk) || !bbr->round_start || rs->is_app_limited)
// 		return;

// 	bw_thresh = (u64)bbr->full_bw * bbr_full_bw_thresh >> BBR_SCALE;
// 	if (bbr_max_bw(sk) >= bw_thresh) {
// 		bbr->full_bw = bbr_max_bw(sk);
// 		bbr->full_bw_cnt = 0;
// 		return;
// 	}
// 	++bbr->full_bw_cnt;
// 	bbr->full_bw_reached = bbr->full_bw_cnt >= bbr_full_bw_cnt;
// }

// /* If pipe is probably full, drain the queue and then enter steady-state. */
// static void bbr_check_drain(struct sock *sk, const struct rate_sample *rs)
// {
// 	struct bbr *bbr = inet_csk_ca(sk);

// 	if (bbr->mode == BBR_STARTUP && bbr_full_bw_reached(sk)) {
// 		bbr->mode = BBR_DRAIN;	/* drain queue we created */
// 		tcp_sk(sk)->snd_ssthresh =
// 				bbr_inflight(sk, bbr_max_bw(sk), BBR_UNIT);
// 	}	/* fall through to check if in-flight is already small: */
// 	if (bbr->mode == BBR_DRAIN &&
// 	    bbr_packets_in_net_at_edt(sk, tcp_packets_in_flight(tcp_sk(sk))) <=
// 	    bbr_inflight(sk, bbr_max_bw(sk), BBR_UNIT))
// 		bbr_reset_probe_bw_mode(sk);  /* we estimate queue is drained */
// }

// static void bbr_check_probe_rtt_done(struct sock *sk)
// {
// 	struct tcp_sock *tp = tcp_sk(sk);
// 	struct bbr *bbr = inet_csk_ca(sk);

// 	if (!(bbr->probe_rtt_done_stamp &&
// 	      after(tcp_jiffies32, bbr->probe_rtt_done_stamp)))
// 		return;

// 	bbr->min_rtt_stamp = tcp_jiffies32;  /* wait a while until PROBE_RTT */
// 	tcp_snd_cwnd_set(tp, max(tcp_snd_cwnd(tp), bbr->prior_cwnd));
// 	bbr_reset_mode(sk);
// }

// /* The goal of PROBE_RTT mode is to have BBR flows cooperatively and
//  * periodically drain the bottleneck queue, to converge to measure the true
//  * min_rtt (unloaded propagation delay). This allows the flows to keep queues
//  * small (reducing queuing delay and packet loss) and achieve fairness among
//  * BBR flows.
//  *
//  * The min_rtt filter window is 10 seconds. When the min_rtt estimate expires,
//  * we enter PROBE_RTT mode and cap the cwnd at bbr_cwnd_min_target=4 packets.
//  * After at least bbr_probe_rtt_mode_ms=200ms and at least one packet-timed
//  * round trip elapsed with that flight size <= 4, we leave PROBE_RTT mode and
//  * re-enter the previous mode. BBR uses 200ms to approximately bound the
//  * performance penalty of PROBE_RTT's cwnd capping to roughly 2% (200ms/10s).
//  *
//  * Note that flows need only pay 2% if they are busy sending over the last 10
//  * seconds. Interactive applications (e.g., Web, RPCs, video chunks) often have
//  * natural silences or low-rate periods within 10 seconds where the rate is low
//  * enough for long enough to drain its queue in the bottleneck. We pick up
//  * these min RTT measurements opportunistically with our min_rtt filter. :-)
//  */
// static void bbr_update_min_rtt(struct sock *sk, const struct rate_sample *rs)
// {
// 	struct tcp_sock *tp = tcp_sk(sk);
// 	struct bbr *bbr = inet_csk_ca(sk);
// 	bool filter_expired;

// 	/* Track min RTT seen in the min_rtt_win_sec filter window: */
// 	filter_expired = after(tcp_jiffies32,
// 			       bbr->min_rtt_stamp + bbr_min_rtt_win_sec * HZ);
// 	if (rs->rtt_us >= 0 &&
// 	    (rs->rtt_us < bbr->min_rtt_us ||
// 	     (filter_expired && !rs->is_ack_delayed))) {
// 		bbr->min_rtt_us = rs->rtt_us;
// 		bbr->min_rtt_stamp = tcp_jiffies32;
// 	}

// 	if (bbr_probe_rtt_mode_ms > 0 && filter_expired &&
// 	    !bbr->idle_restart && bbr->mode != BBR_PROBE_RTT) {
// 		bbr->mode = BBR_PROBE_RTT;  /* dip, drain queue */
// 		bbr_save_cwnd(sk);  /* note cwnd so we can restore it */
// 		bbr->probe_rtt_done_stamp = 0;
// 	}

// 	if (bbr->mode == BBR_PROBE_RTT) {
// 		/* Ignore low rate samples during this mode. */
// 		tp->app_limited =
// 			(tp->delivered + tcp_packets_in_flight(tp)) ? : 1;
// 		/* Maintain min packets in flight for max(200 ms, 1 round). */
// 		if (!bbr->probe_rtt_done_stamp &&
// 		    tcp_packets_in_flight(tp) <= bbr_cwnd_min_target) {
// 			bbr->probe_rtt_done_stamp = tcp_jiffies32 +
// 				msecs_to_jiffies(bbr_probe_rtt_mode_ms);
// 			bbr->probe_rtt_round_done = 0;
// 			bbr->next_rtt_delivered = tp->delivered;
// 		} else if (bbr->probe_rtt_done_stamp) {
// 			if (bbr->round_start)
// 				bbr->probe_rtt_round_done = 1;
// 			if (bbr->probe_rtt_round_done)
// 				bbr_check_probe_rtt_done(sk);
// 		}
// 	}
// 	/* Restart after idle ends only once we process a new S/ACK for data */
// 	if (rs->delivered > 0)
// 		bbr->idle_restart = 0;
// }

// static void bbr_update_gains(struct sock *sk)
// {
// 	struct bbr *bbr = inet_csk_ca(sk);

// 	switch (bbr->mode) {
// 	case BBR_STARTUP:
// 		bbr->pacing_gain = bbr_high_gain;
// 		bbr->cwnd_gain	 = bbr_high_gain;
// 		break;
// 	case BBR_DRAIN:
// 		bbr->pacing_gain = bbr_drain_gain;	/* slow, to drain */
// 		bbr->cwnd_gain	 = bbr_high_gain;	/* keep cwnd */
// 		break;
// 	case BBR_PROBE_BW:
// 		bbr->pacing_gain = (bbr->lt_use_bw ?
// 				    BBR_UNIT :
// 				    bbr_pacing_gain[bbr->cycle_idx]);
// 		bbr->cwnd_gain	 = bbr_cwnd_gain;
// 		break;
// 	case BBR_PROBE_RTT:
// 		bbr->pacing_gain = BBR_UNIT;
// 		bbr->cwnd_gain	 = BBR_UNIT;
// 		break;
// 	default:
// 		// WARN_ONCE(1, "BBR bad mode: %u\n", bbr->mode);
// 		break;
// 	}
// }

// static void bbr_update_model(struct sock *sk, const struct rate_sample *rs)
// {
// 	bbr_update_bw(sk, rs);
// 	bbr_update_ack_aggregation(sk, rs);
// 	bbr_update_cycle_phase(sk, rs);
// 	bbr_check_full_bw_reached(sk, rs);
// 	bbr_check_drain(sk, rs);
// 	bbr_update_min_rtt(sk, rs);
// 	bbr_update_gains(sk);
// }


extern void bbr_init(struct sock *sk) __ksym;
extern void bbr_main(struct sock *sk, u32 ack, int flag, const struct rate_sample *rs) __ksym;
extern u32 bbr_sndbuf_expand(struct sock *sk) __ksym;
extern u32 bbr_undo_cwnd(struct sock *sk) __ksym;
extern void bbr_cwnd_event(struct sock *sk, enum tcp_ca_event event) __ksym;
extern u32 bbr_ssthresh(struct sock *sk) __ksym;
extern u32 bbr_min_tso_segs(struct sock *sk) __ksym;
extern void bbr_set_state(struct sock *sk, u8 new_state) __ksym;



SEC("struct_ops")
void BPF_PROG(bpf_bbr_init, struct sock *sk)
{
	bbr_init(sk);
}


SEC("struct_ops")
void BPF_PROG(bpf_bbr_main, struct sock *sk, u32 ack, int flag, const struct rate_sample *rs)
{
	bbr_main(sk, ack, flag, rs);
}


SEC("struct_ops")
u32 BPF_PROG(bpf_bbr_sndbuf_expand, struct sock *sk)
{
	return bbr_sndbuf_expand(sk);
}


SEC("struct_ops")
u32 BPF_PROG(bpf_bbr_undo_cwnd, struct sock *sk)
{
	return bbr_undo_cwnd(sk);
}


SEC("struct_ops")
void BPF_PROG(bpf_bbr_cwnd_event, struct sock *sk, enum tcp_ca_event event)
{
	bbr_cwnd_event(sk, event);
}


SEC("struct_ops")
u32 BPF_PROG(bpf_bbr_ssthresh, struct sock *sk)
{
	return bbr_ssthresh(sk);
}

SEC("struct_ops")
u32 BPF_PROG(bpf_bbr_min_tso_segs, struct sock *sk)
{
	return bbr_min_tso_segs(sk);
}



SEC("struct_ops")
void BPF_PROG(bpf_bbr_set_state, struct sock *sk, u8 new_state)
{
	bbr_set_state(sk, new_state);
}


SEC(".struct_ops")
struct tcp_congestion_ops bbr_wrp = {
	.name		= "bbr_wrp",
	.init		= (void *)bpf_bbr_init,
	.cong_control	= (void *)bpf_bbr_main,
	.sndbuf_expand	= (void *)bpf_bbr_sndbuf_expand,
	.undo_cwnd	= (void *)bpf_bbr_undo_cwnd,
	.cwnd_event	= (void *)bpf_bbr_cwnd_event,
	.ssthresh	= (void *)bpf_bbr_ssthresh,
	.min_tso_segs	= (void *)bpf_bbr_min_tso_segs,
	.set_state	= (void *)bpf_bbr_set_state,
};
char _license[] SEC("license") = "GPL";

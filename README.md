# bbr-bpf

## Modifications
Modification to the original TCP BBR file:
* change u8,u32,u64,etc to __u8, __u32, __u64, etc.
* Defined external kernel functions
* Removed compiler flags using macro (e.g., "unlikely", "READ_ONCE")
*  Borrowed some time definitions from bpf_cubic (e.g., HZ and JIFFY)
* Defined constant values not included in vmlinux.h (e.g., "TCP_INFINITE_SSTHRESH")
*  Implemented do_div() and cmpxchg() from assembly to C
* Changed min_t() macro to min()


## System 

```
Ubuntu 22.04

$ uname -r
6.5.0-41-generic

$ bpftool -V
bpftool v7.3.0
using libbpf v1.3
features: llvm, skeletons

$ clang -v
Ubuntu clang version 14.0.0-1ubuntu1.1

```

## Expected result

```sh
$ clang -O2 -target bpf -c -g bpf_cubic.c

$ sudo bpftool struct_ops register bpf_cubic.o
Registered tcp_congestion_ops cubic id 953

$ sudo bpftool struct_ops list
953: cubic           tcp_congestion_ops

$ sudo sysctl net.ipv4.tcp_available_congestion_control
net.ipv4.tcp_available_congestion_control = reno cubic bpf_cubic
```



## Actual result

```bash
$ clang -O2 -target bpf -c -g tcp_bbr.c
#no ouput and generate tcp_bbr.o

$ sudo bpftool struct_ops -d register tcp_bbr.o 
libbpf: loading tcp_bbr.o
libbpf: elf: section(2) .text, size 4056, link 0, flags 6, type=1
libbpf: sec '.text': found program 'bbr_check_probe_rtt_done' at insn offset 52 (416 bytes), code size 58 insns (464 bytes)
libbpf: sec '.text': found program 'bbr_set_pacing_rate' at insn offset 18 (144 bytes), code size 34 insns (272 bytes)
libbpf: sec '.text': found program 'bbr_lt_bw_sampling' at insn offset 145 (1160 bytes), code size 158 insns (1264 bytes)
libbpf: sec '.text': found program 'bbr_packets_in_net_at_edt' at insn offset 380 (3040 bytes), code size 74 insns (592 bytes)
libbpf: sec '.text': found program 'bbr_inflight' at insn offset 454 (3632 bytes), code size 53 insns (424 bytes)
libbpf: sec '.text': found program 'bbr_init_pacing_rate_from_rtt' at insn offset 110 (880 bytes), code size 35 insns (280 bytes)
libbpf: sec '.text': found program 'bbr_reset_lt_bw_sampling' at insn offset 303 (2424 bytes), code size 19 insns (152 bytes)
libbpf: sec '.text': found program 'bbr_lt_bw_interval_done' at insn offset 322 (2576 bytes), code size 58 insns (464 bytes)
libbpf: sec '.text': found program 'mydiv' at insn offset 0 (0 bytes), code size 9 insns (72 bytes)
libbpf: sec '.text': found program 'cmpxchg' at insn offset 9 (72 bytes), code size 9 insns (72 bytes)
libbpf: elf: section(3) .rel.text, size 112, link 30, flags 40, type=9
libbpf: elf: section(4) struct_ops, size 8168, link 0, flags 6, type=1
libbpf: sec 'struct_ops': found program 'bpf_bbr_min_tso_segs' at insn offset 0 (0 bytes), code size 7 insns (56 bytes)
libbpf: sec 'struct_ops': found program 'bpf_bbr_cwnd_event' at insn offset 7 (56 bytes), code size 39 insns (312 bytes)
libbpf: sec 'struct_ops': found program 'bpf_bbr_main' at insn offset 46 (368 bytes), code size 820 insns (6560 bytes)
libbpf: sec 'struct_ops': found program 'bpf_bbr_init' at insn offset 866 (6928 bytes), code size 73 insns (584 bytes)
libbpf: sec 'struct_ops': found program 'bpf_bbr_sndbuf_expand' at insn offset 939 (7512 bytes), code size 2 insns (16 bytes)
libbpf: sec 'struct_ops': found program 'bpf_bbr_undo_cwnd' at insn offset 941 (7528 bytes), code size 27 insns (216 bytes)
libbpf: sec 'struct_ops': found program 'bpf_bbr_ssthresh' at insn offset 968 (7744 bytes), code size 23 insns (184 bytes)
libbpf: sec 'struct_ops': found program 'bpf_bbr_set_state' at insn offset 991 (7928 bytes), code size 30 insns (240 bytes)
libbpf: elf: section(5) .relstruct_ops, size 816, link 30, flags 40, type=9
libbpf: elf: section(6) license, size 4, link 0, flags 3, type=1
libbpf: license of tcp_bbr.o is GPL
libbpf: elf: section(7) .struct_ops, size 192, link 0, flags 3, type=1
libbpf: elf: section(8) .rel.struct_ops, size 128, link 30, flags 40, type=9
libbpf: elf: section(9) .rodata.cst32, size 32, link 0, flags 12, type=1
libbpf: elf: section(20) .BTF, size 34773, link 0, flags 0, type=1
libbpf: elf: section(22) .BTF.ext, size 13260, link 0, flags 0, type=1
libbpf: elf: section(30) .symtab, size 3816, link 1, flags 0, type=2
libbpf: looking for externs among 159 symbols...
libbpf: collected 11 externs total
libbpf: extern (ksym) #1: symbol 146, name get_random_u32_below
libbpf: extern (ksym) #2: symbol 140, name minmax_get
libbpf: extern (ksym) #3: symbol 152, name minmax_reset
libbpf: extern (ksym) #4: symbol 142, name minmax_running_max
libbpf: extern (ksym) #5: symbol 148, name msecs_to_jiffies
libbpf: extern (ksym) #6: symbol 151, name tcp_min_rtt
libbpf: extern (ksym) #7: symbol 145, name tcp_packets_in_flight
libbpf: extern (ksym) #8: symbol 144, name tcp_snd_cwnd
libbpf: extern (ksym) #9: symbol 149, name tcp_snd_cwnd_set
libbpf: extern (ksym) #10: symbol 143, name tcp_stamp_us_delta
libbpf: extern (kcfg) #0: symbol 147, off 0, name CONFIG_HZ
libbpf: sec '.rodata': failed to determine size from ELF: size 0, err -2

```
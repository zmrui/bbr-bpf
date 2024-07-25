# bbr-bpf

Expected result

```sh
clang -O2 -target bpf -c -g bpf_cubic.c
sudo bpftool struct_ops register bpf_cubic.o
```

![Expected result](expected_result.png)

Actual result

```sh
clang -O2 -target bpf -c -g tcp_bbr.c
sudo bpftool struct_ops register tcp_bbr.o
```

![Actual result](actual_result.png)

Failed to register and no error message
# TC-Pkt-Counter

This is a simple eBPF program that attaches to the TC egress hook of a Kubernetes node's primary interface (assumed to be "eth0"), and emits logs of all TCP, UDP and ICMP traffic egressing from the node, including source and destination IPs (pods or nodes), ports, protocol and TCP flags or ICMP Echo types.

Each pod will emit logs that look like this, showing traffic from the node or pods on the node, to destination pod, node or external IPs per protocol, including the packet counts:
```
---
[23:33:50] TCP 172.18.0.5->172.18.0.6 55136->6443 [ACK] (len=16896) count=1983
[23:33:50] ICMP 10.244.2.2->10.244.1.4 type=0 code=0 (len=25088) count=45
[23:33:50] TCP 10.244.2.3->10.244.1.2 33738->5201 [ACK] (len=16896) count=86
[23:33:50] TCP 10.244.2.2->10.244.1.3 5201->49082 [FIN|ACK] (len=16896) count=71
[23:33:50] UDP 10.244.2.4->10.244.0.4 42978->53 (len=25344) count=72
[23:33:50] UDP 10.244.2.3->10.244.1.2 48229->5201 (len=10880) count=22930
[23:33:50] UDP 10.244.2.2->10.244.1.3 5201->52311 (len=11776) count=5
[23:33:50] ICMP 10.244.2.4->10.244.1.2 type=8 code=0 (len=25088) count=45
---
[23:33:51] TCP 172.18.0.5->172.18.0.6 10250->38528 [PSH|ACK] (len=42752) count=1993
[23:33:51] ICMP 10.244.2.2->10.244.1.4 type=0 code=0 (len=25088) count=46
[23:33:51] TCP 10.244.2.3->10.244.1.2 33738->5201 [ACK] (len=16896) count=86
[23:33:51] TCP 10.244.2.2->10.244.1.3 5201->49082 [FIN|ACK] (len=16896) count=71
[23:33:51] UDP 10.244.2.4->10.244.0.4 42978->53 (len=25344) count=72
[23:33:51] UDP 10.244.2.3->10.244.1.2 48229->5201 (len=10880) count=22930
[23:33:51] UDP 10.244.2.2->10.244.1.3 5201->52311 (len=11776) count=5
[23:33:51] ICMP 10.244.2.4->10.244.1.2 type=8 code=0 (len=25088) count=45
---
[23:33:52] TCP 172.18.0.5->172.18.0.6 10250->38528 [PSH|ACK] (len=42752) count=2003
[23:33:52] ICMP 10.244.2.2->10.244.1.4 type=0 code=0 (len=25088) count=47
[23:33:52] TCP 10.244.2.3->10.244.1.2 33738->5201 [ACK] (len=16896) count=86
[23:33:52] TCP 10.244.2.2->10.244.1.3 5201->49082 [FIN|ACK] (len=16896) count=71
[23:33:52] UDP 10.244.2.4->10.244.0.4 42978->53 (len=25344) count=72
[23:33:52] UDP 10.244.2.3->10.244.1.2 48229->5201 (len=10880) count=22930
[23:33:52] UDP 10.244.2.2->10.244.1.3 5201->52311 (len=11776) count=5
[23:33:52] ICMP 10.244.2.4->10.244.1.2 type=8 code=0 (len=25088) count=45
---
```

## Deploy to a Kind cluster
```bash
./deploy.sh
```

Generate some load:
```bash
kubectl apply -f k8s/load-test.yaml
```

Monitor pod logs:
```bash
kubectl logs -l app=tc-pkt-counter -f
```

## Development

### Steps to set-up eBPF on MacOS

1. Install lima to have a Linux VM: 
   ```bash
   brew install limactl
   ```
2. Start lima with the VM using `ebpf-cluster.yaml` config:
   ```bash
   limactl start ebpf-cluster.yaml --mount-writable
   ```
3. Shell into the VM: 
   ```bash
   limactl shell ebpf-cluster
   ```
4. Generate the "vmlinux.h" header file:
   ```bash
   make vmlinux
   ```
5. Build tc-pkt-counter module:
   ```bash
   go generate && go build
   ```
6. Run the tc-pkt-counter
   ```bash
   sudo ./tc-pkt-counter
   ```
7. While `tc-pkt-counter` is attached you can do any network operation to see it being intercepted by it.

### Cleanup
At the end, make sure to stop and remove the VM using: 
```bash
limactl stop ebpf-cluster
limactl delete ebpf-cluster
```

## Useful links
- [Getting Started with eBPF in Go](https://ebpf-go.dev/guides/getting-started/)
- [Go library to read, modify and load eBPF programs](https://github.com/cilium/ebpf)


package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/florianl/go-tc"
	"github.com/florianl/go-tc/core"
	"golang.org/x/sys/unix"
)

// PacketKey represents the key used in the BPF map
type PacketKey struct {
	SrcIP    uint32
	Protocol uint8
	Pad      [3]uint8
}

// PacketInfo represents packet information stored in the BPF map
type PacketInfo struct {
	SrcIP     uint32
	DstIP     uint32
	SrcPort   uint16
	DstPort   uint16
	PktLen    uint16
	Protocol  uint8
	TCPFlags  uint8
	Count     uint64
	Timestamp uint64
}

func formatIPv4(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		(ip>>24)&0xFF,
		(ip>>16)&0xFF,
		(ip>>8)&0xFF,
		ip&0xFF,
	)
}

func formatProtocol(proto uint8) string {
	switch proto {
	case syscall.IPPROTO_TCP:
		return "TCP"
	case syscall.IPPROTO_UDP:
		return "UDP"
	case syscall.IPPROTO_ICMP:
		return "ICMP"
	default:
		return fmt.Sprintf("Unknown(%d)", proto)
	}
}

func formatTCPFlags(flags uint8) string {
	var flagStrs []string
	if flags&0x01 != 0 {
		flagStrs = append(flagStrs, "FIN")
	}
	if flags&0x02 != 0 {
		flagStrs = append(flagStrs, "SYN")
	}
	if flags&0x04 != 0 {
		flagStrs = append(flagStrs, "RST")
	}
	if flags&0x08 != 0 {
		flagStrs = append(flagStrs, "PSH")
	}
	if flags&0x10 != 0 {
		flagStrs = append(flagStrs, "ACK")
	}
	if flags&0x20 != 0 {
		flagStrs = append(flagStrs, "URG")
	}
	if len(flagStrs) == 0 {
		return "none"
	}
	return strings.Join(flagStrs, "|")
}

// attachTCX attempts to attach the eBPF program using the modern TCX API (kernel >= 6.6)
func attachTCX(ifaceIndex int, prog *ebpf.Program) (link.Link, error) {
	egressHook := link.TCXOptions{
		Interface: ifaceIndex,
		Attach:    ebpf.AttachTCXEgress,
		Program:   prog,
	}

	return link.AttachTCX(egressHook)
}

// attachTC attaches the eBPF program using go-tc for kernel < 6.6
func attachTC(ifaceName string, ifaceIndex int, prog *ebpf.Program) (io.Closer, error) {
	// Open a netlink/tc connection to the Linux kernel
	tcnl, err := tc.Open(&tc.Config{})
	if err != nil {
		return nil, fmt.Errorf("could not open rtnetlink socket: %v", err)
	}

	// Create a qdisc/clsact object for the interface
	qdisc := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(ifaceIndex),
			Handle:  core.BuildHandle(tc.HandleRoot, 0x0000),
			Parent:  tc.HandleIngress, // We're using HandleIngress here as our base
			Info:    0,
		},
		Attribute: tc.Attribute{
			Kind: "clsact",
		},
	}

	// Attach the qdisc/clsact to the interface
	if err := tcnl.Qdisc().Add(&qdisc); err != nil {
		tcnl.Close()
		return nil, fmt.Errorf("could not assign clsact to %s: %v", ifaceName, err)
	}

	// Get the file descriptor of the eBPF program
	fd := uint32(prog.FD())
	flags := uint32(0x1) // Attach to TC_ACT_DIRECT action

	// Create a tc/filter object for the egress path
	egressFilter := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(ifaceIndex),
			Handle:  0,
			Parent:  core.BuildHandle(tc.HandleRoot, tc.HandleMinEgress),
			Info:    core.FilterInfo(1, 0x0003), // ETH_P_ALL (0x0003) - catch all ethernet packets
		},
		Attribute: tc.Attribute{
			Kind: "bpf",
			BPF: &tc.Bpf{
				FD:    &fd,
				Name:  ToCString("counters"),
				Flags: &flags,
			},
		},
	}

	// Attach the filter to the egress path
	if err := tcnl.Filter().Add(&egressFilter); err != nil {
		// Clean up the qdisc
		tcnl.Qdisc().Delete(&qdisc)
		tcnl.Close()
		return nil, fmt.Errorf("could not attach eBPF filter to egress: %v", err)
	}

	// Return a closer that will clean up everything when called
	return &tcCloser{
		tcnl:   tcnl,
		qdisc:  qdisc,
		filter: egressFilter,
	}, nil
}

// ToCString converts a Go string to a C-string with null termination
func ToCString(s string) *string {
	cs := s + "\000"
	return &cs
}

// tcCloser handles cleanup of TC resources
type tcCloser struct {
	tcnl   *tc.Tc
	qdisc  tc.Object
	filter tc.Object
}

func (c *tcCloser) Close() error {
	if err := c.tcnl.Filter().Delete(&c.filter); err != nil {
		log.Printf("Warning: Could not delete TC filter: %v", err)
	}
	if err := c.tcnl.Qdisc().Delete(&c.qdisc); err != nil {
		log.Printf("Warning: Could not delete TC qdisc: %v", err)
	}
	return c.tcnl.Close()
}

func main() {
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	// List all interfaces for debugging
	interfaces, err := net.Interfaces()
	if err != nil {
		log.Fatal("Getting interfaces:", err)
	}

	log.Println("Available interfaces:")
	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		log.Printf("Interface %s (index %d): %v", iface.Name, iface.Index, addrs)
	}

	var objs counterObjects
	if err := loadCounterObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	// In a pod, eth0 is typically the main interface
	ifname := "eth0"
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		log.Fatalf("Getting interface %s: %s", ifname, err)
	}

	addrs, err := iface.Addrs()
	if err != nil {
		log.Printf("Warning: couldn't get addresses for %s: %v", ifname, err)
	} else {
		log.Printf("Selected interface %s (index %d) has addresses: %v", ifname, iface.Index, addrs)
	}

	// First try to attach using TCX (kernel >= 6.6)
	var l io.Closer
	link, err := attachTCX(iface.Index, objs.CountPackets)
	if err != nil {
		if strings.Contains(err.Error(), "tcx not supported") {
			log.Printf("TCX not supported (kernel < 6.6), falling back to TC...")
			// Fall back to TC for older kernels
			l, err = attachTC(ifname, iface.Index, objs.CountPackets)
			if err != nil {
				log.Fatal("Attaching TC program:", err)
			}
			log.Printf("Successfully attached TC program to interface %s using go-tc", ifname)
		} else {
			// Some other error occurred
			log.Fatal("Attaching TCX program:", err)
		}
	} else {
		l = link
		log.Printf("Successfully attached TCX program to interface %s", ifname)
	}
	defer l.Close()

	// Get the NODE_IP from environment variable or auto-detect
	nodeIP := os.Getenv("NODE_IP")
	if nodeIP == "" {
		// Auto-detect IP address for local development
		ifaces, err := net.Interfaces()
		if err != nil {
			log.Fatal("Failed to get network interfaces:", err)
		}

		for _, iface := range ifaces {
			if iface.Name == "eth0" { // Lima VM uses eth0
				addrs, err := iface.Addrs()
				if err != nil {
					log.Fatal("Failed to get interface addresses:", err)
				}
				for _, addr := range addrs {
					// Look for IPv4 address
					if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
						nodeIP = ipnet.IP.String()
						break
					}
				}
				break
			}
		}
		if nodeIP == "" {
			log.Fatal("Could not auto-detect IP address and NODE_IP environment variable is not set")
		}
		log.Printf("Auto-detected IP address: %s", nodeIP)
	} else {
		log.Printf("Using NODE_IP from env: %s", nodeIP)
	}

	// Convert NODE_IP string to uint32 for BPF map lookup
	ip := net.ParseIP(nodeIP)
	if ip == nil {
		log.Fatal("Invalid NODE_IP format")
	}
	log.Printf("Parsed IP: %v", ip)

	ip = ip.To4()
	if ip == nil {
		log.Fatal("NODE_IP is not an IPv4 address")
	}
	log.Printf("IPv4: %v (bytes: %x %x %x %x)", ip, ip[0], ip[1], ip[2], ip[3])
	log.Printf("IPv4 (decimal): %d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
	log.Printf("IPv4 (hex): %x:%x:%x:%x", ip[0], ip[1], ip[2], ip[3])

	// Convert to network byte order (big endian)
	nodeIPUint32 := binary.BigEndian.Uint32(ip)
	log.Printf("Node IP in uint32 (network order): %x", nodeIPUint32)

	// Start a ticker to read map values periodically
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	log.Printf("Listening for packets on %s (index %d)...", iface.Name, iface.Index)

	signalChan := make(chan os.Signal, 5)
	signal.Notify(signalChan, os.Interrupt)

	for {
		select {
		case <-signalChan:
			log.Println("\nReceived an interrupt, stopping...")
			return
		case <-ticker.C:
			var key PacketKey
			var nextKey PacketKey
			var value PacketInfo

			// Start with key = nil to get the first key
			err := objs.PktCount.NextKey(nil, &nextKey)
			if err != nil {
				if err != ebpf.ErrKeyNotExist {
					log.Printf("Error getting first key: %v", err)
				}
				continue
			}

			for {
				// Look up value for the current key
				err = objs.PktCount.Lookup(&nextKey, &value)
				if err != nil {
					if err != ebpf.ErrKeyNotExist {
						log.Printf("Error looking up value: %v", err)
					}
					break
				}

				srcIP := formatIPv4(value.SrcIP)
				dstIP := formatIPv4(value.DstIP)
				proto := formatProtocol(value.Protocol)

				var portInfo string
				if value.Protocol == syscall.IPPROTO_TCP {
					flags := formatTCPFlags(value.TCPFlags)
					portInfo = fmt.Sprintf("%d->%d [%s]", value.SrcPort, value.DstPort, flags)
				} else if value.Protocol == syscall.IPPROTO_UDP {
					portInfo = fmt.Sprintf("%d->%d", value.SrcPort, value.DstPort)
				} else if value.Protocol == syscall.IPPROTO_ICMP {
					portInfo = fmt.Sprintf("type=%d code=%d", value.SrcPort, value.DstPort)
				}

				fmt.Printf("[%s] %s %s->%s %s (len=%d) count=%d\n",
					time.Now().Format("15:04:05"),
					proto,
					srcIP,
					dstIP,
					portInfo,
					value.PktLen,
					value.Count)

				// Get next key, using current key
				key = nextKey
				err = objs.PktCount.NextKey(&key, &nextKey)
				// Break silently if we've reached the end
				if err == ebpf.ErrKeyNotExist {
					break
				}
				if err != nil {
					// FIXME: This is noisy, but check for genuine errors
					// log.Printf("Error iterating map: %v", err)
					break
				}
			}
			fmt.Println("---")
		}
	}
}

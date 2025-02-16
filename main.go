package main

import (
	"encoding/binary"
	"fmt"
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

	egressHook := link.TCXOptions{
		Interface: iface.Index,
		Attach:    ebpf.AttachTCXEgress,
		Program:   objs.CountPackets,
	}

	egressLink, err := link.AttachTCX(egressHook)
	if err != nil {
		log.Fatal("Attaching egress TC program:", err)
	}
	defer egressLink.Close()

	log.Printf("Successfully attached TC programs (ingress and egress) to interface %s", ifname)

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

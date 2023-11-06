package main

import (
	"bytes"
	"fmt"
	"log"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// var (
// 	routine int
// 	count   int
// )

func analysePacket(packet gopacket.Packet) {
	if ip4Layer := packet.Layer(layers.LayerTypeIPv4); ip4Layer != nil {
		ip4 := ip4Layer.(*layers.IPv4)

		// tcp
		if ip4.NextLayerType() == layers.LayerTypeTCP {
			tcpLayer := packet.Layer(layers.LayerTypeTCP)
			tcp := tcpLayer.(*layers.TCP)

			// is HTTP request or response
			if len(tcp.Payload) > 4 {
				if bytes.Equal(tcp.Payload[:4], []byte("HTTP")) {
					fmt.Printf("%s Respond     From %s:%d to %s:%d\n", tcp.Payload[:4], ip4.SrcIP, tcp.SrcPort, ip4.DstIP, tcp.DstPort)
				} else if bytes.Equal(tcp.Payload[:4], []byte("GET ")) || bytes.Equal(tcp.Payload[:4], []byte("POST")) {
					fmt.Printf("HTTP %s     From %s:%d to %s:%d\n", tcp.Payload[:4], ip4.SrcIP, tcp.SrcPort, ip4.DstIP, tcp.DstPort)
				}
			}
			// udp
		} else if ip4.NextLayerType() == layers.LayerTypeUDP {
			udpLayer := packet.Layer(layers.LayerTypeUDP)
			udp := udpLayer.(*layers.UDP)
			// dns
			if udp.NextLayerType() == layers.LayerTypeDNS {
				fmt.Printf("DNS     From %s:%d to %s:%d\n", ip4.SrcIP, udp.SrcPort, ip4.DstIP, udp.DstPort)
				dnsLayer := packet.Layer(layers.LayerTypeDNS)
				dns := dnsLayer.(*layers.DNS)
				// is dns request or response
				if dns.QR {
					for _, dnsAnswer := range dns.Answers {
						fmt.Printf("DNS Answer: %s\n", dnsAnswer.String())
					}
				} else {
					for _, dnsQuestion := range dns.Questions {
						fmt.Printf("DNS Question: %s\n", string(dnsQuestion.Name))
					}
				}

			}
		}
	}
	// routine += runtime.NumGoroutine()
	// count++
}

func main() {
	// Check if file argument is provided
	if len(os.Args) < 2 {
		fmt.Println("Please provide a wifi interface")
		os.Exit(1)
	}

	// Open a pcap handle for the provided interface
	handle, err := pcap.OpenLive(os.Args[1], 16384, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.NoCopy = true
	packetSource.Lazy = true

	// count = 0
	// routine = 0
	for packet := range packetSource.Packets() {
		// if count > 10000 {
		// 	time.Sleep(500 * time.Millisecond)
		// 	fmt.Printf("count: %d, routine: %d\n", count, routine)

		// 	fmt.Printf("avg: %f\n", float32(routine)/float32(count))
		// 	break
		// }
		go analysePacket(packet)
	}
}

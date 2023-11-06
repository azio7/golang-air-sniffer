package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func analysePacket(packet gopacket.Packet) {
	if ip4Layer := packet.Layer(layers.LayerTypeIPv4); ip4Layer != nil {
		ip4 := ip4Layer.(*layers.IPv4)

		// tcp
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp := tcpLayer.(*layers.TCP)

			// is HTTP request or response
			if len(tcp.Payload) > 4 {
				if bytes.Equal(tcp.Payload[:4], []byte("HTTP")) {
					fmt.Printf("%s Respond		From %s:%d to %s:%d\n", tcp.Payload[:4], ip4.SrcIP, tcp.SrcPort, ip4.DstIP, tcp.DstPort)
				} else if bytes.Equal(tcp.Payload[:4], []byte("GET ")) || bytes.Equal(tcp.Payload[:4], []byte("POST")) {

					// find the path of the request
					i1 := -1
					i2 := -1
					for index, value := range tcp.Payload {
						if i1 == -1 {
							if value == ' ' {
								i1 = index + 1
							}
						} else if i2 == -1 {
							if value == ' ' {
								i2 = index
								break
							}
						}
					}

					fmt.Printf("HTTP %s %s		From %s:%d to %s:%d\n", tcp.Payload[:4], tcp.Payload[i1:i2], ip4.SrcIP, tcp.SrcPort, ip4.DstIP, tcp.DstPort)
				}
			}
			// udp
		} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp := udpLayer.(*layers.UDP)
			// dns
			if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
				fmt.Printf("DNS		From %s:%d to %s:%d\n", ip4.SrcIP, udp.SrcPort, ip4.DstIP, udp.DstPort)

				dns := dnsLayer.(*layers.DNS)
				// is dns request or response
				if dns.QR {
					for _, dnsAnswer := range dns.Answers {
						fmt.Printf("DNS Answer:			%s\n", dnsAnswer.String())
					}
				} else {
					for _, dnsQuestion := range dns.Questions {
						fmt.Printf("DNS Question:		%s\n", string(dnsQuestion.Name))
					}
				}

			}
		}
	}
}

func main() {

	var (
		device string = "wlan0"
	)
	flag.StringVar(&device, "i", device, "Interface to use")
	flag.Parse()

	// Open a pcap handle for the provided interface
	handle, err := pcap.OpenLive(device, 16384, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.NoCopy = true
	packetSource.Lazy = true

	for packet := range packetSource.Packets() {
		go analysePacket(packet)
	}
}

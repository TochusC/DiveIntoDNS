/**
 * @Project :   Kaweh
 * @File    :   dns_server_ag.go
 * @Contact :
 * @License :   (C)Copyright 2023
 *
 * @Modify Time        @Author     @Version    @Description
 * ----------------    --------    --------    -----------
 * 4/8/23 5:34 PM      idealeer    0.0         None
 */
package main

import (
	"bytes"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	deviceAG     = "ens160"
	srcMacAG     = net.HardwareAddr{0x00, 0x50, 0x56, 0xa1, 0x54, 0x6f}
	gtwMacAG     = net.HardwareAddr{0xdc, 0xda, 0x80, 0xd8, 0xcf, 0x81}
	srcIPAG      = net.ParseIP("202.112.238.56")
	srcPortAG    = 53
	handleSendAG *pcap.Handle
	errAG        error
	domainAG     = "redelegation.net"
	ns1AG        = "ns1-dcl.redelegation.net"
	ns2AG        = "ns2-dcl.redelegation.net"
	ipAG         = "202.112.238.56"
	qnameAG      = []byte{0xc0, 0x0c}
	qnameWAG     = []byte{0x02, 0xc0, 0x0c, 0x00}
	slpTmMapAG   = make(map[string]int64)
	lockAG       sync.Mutex
	mtuAG        = 1500
	ethHLenAG    = 14
	ipv4HLenAG   = 20
)

const letterBytesAG = "abcdefghijklmnopqrstuvwxyz"

func randBytesAG(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytesAG[rand.Intn(len(letterBytesAG))]
	}
	return b
}

func dnsResponseAGNS(
	dstIP string, dstPort layers.UDPPort, qname string, qtype layers.DNSType, txid uint16, ttl uint32, rdata string,
) {

	//fmt.Printf(
	//	"%s : fm %s:%d:0x%04x %s %s?\n", time.Now().Format(time.ANSIC), dstIP, dstPort, txid, qname, qtype.String(),
	//)

	ethernetLayer := &layers.Ethernet{
		BaseLayer:    layers.BaseLayer{},
		SrcMAC:       srcMacAG,
		DstMAC:       gtwMacAG,
		EthernetType: layers.EthernetTypeIPv4,
		Length:       0,
	}

	ipv4Layer := &layers.IPv4{
		BaseLayer:  layers.BaseLayer{},
		Version:    4,
		IHL:        0,
		TOS:        0,
		Length:     0,
		Id:         0,
		Flags:      0,
		FragOffset: 0,
		TTL:        64,
		Protocol:   layers.IPProtocolUDP,
		Checksum:   0,
		SrcIP:      srcIPAG,
		DstIP:      net.ParseIP(dstIP),
		Options:    nil,
		Padding:    nil,
	}

	udpLayer := &layers.UDP{
		BaseLayer: layers.BaseLayer{},
		SrcPort:   layers.UDPPort(srcPortAG),
		DstPort:   layers.UDPPort(dstPort),
		Length:    0,
		Checksum:  0,
	}

	err := udpLayer.SetNetworkLayerForChecksum(ipv4Layer)
	if err != nil {
		fmt.Println("Error: ", err)
		os.Exit(1)
	}

	var dnsLayer *layers.DNS
	switch qtype {
	case layers.DNSTypeNS:
		dnsLayer = &layers.DNS{
			BaseLayer:    layers.BaseLayer{},
			ID:           txid,
			QR:           true,
			OpCode:       0,
			AA:           true,
			TC:           false,
			RD:           false,
			RA:           false,
			Z:            0,
			ResponseCode: 0,
			QDCount:      1,
			ANCount:      2,
			NSCount:      0,
			ARCount:      2,
			Questions: []layers.DNSQuestion{
				{
					Name:  []byte(qname),
					Type:  layers.DNSTypeNS,
					Class: layers.DNSClassIN,
				},
			},
			Answers: []layers.DNSResourceRecord{
				{
					Name:  []byte(qname),
					Type:  layers.DNSTypeNS,
					Class: layers.DNSClassIN,
					TTL:   ttl,
					NS:    []byte(ns1AG),
				},
				{
					Name:  []byte(qname),
					Type:  layers.DNSTypeNS,
					Class: layers.DNSClassIN,
					TTL:   ttl,
					NS:    []byte(ns2AG),
				},
			},
			Additionals: []layers.DNSResourceRecord{
				{
					Name:  []byte(ns1AG),
					Type:  layers.DNSTypeA,
					Class: layers.DNSClassIN,
					TTL:   ttl,
					IP:    net.ParseIP(ipAG),
				},
				{
					Name:  []byte(ns2AG),
					Type:  layers.DNSTypeA,
					Class: layers.DNSClassIN,
					TTL:   ttl,
					IP:    net.ParseIP(ipAG),
				},
			},
		}
	default:
		return
	}

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	err = gopacket.SerializeLayers(
		buffer,
		options,
		ethernetLayer,
		ipv4Layer,
		udpLayer,
		dnsLayer,
	)
	if err != nil {
		fmt.Println("Error: ", err)
		os.Exit(1)
	}

	outgoingPacket := buffer.Bytes()

	err = handleSendAG.WritePacketData(outgoingPacket)
	if err != nil {
		fmt.Println("Error: ", err)
		os.Exit(1)
	}

	//fmt.Printf(
	//	"%s : to %s:%d:0x%04x with %s %s\n", time.Now().Format(time.ANSIC), dstIP, dstPort, txid, qname, qtype.String(),
	//)
}

func dnsResponseAGA(
	dstIP string, dstPort layers.UDPPort, qname string, qtype layers.DNSType, txid uint16, ttl uint32, rdata string,
) {
	ethernetLayer := &layers.Ethernet{
		BaseLayer:    layers.BaseLayer{},
		SrcMAC:       srcMacAG,
		DstMAC:       gtwMacAG,
		EthernetType: layers.EthernetTypeIPv4,
		Length:       0,
	}

	ipv4Layer := &layers.IPv4{
		BaseLayer:  layers.BaseLayer{},
		Version:    4,
		IHL:        0,
		TOS:        0,
		Length:     0,
		Id:         0,
		Flags:      0,
		FragOffset: 0,
		TTL:        64,
		Protocol:   layers.IPProtocolUDP,
		Checksum:   0,
		SrcIP:      srcIPAG,
		DstIP:      net.ParseIP(dstIP),
		Options:    nil,
		Padding:    nil,
	}

	udpLayer := &layers.UDP{
		BaseLayer: layers.BaseLayer{},
		SrcPort:   layers.UDPPort(srcPortAG),
		DstPort:   layers.UDPPort(dstPort),
		Length:    0,
		Checksum:  0,
	}

	err := udpLayer.SetNetworkLayerForChecksum(ipv4Layer)
	if err != nil {
		fmt.Println("Error: ", err)
		os.Exit(1)
	}

	var dnsLayer *layers.DNS
	switch qtype {
	case layers.DNSTypeA:
		dnsLayer = &layers.DNS{
			BaseLayer:    layers.BaseLayer{},
			ID:           txid,
			QR:           true,
			OpCode:       0,
			AA:           true,
			TC:           false,
			RD:           false,
			RA:           false,
			Z:            0,
			ResponseCode: 0,
			QDCount:      1,
			ANCount:      1,
			NSCount:      0,
			ARCount:      0,
			Questions: []layers.DNSQuestion{
				{
					Name:  []byte(qname),
					Type:  layers.DNSTypeA,
					Class: layers.DNSClassIN,
				},
			},
			Answers: []layers.DNSResourceRecord{
				{
					Name:  []byte(qname),
					Type:  layers.DNSTypeA,
					Class: layers.DNSClassIN,
					TTL:   ttl,
					IP:    net.ParseIP(ipAG),
				},
			},
		}
	default:
		return
	}

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	err = gopacket.SerializeLayers(
		buffer,
		options,
		ethernetLayer,
		ipv4Layer,
		udpLayer,
		dnsLayer,
	)
	if err != nil {
		fmt.Println("Error: ", err)
		os.Exit(1)
	}

	outgoingPacket := buffer.Bytes()

	err = handleSendAG.WritePacketData(outgoingPacket)
	if err != nil {
		fmt.Println("Error: ", err)
		os.Exit(1)
	}

	//fmt.Printf(
	//	"%s : to %s:%d:0x%04x %s %s %s\n", time.Now().Format(time.ANSIC), dstIP, dstPort, txid, qname, qtype.String(),
	//	ipAG,
	//)
}

func dnsResponseAGNX(
	dstIP string, dstPort layers.UDPPort, qname string, qtype layers.DNSType, txid uint16, ttl uint32, rdata string,
) {
	ethernetLayer := &layers.Ethernet{
		BaseLayer:    layers.BaseLayer{},
		SrcMAC:       srcMacAG,
		DstMAC:       gtwMacAG,
		EthernetType: layers.EthernetTypeIPv4,
		Length:       0,
	}

	ipv4Layer := &layers.IPv4{
		BaseLayer:  layers.BaseLayer{},
		Version:    4,
		IHL:        0,
		TOS:        0,
		Length:     0,
		Id:         0,
		Flags:      0,
		FragOffset: 0,
		TTL:        64,
		Protocol:   layers.IPProtocolUDP,
		Checksum:   0,
		SrcIP:      srcIPAG,
		DstIP:      net.ParseIP(dstIP),
		Options:    nil,
		Padding:    nil,
	}

	udpLayer := &layers.UDP{
		BaseLayer: layers.BaseLayer{},
		SrcPort:   layers.UDPPort(srcPortAG),
		DstPort:   layers.UDPPort(dstPort),
		Length:    0,
		Checksum:  0,
	}

	err := udpLayer.SetNetworkLayerForChecksum(ipv4Layer)
	if err != nil {
		fmt.Println("Error: ", err)
		os.Exit(1)
	}

	var dnsLayer *layers.DNS
	switch qtype {
	case layers.DNSTypeA:
		dnsLayer = &layers.DNS{
			BaseLayer:    layers.BaseLayer{},
			ID:           txid,
			QR:           true,
			OpCode:       0,
			AA:           true,
			TC:           false,
			RD:           false,
			RA:           false,
			Z:            0,
			ResponseCode: layers.DNSResponseCodeNXDomain,
			QDCount:      1,
			ANCount:      0,
			NSCount:      0,
			ARCount:      0,
			Questions: []layers.DNSQuestion{
				{
					Name:  []byte(qname),
					Type:  layers.DNSTypeA,
					Class: layers.DNSClassIN,
				},
			},
		}
	default:
		return
	}

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	err = gopacket.SerializeLayers(
		buffer,
		options,
		ethernetLayer,
		ipv4Layer,
		udpLayer,
		dnsLayer,
	)
	if err != nil {
		fmt.Println("Error: ", err)
		os.Exit(1)
	}

	outgoingPacket := buffer.Bytes()

	err = handleSendAG.WritePacketData(outgoingPacket)
	if err != nil {
		fmt.Println("Error: ", err)
		os.Exit(1)
	}

	//fmt.Printf(
	//	"%s : to %s:%d:0x%04x %s %s %s\n", time.Now().Format(time.ANSIC), dstIP, dstPort, txid, qname, qtype.String(),
	//	ipAG,
	//)
}

func dnsResponseAGTXT_(
	dstIP string, dstPort layers.UDPPort, qname string, qtype layers.DNSType, txid uint16, ttl uint32, rdata string,
	pktSz int,
) {
	ethernetLayer := &layers.Ethernet{
		BaseLayer:    layers.BaseLayer{},
		SrcMAC:       srcMacAG,
		DstMAC:       gtwMacAG,
		EthernetType: layers.EthernetTypeIPv4,
		Length:       0,
	}

	ipv4Layer := &layers.IPv4{
		BaseLayer:  layers.BaseLayer{},
		Version:    4,
		IHL:        0,
		TOS:        0,
		Length:     0,
		Id:         0,
		Flags:      0,
		FragOffset: 0,
		TTL:        64,
		Protocol:   layers.IPProtocolUDP,
		Checksum:   0,
		SrcIP:      srcIPAG,
		DstIP:      net.ParseIP(dstIP),
		Options:    nil,
		Padding:    nil,
	}

	udpLayer := &layers.UDP{
		BaseLayer: layers.BaseLayer{},
		SrcPort:   layers.UDPPort(srcPortAG),
		DstPort:   layers.UDPPort(dstPort),
		Length:    0,
		Checksum:  0,
	}

	err := udpLayer.SetNetworkLayerForChecksum(ipv4Layer)
	if err != nil {
		fmt.Println("Error: ", err)
		os.Exit(1)
	}

	var txts [][]byte = nil
	batch := pktSz / 255
	mod := pktSz % 255
	for i := 0; i < batch; i++ {
		txts = append(txts, randBytesAG(255))
	}
	if mod > 0 {
		txts = append(txts, randBytesAG(pktSz%255))
	}

	var dnsLayer *layers.DNS
	switch qtype {
	case layers.DNSTypeTXT:
		dnsLayer = &layers.DNS{
			BaseLayer:    layers.BaseLayer{},
			ID:           txid,
			QR:           true,
			OpCode:       0,
			AA:           true,
			TC:           false,
			RD:           false,
			RA:           false,
			Z:            0,
			ResponseCode: 0,
			QDCount:      1,
			ANCount:      1,
			NSCount:      0,
			ARCount:      0,
			Questions: []layers.DNSQuestion{
				{
					Name:  []byte(qname),
					Type:  layers.DNSTypeTXT,
					Class: layers.DNSClassIN,
				},
			},
			Answers: []layers.DNSResourceRecord{
				{
					Name:  qnameAG,
					Type:  layers.DNSTypeTXT,
					Class: layers.DNSClassIN,
					TTL:   ttl,
					TXTs:  txts,
				},
			},
		}
	default:
		return
	}

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	err = gopacket.SerializeLayers(
		buffer,
		options,
		ethernetLayer,
		ipv4Layer,
		udpLayer,
		dnsLayer,
	)
	if err != nil {
		fmt.Println("Error: ", err)
		os.Exit(1)
	}
	outgoingPacket := buffer.Bytes()

	err = handleSendAG.WritePacketData(outgoingPacket)
	if err != nil {
		fmt.Println("Error: ", err)
		os.Exit(1)
	}
}

func dnsResponseAGTXTEDNS0_(
	dstIP string, dstPort layers.UDPPort, qname string, qtype layers.DNSType, txid uint16, ttl uint32, rdata string,
	pktSz int, edns0 int,
) {
	ethernetLayer := &layers.Ethernet{
		BaseLayer:    layers.BaseLayer{},
		SrcMAC:       srcMacAG,
		DstMAC:       gtwMacAG,
		EthernetType: layers.EthernetTypeIPv4,
		Length:       0,
	}

	ipv4Layer := &layers.IPv4{
		BaseLayer:  layers.BaseLayer{},
		Version:    4,
		IHL:        0,
		TOS:        0,
		Length:     0,
		Id:         0,
		Flags:      0,
		FragOffset: 0,
		TTL:        64,
		Protocol:   layers.IPProtocolUDP,
		Checksum:   0,
		SrcIP:      srcIPAG,
		DstIP:      net.ParseIP(dstIP),
		Options:    nil,
		Padding:    nil,
	}

	udpLayer := &layers.UDP{
		BaseLayer: layers.BaseLayer{},
		SrcPort:   layers.UDPPort(srcPortAG),
		DstPort:   layers.UDPPort(dstPort),
		Length:    0,
		Checksum:  0,
	}

	err := udpLayer.SetNetworkLayerForChecksum(ipv4Layer)
	if err != nil {
		fmt.Println("Error: ", err)
		os.Exit(1)
	}

	var txts [][]byte = nil
	batch := pktSz / 255
	mod := pktSz % 255
	for i := 0; i < batch; i++ {
		txts = append(txts, randBytesAG(255))
	}
	if mod > 0 {
		txts = append(txts, randBytesAG(pktSz%255))
	}

	var dnsLayer *layers.DNS
	switch qtype {
	case layers.DNSTypeTXT:
		dnsLayer = &layers.DNS{
			BaseLayer:    layers.BaseLayer{},
			ID:           txid,
			QR:           true,
			OpCode:       0,
			AA:           true,
			TC:           false,
			RD:           false,
			RA:           false,
			Z:            0,
			ResponseCode: 0,
			QDCount:      1,
			ANCount:      1,
			NSCount:      0,
			ARCount:      1,
			Questions: []layers.DNSQuestion{
				{
					Name:  []byte(qname),
					Type:  layers.DNSTypeTXT,
					Class: layers.DNSClassIN,
				},
			},
			Answers: []layers.DNSResourceRecord{
				{
					Name:  qnameAG,
					Type:  layers.DNSTypeTXT,
					Class: layers.DNSClassIN,
					TTL:   ttl,
					TXTs:  txts,
				},
			},
			Additionals: []layers.DNSResourceRecord{
				{
					Name: []byte(nil),
					Type: layers.DNSTypeOPT,
				},
			},
		}
	default:
		return
	}

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	dnsBuffer := gopacket.NewSerializeBuffer()
	err = dnsLayer.SerializeTo(dnsBuffer, options)
	if err != nil {
		fmt.Println("Error: ", err)
		os.Exit(1)
	}

	higherByte := edns0 / 256
	lowerByte := edns0 % 256
	dnsPayload := dnsBuffer.Bytes()
	dnsPayload[len(dnsPayload)-8] = byte(higherByte)
	dnsPayload[len(dnsPayload)-7] = byte(lowerByte)

	err = gopacket.SerializeLayers(
		buffer,
		options,
		ethernetLayer,
		ipv4Layer,
		udpLayer,
		gopacket.Payload(dnsPayload),
	)
	if err != nil {
		fmt.Println("Error: ", err)
		os.Exit(1)
	}
	outgoingPacket := buffer.Bytes()

	err = handleSendAG.WritePacketData(outgoingPacket)
	if err != nil {
		fmt.Println("Error: ", err)
		os.Exit(1)
	}
}

// Enabled with fragments sending
func dnsResponseAGTXT(
	dstIP string, dstPort layers.UDPPort, qname string, qtype layers.DNSType, txid uint16, ttl uint32, rdata string,
	pktSz int,
) {
	// Generate a random IPID value for all fragments
	ipID := uint16(rand.Intn(65536)) // Generate a random number between 0 and 65535

	// Each layer
	ethernetLayer := &layers.Ethernet{
		BaseLayer:    layers.BaseLayer{},
		SrcMAC:       srcMacAG,
		DstMAC:       gtwMacAG,
		EthernetType: layers.EthernetTypeIPv4,
		Length:       0,
	}

	ipv4Layer := &layers.IPv4{
		BaseLayer:  layers.BaseLayer{},
		Version:    4,
		IHL:        0,
		TOS:        0,
		Length:     0,
		Id:         ipID,
		Flags:      0,
		FragOffset: 0,
		TTL:        64,
		Protocol:   layers.IPProtocolUDP,
		Checksum:   0,
		SrcIP:      srcIPAG,
		DstIP:      net.ParseIP(dstIP),
		Options:    nil,
		Padding:    nil,
	}

	udpLayer := &layers.UDP{
		BaseLayer: layers.BaseLayer{},
		SrcPort:   layers.UDPPort(srcPortAG),
		DstPort:   layers.UDPPort(dstPort),
		Length:    0,
		Checksum:  0,
	}

	err := udpLayer.SetNetworkLayerForChecksum(ipv4Layer)
	if err != nil {
		fmt.Println("Error: ", err)
		os.Exit(1)
	}

	var txts [][]byte = nil
	batch := pktSz / 255
	mod := pktSz % 255
	for i := 0; i < batch; i++ {
		txts = append(txts, randBytesAG(255))
	}
	if mod > 0 {
		txts = append(txts, randBytesAG(pktSz%255))
	}

	var dnsLayer *layers.DNS
	switch qtype {
	case layers.DNSTypeTXT:
		dnsLayer = &layers.DNS{
			BaseLayer:    layers.BaseLayer{},
			ID:           txid,
			QR:           true,
			OpCode:       0,
			AA:           true,
			TC:           false,
			RD:           false,
			RA:           false,
			Z:            0,
			ResponseCode: 0,
			QDCount:      1,
			ANCount:      1,
			NSCount:      0,
			ARCount:      0,
			Questions: []layers.DNSQuestion{
				{
					Name:  []byte(qname),
					Type:  layers.DNSTypeTXT,
					Class: layers.DNSClassIN,
				},
			},
			Answers: []layers.DNSResourceRecord{
				{
					Name:  qnameAG,
					Type:  layers.DNSTypeTXT,
					Class: layers.DNSClassIN,
					TTL:   ttl,
					TXTs:  txts,
				},
			},
		}
	default:
		return
	}

	// IP payload
	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	// DNS
	dnsBuffer := gopacket.NewSerializeBuffer()
	err = dnsLayer.SerializeTo(dnsBuffer, options)
	if err != nil {
		fmt.Println("Error: ", err)
		os.Exit(1)
	}
	dnsPayload := dnsBuffer.Bytes()
	dnsPayload = bytes.ReplaceAll(dnsPayload, qnameWAG, qnameAG) // 0xc0, 0x0c

	fmt.Printf(
		"%s : DNS layer size = %d\n", time.Now().Format(time.ANSIC), len(dnsPayload),
	)

	payloadBuffer := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(
		payloadBuffer,
		options,
		udpLayer,
		gopacket.Payload(dnsPayload),
	)
	if err != nil {
		fmt.Println("Error: ", err)
		os.Exit(1)
	}
	payload := payloadBuffer.Bytes()

	// Calculate the payload size per fragment
	payloadSize := mtuAG - ethHLenAG - ipv4HLenAG
	payloadSize = payloadSize &^ 7

	// Split the packet data into fragments
	var fragments [][]byte
	for i := 0; i < len(payload); i += payloadSize {
		end := i + payloadSize
		if end > len(payload) {
			end = len(payload)
		}
		fragments = append(fragments, payload[i:end])
	}

	// Iterate over the fragments and send them
	for i, fragment := range fragments {
		ipv4Layer.Payload = fragment
		ipv4Layer.Length = uint16(len(fragment) + ipv4HLenAG)

		// Calculate the FragOffset for the fragment
		fragOffset := uint16(i * payloadSize / 8)
		ipv4Layer.FragOffset = fragOffset

		// Set the IP flags
		if i < len(fragments)-1 {
			ipv4Layer.Flags = layers.IPv4MoreFragments
		} else {
			ipv4Layer.Flags = 0
		}

		buffer := gopacket.NewSerializeBuffer()
		err = gopacket.SerializeLayers(
			buffer,
			options,
			ethernetLayer,
			ipv4Layer,
			gopacket.Payload(fragment),
		)
		if err != nil {
			fmt.Println("Error: ", err)
			os.Exit(1)
		}
		outgoingPacket := buffer.Bytes()

		// Send the fragment using your preferred method (e.g., raw socket, socket library)
		err = handleSendAG.WritePacketData(outgoingPacket)
		if err != nil {
			fmt.Println("Error: ", err)
			os.Exit(1)
		}

		fmt.Printf(
			"%s : frag#%d with size %d\n", time.Now().Format(time.ANSIC), i+1, len(fragment),
		)
	}
}

// Enabled with fragments sending
func dnsResponseAGTXTEDNS0(
	dstIP string, dstPort layers.UDPPort, qname string, qtype layers.DNSType, txid uint16, ttl uint32, rdata string,
	pktSz int, edns0 int,
) {
	// Generate a random IPID value for all fragments
	ipID := uint16(rand.Intn(65536)) // Generate a random number between 0 and 65535

	// Each layer
	ethernetLayer := &layers.Ethernet{
		BaseLayer:    layers.BaseLayer{},
		SrcMAC:       srcMacAG,
		DstMAC:       gtwMacAG,
		EthernetType: layers.EthernetTypeIPv4,
		Length:       0,
	}

	ipv4Layer := &layers.IPv4{
		BaseLayer:  layers.BaseLayer{},
		Version:    4,
		IHL:        0,
		TOS:        0,
		Length:     0,
		Id:         ipID,
		Flags:      0,
		FragOffset: 0,
		TTL:        64,
		Protocol:   layers.IPProtocolUDP,
		Checksum:   0,
		SrcIP:      srcIPAG,
		DstIP:      net.ParseIP(dstIP),
		Options:    nil,
		Padding:    nil,
	}

	udpLayer := &layers.UDP{
		BaseLayer: layers.BaseLayer{},
		SrcPort:   layers.UDPPort(srcPortAG),
		DstPort:   layers.UDPPort(dstPort),
		Length:    0,
		Checksum:  0,
	}

	err := udpLayer.SetNetworkLayerForChecksum(ipv4Layer)
	if err != nil {
		fmt.Println("Error: ", err)
		os.Exit(1)
	}

	var txts [][]byte = nil
	batch := pktSz / 255
	mod := pktSz % 255
	for i := 0; i < batch; i++ {
		txts = append(txts, randBytesAG(255))
	}
	if mod > 0 {
		txts = append(txts, randBytesAG(pktSz%255))
	}

	var dnsLayer *layers.DNS
	switch qtype {
	case layers.DNSTypeTXT:
		dnsLayer = &layers.DNS{
			BaseLayer:    layers.BaseLayer{},
			ID:           txid,
			QR:           true,
			OpCode:       0,
			AA:           true,
			TC:           false,
			RD:           false,
			RA:           false,
			Z:            0,
			ResponseCode: 0,
			QDCount:      1,
			ANCount:      1,
			NSCount:      0,
			ARCount:      1,
			Questions: []layers.DNSQuestion{
				{
					Name:  []byte(qname),
					Type:  layers.DNSTypeTXT,
					Class: layers.DNSClassIN,
				},
			},
			Answers: []layers.DNSResourceRecord{
				{
					Name:  qnameAG,
					Type:  layers.DNSTypeTXT,
					Class: layers.DNSClassIN,
					TTL:   ttl,
					TXTs:  txts,
				},
			},
			Additionals: []layers.DNSResourceRecord{
				{
					Name: []byte(nil),
					Type: layers.DNSTypeOPT,
				},
			},
		}
	default:
		return
	}

	// IP payload
	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	// Set EDNS0=4096
	dnsBuffer := gopacket.NewSerializeBuffer()
	err = dnsLayer.SerializeTo(dnsBuffer, options)
	if err != nil {
		fmt.Println("Error: ", err)
		os.Exit(1)
	}
	dnsPayload := dnsBuffer.Bytes()
	higherByte := edns0 / 256
	lowerByte := edns0 % 256
	dnsPayload[len(dnsPayload)-8] = byte(higherByte)
	dnsPayload[len(dnsPayload)-7] = byte(lowerByte)
	dnsPayload = bytes.ReplaceAll(dnsPayload, qnameWAG, qnameAG) // 0xc0, 0x0c

	fmt.Printf(
		"%s : DNS layer size %d\n", time.Now().Format(time.ANSIC), len(dnsPayload),
	)

	payloadBuffer := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(
		payloadBuffer,
		options,
		udpLayer,
		gopacket.Payload(dnsPayload),
	)
	if err != nil {
		fmt.Println("Error: ", err)
		os.Exit(1)
	}
	payload := payloadBuffer.Bytes()

	// Calculate the payload size per fragment
	payloadSize := mtuAG - ethHLenAG - ipv4HLenAG
	payloadSize = payloadSize &^ 7

	// Split the packet data into fragments
	var fragments [][]byte
	for i := 0; i < len(payload); i += payloadSize {
		end := i + payloadSize
		if end > len(payload) {
			end = len(payload)
		}
		fragments = append(fragments, payload[i:end])
	}

	// Iterate over the fragments and send them
	for i, fragment := range fragments {
		ipv4Layer.Payload = fragment
		ipv4Layer.Length = uint16(len(fragment) + ipv4HLenAG)

		// Calculate the FragOffset for the fragment
		fragOffset := uint16(i * payloadSize / 8)
		ipv4Layer.FragOffset = fragOffset

		// Set the IP flags
		if i < len(fragments)-1 {
			ipv4Layer.Flags = layers.IPv4MoreFragments
		} else {
			ipv4Layer.Flags = 0
		}

		buffer := gopacket.NewSerializeBuffer()
		err = gopacket.SerializeLayers(
			buffer,
			options,
			ethernetLayer,
			ipv4Layer,
			gopacket.Payload(fragment),
		)
		if err != nil {
			fmt.Println("Error: ", err)
			os.Exit(1)
		}
		outgoingPacket := buffer.Bytes()

		// Send the fragment using your preferred method (e.g., raw socket, socket library)
		err = handleSendAG.WritePacketData(outgoingPacket)
		if err != nil {
			fmt.Println("Error: ", err)
			os.Exit(1)
		}

		fmt.Printf(
			"%s : frag#%d with size %d\n", time.Now().Format(time.ANSIC), i+1, len(fragment),
		)
	}
}

func dnsResponseAGA4096EDNS0(
	dstIP string, dstPort layers.UDPPort, qname string, qtype layers.DNSType, txid uint16, ttl uint32, rdata string,
	ansI int, edns0 int,
) {
	// Generate a random IPID value for all fragments
	ipID := uint16(rand.Intn(65536)) // Generate a random number between 0 and 65535

	// Each layer
	ethernetLayer := &layers.Ethernet{
		BaseLayer:    layers.BaseLayer{},
		SrcMAC:       srcMacAG,
		DstMAC:       gtwMacAG,
		EthernetType: layers.EthernetTypeIPv4,
		Length:       0,
	}

	ipv4Layer := &layers.IPv4{
		BaseLayer:  layers.BaseLayer{},
		Version:    4,
		IHL:        0,
		TOS:        0,
		Length:     0,
		Id:         ipID,
		Flags:      0,
		FragOffset: 0,
		TTL:        64,
		Protocol:   layers.IPProtocolUDP,
		Checksum:   0,
		SrcIP:      srcIPAG,
		DstIP:      net.ParseIP(dstIP),
		Options:    nil,
		Padding:    nil,
	}

	udpLayer := &layers.UDP{
		BaseLayer: layers.BaseLayer{},
		SrcPort:   layers.UDPPort(srcPortAG),
		DstPort:   layers.UDPPort(dstPort),
		Length:    0,
		Checksum:  0,
	}

	err := udpLayer.SetNetworkLayerForChecksum(ipv4Layer)
	if err != nil {
		fmt.Println("Error: ", err)
		os.Exit(1)
	}

	//domain := strings.ToLower(qname)
	//qnameList := strings.Split(domain, ".")
	//qnameListLen := len(qnameList)
	//ansI := 1
	//if qnameListLen == 3 {
	//	numList := strings.Split(qnameList[0], "-")
	//	numListLen := len(numList)
	//	if numListLen >= 2 {
	//		num, err := strconv.ParseInt(numList[1], 10, 32)
	//		if err == nil {
	//			ansI = int(num)
	//		}
	//	}
	//}

	var ans []layers.DNSResourceRecord
	for i := 0; i < ansI; i++ {
		c := i / 256
		d := i % 256
		an := layers.DNSResourceRecord{
			Name:  qnameAG,
			Type:  layers.DNSTypeA,
			Class: layers.DNSClassIN,
			TTL:   ttl,
			IP:    net.ParseIP(fmt.Sprintf("202.0.%d.%d", c, d)),
		}
		ans = append(ans, an)
	}

	var dnsLayer *layers.DNS
	switch qtype {
	case layers.DNSTypeA:
		dnsLayer = &layers.DNS{
			BaseLayer:    layers.BaseLayer{},
			ID:           txid,
			QR:           true,
			OpCode:       0,
			AA:           true,
			TC:           false,
			RD:           false,
			RA:           false,
			Z:            0,
			ResponseCode: 0,
			QDCount:      1,
			ANCount:      uint16(ansI),
			NSCount:      0,
			ARCount:      1,
			Questions: []layers.DNSQuestion{
				{
					Name:  []byte(qname),
					Type:  layers.DNSTypeA,
					Class: layers.DNSClassIN,
				},
			},
			Answers: ans,
			Additionals: []layers.DNSResourceRecord{
				{
					Name: []byte(nil),
					Type: layers.DNSTypeOPT,
				},
			},
		}
	default:
		return
	}

	// IP payload
	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	// Set EDNS0=4096
	dnsBuffer := gopacket.NewSerializeBuffer()
	err = dnsLayer.SerializeTo(dnsBuffer, options)
	if err != nil {
		fmt.Println("Error: ", err)
		os.Exit(1)
	}
	dnsPayload := dnsBuffer.Bytes()
	higherByte := edns0 / 256
	lowerByte := edns0 % 256
	dnsPayload[len(dnsPayload)-8] = byte(higherByte)
	dnsPayload[len(dnsPayload)-7] = byte(lowerByte)
	dnsPayload = bytes.ReplaceAll(dnsPayload, qnameWAG, qnameAG) // 0xc0, 0x0c

	fmt.Printf(
		"%s : DNS layer size = %d\n", time.Now().Format(time.ANSIC), len(dnsPayload),
	)

	payloadBuffer := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(
		payloadBuffer,
		options,
		udpLayer,
		gopacket.Payload(dnsPayload),
	)
	if err != nil {
		fmt.Println("Error: ", err)
		os.Exit(1)
	}
	payload := payloadBuffer.Bytes()

	// Calculate the payload size per fragment
	payloadSize := mtuAG - ethHLenAG - ipv4HLenAG
	payloadSize = payloadSize &^ 7

	// Split the packet data into fragments
	var fragments [][]byte
	for i := 0; i < len(payload); i += payloadSize {
		end := i + payloadSize
		if end > len(payload) {
			end = len(payload)
		}
		fragments = append(fragments, payload[i:end])
	}

	// Iterate over the fragments and send them
	for i, fragment := range fragments {
		ipv4Layer.Payload = fragment
		ipv4Layer.Length = uint16(len(fragment) + ipv4HLenAG)

		// Calculate the FragOffset for the fragment
		fragOffset := uint16(i * payloadSize / 8)
		ipv4Layer.FragOffset = fragOffset

		// Set the IP flags
		if i < len(fragments)-1 {
			ipv4Layer.Flags = layers.IPv4MoreFragments
		} else {
			ipv4Layer.Flags = 0
		}

		buffer := gopacket.NewSerializeBuffer()
		err = gopacket.SerializeLayers(
			buffer,
			options,
			ethernetLayer,
			ipv4Layer,
			gopacket.Payload(fragment),
		)
		if err != nil {
			fmt.Println("Error: ", err)
			os.Exit(1)
		}
		outgoingPacket := buffer.Bytes()

		// Send the fragment using your preferred method (e.g., raw socket, socket library)
		err = handleSendAG.WritePacketData(outgoingPacket)
		if err != nil {
			fmt.Println("Error: ", err)
			os.Exit(1)
		}

		fmt.Printf(
			"%s : frag#%d with size %d\n", time.Now().Format(time.ANSIC), i+1, len(fragment),
		)
	}
}

func dnsResponseAGA4096(
	dstIP string, dstPort layers.UDPPort, qname string, qtype layers.DNSType, txid uint16, ttl uint32, rdata string,
	ansI int,
) {
	// Generate a random IPID value for all fragments
	ipID := uint16(rand.Intn(65536)) // Generate a random number between 0 and 65535

	// Each layer
	ethernetLayer := &layers.Ethernet{
		BaseLayer:    layers.BaseLayer{},
		SrcMAC:       srcMacAG,
		DstMAC:       gtwMacAG,
		EthernetType: layers.EthernetTypeIPv4,
		Length:       0,
	}

	ipv4Layer := &layers.IPv4{
		BaseLayer:  layers.BaseLayer{},
		Version:    4,
		IHL:        0,
		TOS:        0,
		Length:     0,
		Id:         ipID,
		Flags:      0,
		FragOffset: 0,
		TTL:        64,
		Protocol:   layers.IPProtocolUDP,
		Checksum:   0,
		SrcIP:      srcIPAG,
		DstIP:      net.ParseIP(dstIP),
		Options:    nil,
		Padding:    nil,
	}

	udpLayer := &layers.UDP{
		BaseLayer: layers.BaseLayer{},
		SrcPort:   layers.UDPPort(srcPortAG),
		DstPort:   layers.UDPPort(dstPort),
		Length:    0,
		Checksum:  0,
	}

	err := udpLayer.SetNetworkLayerForChecksum(ipv4Layer)
	if err != nil {
		fmt.Println("Error: ", err)
		os.Exit(1)
	}

	//domain := strings.ToLower(qname)
	//qnameList := strings.Split(domain, ".")
	//qnameListLen := len(qnameList)
	//ansI := 1
	//if qnameListLen == 3 {
	//	numList := strings.Split(qnameList[0], "-")
	//	numListLen := len(numList)
	//	if numListLen >= 2 {
	//		num, err := strconv.ParseInt(numList[1], 10, 32)
	//		if err == nil {
	//			ansI = int(num)
	//		}
	//	}
	//}

	var ans []layers.DNSResourceRecord
	for i := 0; i < ansI; i++ {
		c := i / 256
		d := i % 256
		an := layers.DNSResourceRecord{
			Name:  qnameAG,
			Type:  layers.DNSTypeA,
			Class: layers.DNSClassIN,
			TTL:   ttl,
			IP:    net.ParseIP(fmt.Sprintf("202.0.%d.%d", c, d)),
		}
		ans = append(ans, an)
	}

	var dnsLayer *layers.DNS
	switch qtype {
	case layers.DNSTypeA:
		dnsLayer = &layers.DNS{
			BaseLayer:    layers.BaseLayer{},
			ID:           txid,
			QR:           true,
			OpCode:       0,
			AA:           true,
			TC:           false,
			RD:           false,
			RA:           false,
			Z:            0,
			ResponseCode: 0,
			QDCount:      1,
			ANCount:      uint16(ansI),
			NSCount:      0,
			ARCount:      0,
			Questions: []layers.DNSQuestion{
				{
					Name:  []byte(qname),
					Type:  layers.DNSTypeA,
					Class: layers.DNSClassIN,
				},
			},
			Answers: ans,
		}
	default:
		return
	}

	// IP payload
	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	// DNS
	dnsBuffer := gopacket.NewSerializeBuffer()
	err = dnsLayer.SerializeTo(dnsBuffer, options)
	if err != nil {
		fmt.Println("Error: ", err)
		os.Exit(1)
	}
	dnsPayload := dnsBuffer.Bytes()
	dnsPayload = bytes.ReplaceAll(dnsPayload, qnameWAG, qnameAG) // 0xc0, 0x0c

	fmt.Printf(
		"%s : DNS layer size = %d\n", time.Now().Format(time.ANSIC), len(dnsPayload),
	)

	payloadBuffer := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(
		payloadBuffer,
		options,
		udpLayer,
		gopacket.Payload(dnsPayload),
	)
	if err != nil {
		fmt.Println("Error: ", err)
		os.Exit(1)
	}
	payload := payloadBuffer.Bytes()

	// Calculate the payload size per fragment
	payloadSize := mtuAG - ethHLenAG - ipv4HLenAG
	payloadSize = payloadSize &^ 7

	// Split the packet data into fragments
	var fragments [][]byte
	for i := 0; i < len(payload); i += payloadSize {
		end := i + payloadSize
		if end > len(payload) {
			end = len(payload)
		}
		fragments = append(fragments, payload[i:end])
	}

	// Iterate over the fragments and send them
	for i, fragment := range fragments {
		ipv4Layer.Payload = fragment
		ipv4Layer.Length = uint16(len(fragment) + ipv4HLenAG)

		// Calculate the FragOffset for the fragment
		fragOffset := uint16(i * payloadSize / 8)
		ipv4Layer.FragOffset = fragOffset

		// Set the IP flags
		if i < len(fragments)-1 {
			ipv4Layer.Flags = layers.IPv4MoreFragments
		} else {
			ipv4Layer.Flags = 0
		}

		buffer := gopacket.NewSerializeBuffer()
		err = gopacket.SerializeLayers(
			buffer,
			options,
			ethernetLayer,
			ipv4Layer,
			gopacket.Payload(fragment),
		)
		if err != nil {
			fmt.Println("Error: ", err)
			os.Exit(1)
		}
		outgoingPacket := buffer.Bytes()

		// Send the fragment using your preferred method (e.g., raw socket, socket library)
		err = handleSendAG.WritePacketData(outgoingPacket)
		if err != nil {
			fmt.Println("Error: ", err)
			os.Exit(1)
		}

		fmt.Printf(
			"%s : frag#%d with size %d\n", time.Now().Format(time.ANSIC), i+1, len(fragment),
		)
	}
}

func dnsResponseAG(
	dstIP string, dstPort layers.UDPPort, qname string, qtype layers.DNSType, txid uint16, ttl uint32,
	rdata string,
) {

	if qtype == layers.DNSTypeNS {
		dnsResponseAGNS(dstIP, dstPort, qname, qtype, txid, ttl, rdata)
		return
	}

	if strings.HasPrefix(strings.ToLower(qname), "ns") && qtype == layers.DNSTypeA {
		dnsResponseAGA(dstIP, dstPort, qname, qtype, txid, ttl, rdata)
		return
	}

	if strings.Contains(strings.ToLower(qname), "4096") {
		fmt.Printf("%s : fm %s query %s %s\n", time.Now().Format(time.ANSIC), dstIP, qname, qtype.String())

		now := time.Now().UnixMilli()
		domain := strings.ToLower(qname)
		lockAG.Lock()
		if _, ok := slpTmMapAG[domain]; ok {
			lockAG.Unlock()
		} else {
			slpTmMapAG[domain] = now
			lockAG.Unlock()
		}
		slpTm := int64(0)
		ansI := 1
		edns0 := 0

		qnameList := strings.Split(domain, ".")
		qnameListLen := len(qnameList)
		if qnameListLen == 3 {
			numList := strings.Split(qnameList[0], "-")
			numListLen := len(numList)
			base := 0
			if numList[0] != "4096" {
				base = 1
			}
			if numListLen >= 4 {
				tm, err := strconv.ParseInt(numList[base+1], 10, 32)
				if err == nil {
					slpTm = tm
				}
				num, err := strconv.ParseInt(numList[base+2], 10, 32)
				if err == nil {
					ansI = int(num)
				}
				ed, err := strconv.ParseInt(numList[base+3], 10, 32)
				if err == nil {
					edns0 = int(ed)
				}
			}
		}

		lockAG.Lock()
		old := slpTmMapAG[domain]
		lockAG.Unlock()

		slpTmL := slpTm - (now - old)
		if slpTmL > 0 {
			time.Sleep(time.Duration(slpTmL) * time.Millisecond)
		}

		if edns0 > 0 {
			dnsResponseAGA4096EDNS0(dstIP, dstPort, qname, qtype, txid, ttl, rdata, ansI, edns0)
		} else {
			dnsResponseAGA4096(dstIP, dstPort, qname, qtype, txid, ttl, rdata, ansI)
		}

		fmt.Printf(
			"%s : to %s with %s %s %d num=%d EDNS0=%d\n", time.Now().Format(time.ANSIC), dstIP, qname,
			qtype.String(), ttl, ansI, edns0,
		)

		return
	}

	if qtype == layers.DNSTypeA {
		dnsResponseAGA(dstIP, dstPort, qname, qtype, txid, ttl, rdata)
		return
	}

	if qtype != layers.DNSTypeTXT {
		dnsResponseAGNX(dstIP, dstPort, qname, qtype, txid, ttl, rdata)
		return
	}

	fmt.Printf("%s : fm %s query %s %s\n", time.Now().Format(time.ANSIC), dstIP, qname, qtype.String())

	//if !strings.Contains(strings.ToLower(qname), "dcl") {
	//	return
	//}

	now := time.Now().UnixMilli()
	domain := strings.ToLower(qname)
	lockAG.Lock()
	if _, ok := slpTmMapAG[domain]; ok {
		lockAG.Unlock()
	} else {
		slpTmMapAG[domain] = now
		lockAG.Unlock()
	}
	slpTm := int64(0)
	pktSz := 8
	edns0 := 0

	qnameList := strings.Split(domain, ".")
	qnameListLen := len(qnameList)
	if qnameListLen == 3 {
		ttlList := strings.Split(qnameList[0], "-")
		ttlListLen := len(ttlList)
		base := 0
		if ttlList[0] != "s" {
			base = 1
		}
		if ttlListLen >= 9 {
			tm, err := strconv.ParseInt(ttlList[1+base], 10, 32)
			if err == nil {
				slpTm = tm
			}
			ps, err := strconv.ParseInt(ttlList[2+base], 10, 32)
			if err == nil {
				pktSz = int(ps)
			}
			ed, err := strconv.ParseInt(ttlList[3+base], 10, 32)
			if err == nil {
				edns0 = int(ed)
			}
		}
	}

	lockAG.Lock()
	old := slpTmMapAG[domain]
	lockAG.Unlock()

	slpTmL := slpTm - (now - old)
	if slpTmL > 0 {
		time.Sleep(time.Duration(slpTmL) * time.Millisecond)
	}

	if edns0 > 0 {
		dnsResponseAGTXTEDNS0(dstIP, dstPort, qname, qtype, txid, ttl, rdata, pktSz, edns0)
	} else {
		dnsResponseAGTXT(dstIP, dstPort, qname, qtype, txid, ttl, rdata, pktSz)
	}

	fmt.Printf(
		"%s : to %s with %s %s %d EDNS0=%d\n", time.Now().Format(time.ANSIC), dstIP, qname,
		qtype.String(), ttl, edns0,
	)
}

func main() {
	fmt.Printf("%s : %s\n", time.Now().Format(time.ANSIC), "DNS server starts")

	rand.Seed(time.Now().UnixNano())

	handleSendAG, errAG = pcap.OpenLive(deviceAG, 1024, false, 0*time.Second)
	if errAG != nil {
		fmt.Println("Error: ", errAG)
		os.Exit(1)
	}
	defer handleSendAG.Close()

	handleRecv, errAG := pcap.OpenLive(deviceAG, 1024, false, time.Nanosecond)
	if errAG != nil {
		fmt.Println("Error: ", errAG)
		os.Exit(1)
	}
	defer handleRecv.Close()

	var filter = fmt.Sprintf("dst host %s and udp dst port %d", ipAG, srcPortAG)
	errAG = handleRecv.SetBPFFilter(filter)
	if errAG != nil {
		fmt.Println("Error: ", errAG)
		os.Exit(1)
	}

	errAG = handleRecv.SetDirection(pcap.DirectionIn)
	if errAG != nil {
		fmt.Println("Error: ", errAG)
		os.Exit(1)
	}

	var eth layers.Ethernet
	var ipv4 layers.IPv4
	var udp layers.UDP
	var dns_ layers.DNS
	var decoded []gopacket.LayerType
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ipv4, &udp, &dns_)

	packetSource := gopacket.NewPacketSource(handleRecv, handleRecv.LinkType())
	packetChan := packetSource.Packets()

	for packet := range packetChan {
		if err := parser.DecodeLayers(packet.Data(), &decoded); err != nil {
			continue
		}

		if len(dns_.Questions) <= 0 {
			continue
		}

		if !strings.HasSuffix(strings.ToLower(string(dns_.Questions[0].Name)), domainAG) {
			continue
		}

		ttl := 600
		dstIP := ipv4.SrcIP.String()
		dstPort := udp.SrcPort
		qname := string(dns_.Questions[0].Name)
		qtype := dns_.Questions[0].Type
		txid := dns_.ID
		rdata_ := dstIP

		go dnsResponseAG(dstIP, dstPort, qname, qtype, txid, uint32(ttl), rdata_)
	}
}

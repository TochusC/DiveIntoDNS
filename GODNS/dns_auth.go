/*
@Author : idealeer
@File : Kaweh:dns_server.go
@Software: GoLand
@Time : 6/2/2022 09:31
*/
package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"net"
	"os"
	"strings"
	"time"
)

var (
	deviceC     = "ens160"
	srcMac     = net.HardwareAddr{0x00, 0x50, 0x56, 0xa1, 0x54, 0x6f}
	gtwMac     = net.HardwareAddr{0xdc, 0xda, 0x80, 0xd8, 0xcf, 0x81}
	srcIPC      = net.ParseIP("202.112.238.56")
	srcPort    = 53
	handleSend *pcap.Handle
	err        error
	domainC     = "idealeer.com"
	rdataC      = "192.0.33.8"
)

func dnsResponseC(
	dstIP string, dstPort layers.UDPPort, qname string, qtype layers.DNSType, txid uint16, ttl uint32,
	rdata string,
) {

	//if !strings.Contains(strings.ToLower(qname), "recursive") {
	//	return
	//}

	if !strings.Contains(strings.ToLower(qname), "20") {
		return
	}

	//qnameList := strings.Split(strings.ToLower(qname), ".")
	//qnameListLen := len(qnameList)
	//if qnameListLen == 3 {
	//	ttlList := strings.Split(qnameList[qnameListLen - 3], "-")
	//	ttlListLen := len(ttlList)
	//	if ttlListLen == 3 {
	//		ttl_, err := strconv.ParseInt(ttlList[1], 10, 32)
	//		if err == nil {
	//			ttl = uint32(ttl_)
	//		}
	//	}
	//}

	fmt.Printf("%s : fm %s query %s %s\n", time.Now().Format(time.ANSIC), dstIP, qname, qtype.String())

	ethernetLayer := &layers.Ethernet{
		BaseLayer:    layers.BaseLayer{},
		SrcMAC:       srcMac,
		DstMAC:       gtwMac,
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
		SrcIP:      srcIPC,
		DstIP:      net.ParseIP(dstIP),
		Options:    nil,
		Padding:    nil,
	}

	udpLayer := &layers.UDP{
		BaseLayer: layers.BaseLayer{},
		SrcPort:   layers.UDPPort(srcPort),
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
					IP:    net.ParseIP(rdata),
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

	err = handleSend.WritePacketData(outgoingPacket)
	if err != nil {
		fmt.Println("Error: ", err)
		os.Exit(1)
	}

	fmt.Printf(
		"%s : to %s with %s %s %d\n", time.Now().Format(time.ANSIC), dstIP, qname,
		qtype.String(), ttl,
	)
}

func main() {
	fmt.Printf("%s : %s\n", time.Now().Format(time.ANSIC), "DNS server starts")

	handleSend, err = pcap.OpenLive(deviceC, 1024, false, 0*time.Second)
	if err != nil {
		fmt.Println("Error: ", err)
		os.Exit(1)
	}
	defer handleSend.Close()

	handleRecv, err := pcap.OpenLive(deviceC, 1024, false, time.Nanosecond)
	if err != nil {
		fmt.Println("Error: ", err)
		os.Exit(1)
	}
	defer handleRecv.Close()

	var filter = fmt.Sprintf("ip and udp dst port %d", srcPort)
	err = handleRecv.SetBPFFilter(filter)
	if err != nil {
		fmt.Println("Error: ", err)
		os.Exit(1)
	}

	err = handleRecv.SetDirection(pcap.DirectionIn)
	if err != nil {
		fmt.Println("Error: ", err)
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

		if !strings.HasSuffix(strings.ToLower(string(dns_.Questions[0].Name)), domainC) {
			continue
		}

		ttl := 60
		dstIP := ipv4.SrcIP.String()
		dstPort := udp.SrcPort
		qname := string(dns_.Questions[0].Name)
		qtype := dns_.Questions[0].Type
		txid := dns_.ID
		rdata_ := dstIP

		if strings.Compare(qname, strings.ToLower(qname)) == 0 {
			rdata_ = "127.0.0.0"
		} else {
			rdata_ = "127.0.0.1"
		}

		go dnsResponseC(dstIP, dstPort, qname, qtype, txid, uint32(ttl), rdata_)
	}
}

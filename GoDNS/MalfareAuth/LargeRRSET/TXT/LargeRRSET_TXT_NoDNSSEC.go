/**
 * @Project :   ExploitDNSSEC
 * @File    :   LargeRRSET_TXT_NODNSSEC.go
 * @Contact :	tochus@163.com
 * @License :   (C)Copyright 2024
 * @Description: A DNS server that responds to TXT queries with large TXT records but without DNSSEC.
 *
 * @Modify Time        @Author     @Version    @Description
 * ----------------    --------    --------    -----------
 * 4/8/23 5:34 PM      idealeer    0.0         None
 * 14/10/24 16:28	   4stra       0.1.0       Enable DNSSEC
 * 15/10/24 11:10      4stra       0.2.0       Ethnet Fragmentation
 * 14/10/24 18:48      4stra       0.3.0       Large TXT record without DNSSEC
 */

package main

import (
	"encoding/base64"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strings"
	"time"

	// 微调的gopacket库
	"github.com/tochusc/gopacket"
	"github.com/tochusc/gopacket/layers"
	"github.com/tochusc/gopacket/pcap"
)

// TXT记录载荷长度， 16384，32768，(65536×)
var txtRecordByteLenC = 64000

func genRandomByte(byteLen int) []byte {
	b := make([]byte, byteLen)
	_, err := rand.Read(b)
	if err != nil {
		fmt.Println("Error: ", err)
		os.Exit(1)
	}
	return b
}

func genTXTLoadC(pktSz int) [][]byte {
	txts := make([][]byte, 0)
	batch := pktSz / 255
	mod := pktSz % 255
	for i := 0; i < batch; i++ {
		txts = append(txts, genRandomByte(255))
	}
	if mod > 0 {
		txts = append(txts, genRandomByte(mod))
	}
	return txts
}

var txtLoadC = genTXTLoadC(txtRecordByteLenC)

// DNS服务器配置相关变量
var (
	serverIPC = "10.10.3.3"
	srcPortC  = 53
	deviceC   = "eth0"

	// 以太网最大传输单元：发送方所能接受的最大载荷大小
	mtuC = 1500
	// 以太网帧最大长度：mtuC + ethHeaderLenC = 1514字节
	ethHeaderLenC = 14
	ipHeaderLenC  = 20

	// 全局TTL
	globalTTLC  = 86400
	serverMACC  = net.HardwareAddr{0x02, 0x42, 0x0a, 0x0a, 0x03, 0x03}
	handleSend  *pcap.Handle
	err         error
	domainNameC = []string{"nodnssec.test, ns1.nodnssec.test, www.nodnssec.test"}
)

func decode(s string) []byte {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		fmt.Println("Error decoding base64:", err)
		return nil
	}
	return data
}

func encodeDomainName(signerName string) []byte {
	byteArray := make([]byte, 0)
	labelsArray := strings.Split(signerName, ".")
	for _, label := range labelsArray {
		labelLength := byte(len(label))
		byteArray = append(byteArray, labelLength)
		byteArray = append(byteArray, []byte(label)...)
	}
	return byteArray
}

// dnsResponseC响应DNS请求，生成DNS回复并发送。
func dnsResponseC(dstMAC net.HardwareAddr, dstIP string, dstPort layers.UDPPort, qname string, qtype layers.DNSType, txid uint16) {
	fmt.Printf("%s : fm %s query %s %s\n", time.Now().Format(time.ANSIC), dstIP, qname, qtype.String())

	// Generate a random IPID value for all fragments
	ipID := uint16(rand.Intn(65536)) // Generate a random number between 0 and 65535

	ethernetLayer := &layers.Ethernet{
		BaseLayer:    layers.BaseLayer{},
		SrcMAC:       serverMACC,
		DstMAC:       dstMAC,
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
		SrcIP:      net.ParseIP(serverIPC),
		DstIP:      net.ParseIP(dstIP),
		Options:    nil,
		Padding:    nil,
	}

	udpLayer := &layers.UDP{
		BaseLayer: layers.BaseLayer{},
		SrcPort:   layers.UDPPort(srcPortC),
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
			NSCount:      1,
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
					Name:  []byte(qname),
					Type:  layers.DNSTypeTXT,
					Class: layers.DNSClassIN,
					TTL:   uint32(globalTTLC),
					TXTs:  txtLoadC,
				},
			},
			Authorities: []layers.DNSResourceRecord{
				{
					Name:  []byte("nodnssec.test"),
					Type:  layers.DNSTypeNS,
					Class: layers.DNSClassIN,
					TTL:   uint32(globalTTLC),
					NS:    []byte("ns1.nodnssec.test"),
				},
			},
			Additionals: []layers.DNSResourceRecord{
				{
					Name:  []byte("ns1.nodnssec.test"),
					Type:  layers.DNSTypeA,
					Class: layers.DNSClassIN,
					TTL:   uint32(globalTTLC),
					IP:    net.ParseIP(serverIPC),
				},
			},
		}
	default:
		// 未知查询类型，返回NXDOMAIN
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
			ResponseCode: 3, // NXDOMAIN
			QDCount:      1,
			Questions: []layers.DNSQuestion{
				{
					Name:  []byte(qname),
					Type:  qtype,
					Class: layers.DNSClassIN,
				},
			},
		}
	}

	// DNS层序列化
	dnsBuffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	err = dnsLayer.SerializeTo(dnsBuffer, options)
	if err != nil {
		fmt.Println("DNS Layer Serialzing Error: ", err)
		os.Exit(1)
	}
	dnsPayload := dnsBuffer.Bytes()
	fmt.Printf(
		"%s : DNS layer size = %d\n", time.Now().Format(time.ANSIC), len(dnsPayload),
	)

	// UDP层序列化
	udpBuffer := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(
		udpBuffer,
		options,
		udpLayer,
		gopacket.Payload(dnsPayload),
	)
	if err != nil {
		fmt.Println("UDP Layer Serialzing Error: ", err)
		os.Exit(1)
	}
	udpPayload := udpBuffer.Bytes()
	fmt.Printf(
		"%s : UDP layer size = %d\n", time.Now().Format(time.ANSIC), len(udpPayload),
	)

	// 计算每个分片的载荷大小：MTU - IP头部长度
	payloadSize := mtuC - ipHeaderLenC
	// 确保每个分片的载荷大小是8的倍数
	payloadSize = payloadSize &^ 7

	// 分片
	fragments := make([][]byte, 0)
	for i := 0; i < len(udpPayload); i += payloadSize {
		end := i + payloadSize
		if end > len(udpPayload) {
			end = len(udpPayload)
		}
		fragments = append(fragments, udpPayload[i:end])
	}

	// 发送分片
	for i, fragment := range fragments {
		// 设置IP层长度
		ipv4Layer.Length = uint16(ipHeaderLenC + len(fragment))

		// 设置IP层标志
		if i == len(fragments)-1 {
			ipv4Layer.Flags = 0
		} else {
			ipv4Layer.Flags = layers.IPv4MoreFragments
		}

		// 计算偏移量
		ipv4Layer.FragOffset = uint16(i * payloadSize / 8)

		// IP层序列化
		ipv4Buffer := gopacket.NewSerializeBuffer()
		err = gopacket.SerializeLayers(
			ipv4Buffer,
			options,
			ipv4Layer,
			gopacket.Payload(fragment),
		)
		if err != nil {
			fmt.Println("IPv4 Layer Serialzing Error: ", err)
			os.Exit(1)
		}
		ipv4Payload := ipv4Buffer.Bytes()

		// 以太网层序列化
		ethernetBuffer := gopacket.NewSerializeBuffer()
		err = gopacket.SerializeLayers(
			ethernetBuffer,
			options,
			ethernetLayer,
			gopacket.Payload(ipv4Payload),
		)
		if err != nil {
			fmt.Println("Ethernet Layer Serialzing Error: ", err)
			os.Exit(1)
		}

		// 发送数据包
		outgoingPacket := ethernetBuffer.Bytes()
		err = handleSend.WritePacketData(outgoingPacket)
		if err != nil {
			fmt.Println("Error sending packet: ", err)
			os.Exit(1)
		}

		fmt.Printf(
			"%s : frag#%d with size %d\n", time.Now().Format(time.ANSIC), i+1, len(fragment),
		)
	}

	fmt.Printf(
		"%s : to %s with %s %s %d\n", time.Now().Format(time.ANSIC), dstIP, qname,
		qtype.String(), globalTTLC,
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

	// 设置过滤器
	var filter = fmt.Sprintf("ip and udp dst port %d", srcPortC)
	err = handleRecv.SetBPFFilter(filter)
	if err != nil {
		fmt.Println("Error: ", err)
		os.Exit(1)
	}

	// 设置Handler为接收方向
	err = handleRecv.SetDirection(pcap.DirectionIn)
	if err != nil {
		fmt.Println("Error: ", err)
		os.Exit(1)
	}

	//	设置解析器
	var eth layers.Ethernet
	var ipv4 layers.IPv4
	var udp layers.UDP
	var dns_ layers.DNS
	var decoded []gopacket.LayerType
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ipv4, &udp, &dns_)
	//	设置数据包源
	packetSource := gopacket.NewPacketSource(handleRecv, handleRecv.LinkType())
	packetChan := packetSource.Packets()
	//	接收数据包并解析
	for packet := range packetChan {
		if err := parser.DecodeLayers(packet.Data(), &decoded); err != nil {
			continue
		}

		if len(dns_.Questions) <= 0 {
			continue
		}

		dstMAC := eth.SrcMAC
		dstIP := ipv4.SrcIP.String()
		dstPort := udp.SrcPort
		qname := string(dns_.Questions[0].Name)
		qtype := dns_.Questions[0].Type
		txid := dns_.ID

		go dnsResponseC(dstMAC, dstIP, dstPort, qname, qtype, txid)
	}
}

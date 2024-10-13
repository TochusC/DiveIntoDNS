/*
@Author : idealeer&4stra
@File : dns_auth.go
@Software: GoLand
@Time : 6/2/2022 09:31

	: 10/12/2024 17:26
*/
package main

import (
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/tochusc/gopacket"
	"github.com/tochusc/gopacket/layers"
	"github.com/tochusc/gopacket/pcap"
)

// DNS服务器配置相关变量
var (
	serverIPC  = "10.10.3.3"
	srcPortC   = 53
	deviceC    = "eth0"
	serverMACC = net.HardwareAddr{0x02, 0x42, 0x0a, 0x0a, 0x03, 0x03}
	handleSend *pcap.Handle
	err        error
)

// DNSSEC验证相关变量（每次签名都需修改其中值）
var (
	globalTTLC  = 86400
	expirationC = "202410121726"
	inceptionC  = "202310121726"

	zskKeyTagC = 6350
	kskKeyTagC = 30130

	signerNameC = "keytrap.test."
	signaturesC = map[string]string{
		"www.keytrap.test.": "1111",
		"keytrap.test.":     "",
		"ns1.keytrap.test.": "Kb3NEkEkeBuxcpIsRTrBx7QPRk+LQN75ExRKzyiCAkgpz4k7+0lCMKyRcEWGQ6Ow28IFK+FV+lkdRr4uVxsjpVmc5ZtTJjFEfNVv3UCyHufrX4lvneIUYfls6zTR5RBq",
		"ZSK":               "Kb3NEkEkeBuxcpIsRTrBx7QPRk+LQN75ExRKzyiCAkgpz4k7+0lCMKyRcEWGQ6Ow28IFK+FV+lkdRr4uVxsjpVmc5ZtTJjFEfNVv3UCyHufrX4lvneIUYfls6zTR5RBq",
		"KSK":               "Kb3NEkEkeBuxcpIsRTrBx7QPRk+LQN75ExRKzyiCAkgpz4k7+0lCMKyRcEWGQ6Ow28IFK+FV+lkdRr4uVxsjpVmc5ZtTJjFEfNVv3UCyHufrX4lvneIUYfls6zTR5RBq",
	}
	dnskeyC = map[string]string{
		"ZSK": "Kb3NEkEkeBuxcpIsRTrBx7QPRk+LQN75ExRKzyiCAkgpz4k7+0lCMKyRcEWGQ6Ow28IFK+FV+lkdRr4uVxsjpVmc5ZtTJjFEfNVv3UCyHufrX4lvneIUYfls6zTR5RBq",
		"KSK": "Kb3NEkEkeBuxcpIsRTrBx7QPRk+LQN75ExRKzyiCAkgpz4k7+0lCMKyRcEWGQ6Ow28IFK+FV+lkdRr4uVxsjpVmc5ZtTJjFEfNVv3UCyHufrX4lvneIUYfls6zTR5RBq",
	}
)

func decode(s string) []byte {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		fmt.Println("Error decoding base64:", err)
		return nil
	}
	return data
}

func encodeSignerName(signerName string) []byte {
	byteArray := make([]byte, 0)
	labelsArray := strings.Split(signerName, ".")
	for _, label := range labelsArray {
		labelLength := byte(len(label))
		if labelLength > 0 {
			byteArray = append(byteArray, labelLength)
			byteArray = append(byteArray, []byte(label)...)
		}
	}
	return byteArray
}

var (
	globalTTL = uint32(globalTTLC)

	expirationTimestamp, _ = time.Parse("200601021504", expirationC)
	expiration             = uint32(expirationTimestamp.UTC().Unix())

	inceptionTimestamp, _ = time.Parse("200601021504", inceptionC)
	inception             = uint32(inceptionTimestamp.UTC().Unix())

	zskKeyTag = uint16(zskKeyTagC)
	kskKeyTag = uint16(kskKeyTagC)

	signerName = encodeSignerName(signerNameC)
	signatures = map[string][]byte{
		"www.keytrap.test.": decode(signaturesC["www.keytrap.test."]),
		"keytrap.test.":     decode(signaturesC["keytrap.test."]),
		"ns1.keytrap.test.": decode(signaturesC["ns1.keytrap.test."]),
		"ZSK":               decode(signaturesC["ZSK"]),
		"KSK":               decode(signaturesC["KSK"]),
	}
	dnskey = map[string][]byte{
		"ZSK": decode(dnskeyC["ZSK"]),
		"KSK": decode(dnskeyC["KSK"]),
	}
)

var rrsig = map[string]*RRSIG{
	"www.keytrap.test": {
		TypeCovered: 1,
		Algorithm:   14,
		Labels:      3,
		OriginalTTL: globalTTL,
		Expiration:  expiration,
		Inception:   inception,
		KeyTag:      zskKeyTag,
		SignerName:  signerName,
		Signature:   signatures["www.keytrap.test."],
	},
	"keytrap.test": {
		TypeCovered: 2,
		Algorithm:   14,
		Labels:      2,
		OriginalTTL: globalTTL,
		Expiration:  expiration,
		Inception:   inception,
		KeyTag:      zskKeyTag,
		SignerName:  signerName,
		Signature:   signatures["keytrap.test."],
	},
	"ns1.keytrap.test": {
		TypeCovered: 1,
		Algorithm:   14,
		Labels:      3,
		OriginalTTL: globalTTL,
		Expiration:  expiration,
		Inception:   inception,
		KeyTag:      zskKeyTag,
		SignerName:  signerName,
		Signature:   signatures["ns1.keytrap.test."],
	},
	"ZSK": {
		TypeCovered: 1,
		Algorithm:   14,
		Labels:      2,
		OriginalTTL: globalTTL,
		Expiration:  expiration,
		Inception:   inception,
		KeyTag:      zskKeyTag,
		SignerName:  signerName,
		Signature:   signatures["ZSK"],
	},
	"KSK": {
		TypeCovered: 1,
		Algorithm:   14,
		Labels:      2,
		OriginalTTL: globalTTL,
		Expiration:  expiration,
		Inception:   inception,
		KeyTag:      kskKeyTag,
		SignerName:  signerName,
		Signature:   signatures["KSK"],
	},
}

type RRSIG struct {
	TypeCovered uint16
	Algorithm   uint8
	Labels      uint8
	OriginalTTL uint32
	Expiration  uint32
	Inception   uint32
	KeyTag      uint16
	SignerName  []byte
	Signature   []byte
}

// 字节化RRSIG
func (rrsig *RRSIG) Serialize() []byte {
	b := make([]byte, 0)
	b = append(b, byte(rrsig.TypeCovered>>8), byte(rrsig.TypeCovered))
	b = append(b, rrsig.Algorithm)
	b = append(b, rrsig.Labels)
	b = append(b, byte(rrsig.OriginalTTL>>24), byte(rrsig.OriginalTTL>>16), byte(rrsig.OriginalTTL>>8), byte(rrsig.OriginalTTL))
	b = append(b, byte(rrsig.Expiration>>24), byte(rrsig.Expiration>>16), byte(rrsig.Expiration>>8), byte(rrsig.Expiration))
	b = append(b, byte(rrsig.Inception>>24), byte(rrsig.Inception>>16), byte(rrsig.Inception>>8), byte(rrsig.Inception))
	b = append(b, byte(rrsig.KeyTag>>8), byte(rrsig.KeyTag))
	b = append(b, rrsig.SignerName...)
	b = append(b, 0)
	b = append(b, rrsig.Signature...)
	for index, rbyte := range b {
		switch index {
		case 0:
			fmt.Println("TypeCovered:")
		case 2:
			fmt.Println()
			fmt.Println("Algorithm:")
		case 3:
			fmt.Println()
			fmt.Println("Labels:")
		case 4:
			fmt.Println()
			fmt.Println("OriginalTTL:")
		case 8:
			fmt.Println()
			fmt.Println("Expiration:")
		case 12:
			fmt.Println()
			fmt.Println("Inception:")
		case 16:
			fmt.Println()
			fmt.Println("KeyTag:")
		case 18:
			fmt.Println()
			fmt.Println("SignerName:")
		case 18 + len(rrsig.SignerName):
			fmt.Println()
			fmt.Println("Signature:")

		}
		fmt.Printf("%02x ", rbyte)
	}
	fmt.Println()
	return b
}

// 计算RRSIG RDATA长度
func (rrsig *RRSIG) Len() uint16 {
	return uint16(18 + len(rrsig.SignerName) + 1 + len(rrsig.Signature))
}

// dnsResponseC响应DNS请求，生成DNS回复并发送。
func dnsResponseC(dstMAC net.HardwareAddr, dstIP string, dstPort layers.UDPPort, qname string, qtype layers.DNSType, txid uint16) {
	fmt.Printf("%s : fm %s query %s %s\n", time.Now().Format(time.ANSIC), dstIP, qname, qtype.String())

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
		Id:         0,
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
			ANCount:      2,
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
					TTL:   uint32(globalTTLC),
					IP:    net.ParseIP(serverIPC),
				},
				// RRSIG
				{
					Name:       []byte(qname),
					Type:       46,
					Class:      layers.DNSClassIN,
					TTL:        uint32(globalTTLC),
					DataLength: rrsig[qname].Len(),
					Data:       rrsig[qname].Serialize(),
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

/**
 * @Project :   ExploitDNSSEC
 * @File    :   automatic_rrsig.go
 * @Contact :	tochus@163.com
 * @License :   (C)Copyright 2024
 * @Description: A Test DNS server that responds to DNS queries with automatic generated RRSIG records.
 *
 * @Modify Time        @Author     @Version    @Description
 * ----------------    --------    --------    -----------
 * 4/8/23 5:34 PM      idealeer    0.0         None
 * 14/10/24 16:28	   4stra       0.1.0       Enable DNSSEC
 * 15/10/24 11:10      4stra       0.2.0       Ethnet Fragmentation
 * 17/10/24 20:12 	   4stra       1.0.0       Switch to using gopacket/gopacet
 * 18/10/24 11:53      4stra       1.0.1	   Optimizations
 * 19/10/24 11:33	   4stra	   2.0.0       Automatic RRSIG Generation
 * 20/10/24 11:47	   4stra	   2.1.0       Generate RRSET RRSIG
 * 20/10/24 12:00	   4stra	   2.1.1       Optimize
 * 20/10/14 14:59      4stra       2.2.0       Go GoDNS!
 */

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/big"
	mrand "math/rand"
	"net"
	"os"
	"strings"
	"time"

	// 微调的gopacket库
	"github.com/tochusc/gopacket"
	"github.com/tochusc/gopacket/layers"
	"github.com/tochusc/gopacket/pcap"
)

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

	// 需要替换为本机MAC地址
	serverMACC = net.HardwareAddr{0x02, 0x42, 0x0a, 0x0a, 0x03, 0x03}
	handleSend *pcap.Handle
	err        error

	// 所管辖的域名
	domainNameC = map[string]struct{}{
		"www.keytrap.test": {},
		"keytrap.test":     {},
		"ns1.keytrap.test": {},
	}
)

// DNSSEC验证相关变量
var (
	globalTTLC = 86400

	// La frangcais!
	maintenant = "20241018000000"

	// algorithmC = 14
	signerNameCT = "keytrap.test"

	publicKeyCT = map[string]string{
		"ZSK": "DcYreAh+USsK1mtv7bSR2iaQvShPUqCy7l/BRQXttAFupXp6pUaQZS+kii+H2JJqd+rS4YgC3KCd/by8yQi5j+WSy2yRprSuFuDyqZMFnDT/Py+nGjmIa59+W1iMdEYb",
		"KSK": "MzJsFTtAo0j8qGpDIhEMnK4ImTyYwMwDPU5gt/FaXd6TOw6AvZDAj2hlhZvaxMXV6xCw1MU5iPv5ZQrb3NDLUU+TW07imJ5GD9YKi0Qiiypo+zhtL4aGaOG+870yHwuY",
	}

	privateKeyCT = map[string]string{
		"ZSK": "hj22bHPVtSrK+hVbwBKRyEUsPzZuzWRLodxoP3U0r6CvGjF3/vaWtJ4qiSpMi5AY",
		"KSK": "ppaXHmb7u1jOxEzrLzuGKzbjmSLIK4gEhQOvws+cpBQyJbCwIM1Nrk4j5k94CP9e",
	}
)

var (
	timestampCT, _ = time.Parse("20060102150405", maintenant)
	timestampC     = uint32(timestampCT.UTC().Unix())

	signerNameC = []byte(signerNameCT)

	pubilickeyC = map[string][]byte{
		"ZSK": base64Decode(publicKeyCT["ZSK"]),
		"KSK": base64Decode(publicKeyCT["KSK"]),
	}
	privateKeyC = map[string][]byte{
		"ZSK": base64Decode(privateKeyCT["ZSK"]),
		"KSK": base64Decode(privateKeyCT["KSK"]),
	}

	dnskeyC = map[string]layers.DNSKEY{
		"ZSK": {
			Flags:     layers.DNSKEYFlagZoneKey,
			Protocol:  3,
			Algorithm: layers.DNSSECAlgorithmECDSAP384SHA384,
			PublicKey: pubilickeyC["ZSK"],
		},
		"KSK": {
			Flags:     layers.DNSKEYFlagSecureEntryPoint,
			Protocol:  3,
			Algorithm: layers.DNSSECAlgorithmECDSAP384SHA384,
			PublicKey: pubilickeyC["KSK"],
		},
	}
	keytagC = map[string]uint16{
		"ZSK": calculateKeyTag(dnskeyC["ZSK"]),
		"KSK": calculateKeyTag(dnskeyC["KSK"]),
	}
)

var rrC = map[string]layers.DNSResourceRecord{
	"www.keytrap.test": layers.DNSResourceRecord{
		Name:  []byte("www.keytrap.test"),
		Type:  layers.DNSTypeA,
		Class: layers.DNSClassIN,
		TTL:   uint32(globalTTLC),
		IP:    net.ParseIP(serverIPC),
	},
	"keytrap.test": layers.DNSResourceRecord{
		Name:  []byte("keytrap.test"),
		Type:  layers.DNSTypeNS,
		Class: layers.DNSClassIN,
		TTL:   uint32(globalTTLC),
		NS:    []byte("ns1.keytrap.test"),
	},
	"ns1.keytrap.test": layers.DNSResourceRecord{
		Name:  []byte("ns1.keytrap.test"),
		Type:  layers.DNSTypeA,
		Class: layers.DNSClassIN,
		TTL:   uint32(globalTTLC),
		IP:    net.ParseIP(serverIPC),
	},
	"ZSK": layers.DNSResourceRecord{
		Name:   []byte("keytrap.test"),
		Type:   layers.DNSTypeDNSKEY,
		Class:  layers.DNSClassIN,
		TTL:    uint32(globalTTLC),
		DNSKEY: dnskeyC["ZSK"],
	},
	"KSK": layers.DNSResourceRecord{
		Name:   []byte("keytrap.test"),
		Type:   layers.DNSTypeDNSKEY,
		Class:  layers.DNSClassIN,
		TTL:    uint32(globalTTLC),
		DNSKEY: dnskeyC["KSK"],
	},
}

var rrsigC = map[string]layers.DNSResourceRecord{
	"www.keytrap.test": GenRRSIG(
		[]layers.DNSResourceRecord{
			rrC["www.keytrap.test"],
		},
		keytagC["ZSK"],
		timestampC,
		signerNameC,
		privateKeyC["ZSK"],
	),
	"keytrap.test": GenRRSIG(
		[]layers.DNSResourceRecord{
			rrC["keytrap.test"],
		},
		keytagC["ZSK"],
		timestampC,
		signerNameC,
		privateKeyC["ZSK"],
	),
	"ns1.keytrap.test": GenRRSIG(
		[]layers.DNSResourceRecord{
			rrC["ns1.keytrap.test"],
		},
		keytagC["ZSK"],
		timestampC,
		signerNameC,
		privateKeyC["ZSK"],
	),
	"DNSKEY": GenRRSIG(
		[]layers.DNSResourceRecord{
			rrC["ZSK"],
			rrC["KSK"],
		},
		keytagC["KSK"],
		timestampC,
		signerNameC,
		privateKeyC["KSK"],
	),
}

// dnsResponseC响应DNS请求，生成DNS回复并发送。
func dnsResponseC(dstMAC net.HardwareAddr, dstIP string, dstPort layers.UDPPort, qname string, qtype layers.DNSType, txid uint16) {
	fmt.Printf("%s : fm %s query %s %s\n", time.Now().Format(time.ANSIC), dstIP, qname, qtype.String())

	// 生成随机IP标识符
	ipID := uint16(mrand.Intn(65536))

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
	case layers.DNSTypeA:
		if _, ok := domainNameC[qname]; !ok {
			// 未配置的域名，返回NXDOMAIN
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
						Type:  layers.DNSTypeA,
						Class: layers.DNSClassIN,
					},
				},
			}
		} else {
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
				NSCount:      2,
				ARCount:      2,
				Questions: []layers.DNSQuestion{
					{
						Name:  []byte(qname),
						Type:  layers.DNSTypeA,
						Class: layers.DNSClassIN,
					},
				},
				Answers: []layers.DNSResourceRecord{
					rrC[qname],
					rrsigC[qname],
				},
				Authorities: []layers.DNSResourceRecord{
					rrC["keytrap.test"],
					rrsigC["keytrap.test"],
				},
				Additionals: []layers.DNSResourceRecord{
					rrC["ns1.keytrap.test"],
					rrsigC["ns1.keytrap.test"],
				},
			}
		}
	case layers.DNSTypeDNSKEY:
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
			ANCount:      4,
			NSCount:      0,
			ARCount:      0,
			Questions: []layers.DNSQuestion{
				{
					Name:  []byte(qname),
					Type:  layers.DNSTypeDNSKEY,
					Class: layers.DNSClassIN,
				},
			},
			Answers: []layers.DNSResourceRecord{
				rrC["ZSK"],
				rrC["KSK"],
				rrsigC["DNSKEY"],
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

func base64Decode(s string) []byte {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		fmt.Println("Error decoding base64:", err)
		return nil
	}
	return data
}

func encodeDomainName(domainName string) []byte {
	var domainNameBytes []byte
	for _, label := range strings.Split(domainName, ".") {
		domainNameBytes = append(domainNameBytes, byte(len(label)))
		domainNameBytes = append(domainNameBytes, []byte(label)...)
	}
	domainNameBytes = append(domainNameBytes, 0)
	return domainNameBytes
}

// GenRRSIG 生成RRSIG记录
func GenRRSIG(rrset []layers.DNSResourceRecord, keytag uint16, timestamp uint32, signerName, privKeyRawData []byte) layers.DNSResourceRecord {
	// 准备数据
	data := make([]byte, 65536)
	offset := 0

	rrsig := layers.DNSRRSIG{
		TypeCovered: rrset[0].Type,
		Algorithm:   layers.DNSSECAlgorithmECDSAP384SHA384,
		Labels:      uint8(strings.Count(string(rrset[0].Name), ".") + 1),
		OriginalTTL: rrset[0].TTL,
		Expiration:  uint32(timestamp) + 86400*30,
		Inception:   uint32(timestamp),
		KeyTag:      keytag,
		SignerName:  encodeDomainName(string(signerName)),
		Signature:   nil,
	}

	// signature = sign(RRSIG_RDATA | RR(1) | RR(2) | ...)
	// RRSIG_RDATA
	binary.BigEndian.PutUint16(data[offset:], uint16(rrsig.TypeCovered))
	data[offset+2] = uint8(rrsig.Algorithm)
	data[offset+3] = rrsig.Labels
	binary.BigEndian.PutUint32(data[offset+4:], rrsig.OriginalTTL)
	binary.BigEndian.PutUint32(data[offset+8:], rrsig.Expiration)
	binary.BigEndian.PutUint32(data[offset+12:], rrsig.Inception)
	binary.BigEndian.PutUint16(data[offset+16:], rrsig.KeyTag)
	offset += 18
	offset += copy(data[offset:], rrsig.SignerName)

	// RR = owner | type | class | TTL | RDATA length | RDATA
	for _, rr := range rrset {
		// owner
		owner := encodeDomainName(string(rr.Name))
		offset += copy(data[offset:], owner)
		binary.BigEndian.PutUint16(data[offset:], uint16(rr.Type))
		binary.BigEndian.PutUint16(data[offset+2:], uint16(rr.Class))
		binary.BigEndian.PutUint32(data[offset+4:], uint32(rr.TTL))
		offset += 8
		// RDATA length
		rdlen := recSize(&rr)
		binary.BigEndian.PutUint16(data[offset:], uint16(rdlen))
		offset += 2
		// RDATA
		rdata := serializeRDATA(&rr)
		offset += copy(data[offset:], rdata)
	}

	// FIN
	data = data[:offset]

	// 计算哈希摘要
	hashed := sha512.Sum384(data)

	// 解析私钥
	privKey, _ := parsePrivateKey(privKeyRawData)

	// 签名哈希摘要
	r, s, _ := ecdsa.Sign(rand.Reader, privKey, hashed[:])

	// 将签名结果转换为字节数组
	signature := append(r.Bytes(), s.Bytes()...)

	// 准备 RRSIG
	rrsig.Signature = signature
	rrsigRR := layers.DNSResourceRecord{
		Name:  rrset[0].Name,
		Type:  layers.DNSTypeRRSIG,
		Class: layers.DNSClassIN,
		TTL:   rrset[0].TTL,
		RRSIG: rrsig,
	}
	return rrsigRR
}

func calculateKeyTag(key layers.DNSKEY) uint16 {
	rdata := make([]byte, 0)
	rdata = append(rdata, byte(key.Flags>>8))
	rdata = append(rdata, byte(key.Flags))
	rdata = append(rdata, byte(key.Protocol))
	rdata = append(rdata, byte(key.Algorithm))
	rdata = append(rdata, key.PublicKey...)

	var ac uint32
	for i := 0; i < len(rdata); i++ {
		if i&1 == 1 {
			ac += uint32(rdata[i])
		} else {
			ac += uint32(rdata[i]) << 8
		}
	}

	ac += ac >> 16 & 0xFFFF
	return uint16(ac & 0xFFFF)
}

func serializeRDATA(rr *layers.DNSResourceRecord) []byte {
	rdata := make([]byte, 65536)
	offset := 0
	switch rr.Type {
	case layers.DNSTypeA:
		offset = copy(rdata[:], rr.IP.To4())
	case layers.DNSTypeAAAA:
		offset = copy(rdata[:], rr.IP)
	case layers.DNSTypeNS:
		domainName := encodeDomainName(string(rr.NS))
		offset += copy(rdata[offset:], domainName)
	case layers.DNSTypeCNAME:
		domainName := encodeDomainName(string(rr.CNAME))
		offset += copy(rdata[offset:], domainName)
	case layers.DNSTypeTXT:
		for _, txt := range rr.TXTs {
			rdata[offset] = byte(len(txt))
			copy(rdata[offset+1:], txt)
			offset += 1 + len(txt)
		}
	case layers.DNSTypeURI:
		binary.BigEndian.PutUint16(rdata[offset:], rr.URI.Priority)
		binary.BigEndian.PutUint16(rdata[offset+2:], rr.URI.Weight)
		offset += 4
		offset += copy(rdata[offset:], rr.URI.Target)
	case layers.DNSTypeOPT:
		for _, opt := range rr.OPT {
			binary.BigEndian.PutUint16(rdata[offset:], uint16(opt.Code))
			binary.BigEndian.PutUint16(rdata[offset:], uint16(len(opt.Data)))
			offset += 4
			offset += copy(rdata[offset:], opt.Data)
		}
	case layers.DNSTypeRRSIG:
		binary.BigEndian.PutUint16(rdata[offset:], uint16(rr.RRSIG.TypeCovered))
		rdata[offset+2] = uint8(rr.RRSIG.Algorithm)
		rdata[offset+3] = rr.RRSIG.Labels
		binary.BigEndian.PutUint32(rdata[offset+4:], rr.RRSIG.OriginalTTL)
		binary.BigEndian.PutUint32(rdata[offset+8:], rr.RRSIG.Expiration)
		binary.BigEndian.PutUint32(rdata[offset+12:], rr.RRSIG.Inception)
		binary.BigEndian.PutUint16(rdata[offset+16:], rr.RRSIG.KeyTag)
		offset += 18
		offset += copy(rdata[offset:], rr.RRSIG.SignerName)
		offset += copy(rdata[offset:], rr.RRSIG.Signature)
	case layers.DNSTypeDNSKEY:
		binary.BigEndian.PutUint16(rdata[offset:], uint16(rr.DNSKEY.Flags))
		rdata[offset+2] = uint8(rr.DNSKEY.Protocol)
		rdata[offset+3] = uint8(rr.DNSKEY.Algorithm)
		offset += 4
		offset += copy(rdata[offset:], rr.DNSKEY.PublicKey)
	default:
		if rr.Data != nil {
			copy(rdata[offset:], rr.Data)
		} else {
			return nil
		}
	}
	return rdata[:offset]
}

func recSize(rr *layers.DNSResourceRecord) int {
	switch rr.Type {
	case layers.DNSTypeA:
		return 4
	case layers.DNSTypeAAAA:
		return 16
	case layers.DNSTypeNS:
		return len(rr.NS) + 2
	case layers.DNSTypeCNAME:
		return len(rr.CNAME) + 2
	case layers.DNSTypePTR:
		return len(rr.PTR) + 2
	case layers.DNSTypeSOA:
		return len(rr.SOA.MName) + 2 + len(rr.SOA.RName) + 2 + 20
	case layers.DNSTypeMX:
		return 2 + len(rr.MX.Name) + 2
	case layers.DNSTypeTXT:
		l := len(rr.TXTs)
		for _, txt := range rr.TXTs {
			l += len(txt)
		}
		return l
	case layers.DNSTypeSRV:
		return 6 + len(rr.SRV.Name) + 2
	case layers.DNSTypeURI:
		return 4 + len(rr.URI.Target)
	case layers.DNSTypeOPT:
		l := len(rr.OPT) * 4
		for _, opt := range rr.OPT {
			l += len(opt.Data)
		}
		return l
	case layers.DNSTypeRRSIG:
		return 18 + len(rr.RRSIG.SignerName) + len(rr.RRSIG.Signature)
	case layers.DNSTypeDNSKEY:
		return 4 + len(rr.DNSKEY.PublicKey)
	default:
		if rr.Data != nil {
			return int(rr.DataLength)
		} else {
			return 0
		}
	}
}

func parsePrivateKey(privKeyBytes []byte) (*ecdsa.PrivateKey, error) {
	curve := elliptic.P384()
	privKey := new(ecdsa.PrivateKey)
	privKey.PublicKey.Curve = curve
	privKey.D = new(big.Int).SetBytes(privKeyBytes)
	privKey.PublicKey.X, privKey.PublicKey.Y = curve.ScalarBaseMult(privKeyBytes)
	return privKey, nil
}

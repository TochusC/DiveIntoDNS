/**
 * @Project :   ExploitDNSSEC
 * @File    :   dns_auth.go
 * @Contact :	tochus@163.com
 * @License :   (C)Copyright 2024
 * @Description: A DNS server that responds to DNS queries with DNSSEC and Ethernet fragmentation.
 *
 * @Modify Time        @Author     @Version    @Description
 * ----------------    --------    --------    -----------
 * 4/8/23 5:34 PM      idealeer    0.0         None
 * 14/10/24 16:28	   4stra       0.1.0       Enable DNSSEC
 * 15/10/24 11:10      4stra       0.2.0       Ethnet Fragmentation
 * 17/10/24 20:12 	   4stra       1.0.0       Switch to using gopacket/gopacet
 * 18/10/24 11:53      4stra       1.0.1	   Optimizations
 */

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"

	// 微调的gopacket库

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

// DNSSEC验证相关变量（每次签名都需修改其中值）
var (
	globalTTLC = 86400

	expirationC = "20241112125051"
	inceptionC  = "20241013125051"

	zskKeyTagC = 6350
	kskKeyTagC = 30130

	// algorithmC = 14

	signerNameC = "keytrap.test"
	signaturesC = map[string]string{
		"www.keytrap.test": "YsPPs2WpuC0h7+eYanDr3NZ+boDSkUAUHjhKVGzMlHpkpyjTMpJYsHk/M9Hm2isq5loXKpCS43ILkb/9+kBUpyjS+kMQwN+V7v+4fPECpaA+B+sh1S0E2zT0l24JBbBw",
		"keytrap.test":     "2g+7jwHGSajuBtOYYM1O+/AC64CdwRaM4lNUryxYdz+Vn/ZqUL/Rxp/RHEFja5a+SwDzME6VwzY47BFLpoQC04afzaxwKSTpn1mw2tRxS+ZLvI/s0XhRLLGbVk0vf9pb",
		"ns1.keytrap.test": "efiWRospV7iPUMpT6T81FbZ2x10HvEbgS+L/8TvINibNZfi0OLaVm/AQ//tCQjx86Aak8lg2IGH9EmqaeQwdgVG34bLdWbcsin+JvuXOPrB5K5hePxX59LS0svFMWy8P",
		"ZSK":              "1T2zwLEXVvY8ZAKRCKxYGp6jiaAK9/es6nSQbOBS5vgVLaBi/8UX5hVjdBpgmGxJqPVYzwl20L04fPDtAIMAcRXCpzb8NfznEYFRfBIMA53fBHs5IYQGUPBGrH5nPMGr",
		"KSK":              "tYfcl8gWb1OqrPUGoM34X5u0jX6/DxKajsQLXAECLruClEwF/QzSW37JEIAuGvGgkmJNejinukrG+Z6buAl0bFkCfEbyUT+NEcr3a3TrY+0HEXyPxdKyQIHXNiQZLD/6",
	}
	dnskeyC = map[string]string{
		"ZSK": "DcYreAh+USsK1mtv7bSR2iaQvShPUqCy7l/BRQXttAFupXp6pUaQZS+kii+H2JJqd+rS4YgC3KCd/by8yQi5j+WSy2yRprSuFuDyqZMFnDT/Py+nGjmIa59+W1iMdEYb",
		"KSK": "MzJsFTtAo0j8qGpDIhEMnK4ImTyYwMwDPU5gt/FaXd6TOw6AvZDAj2hlhZvaxMXV6xCw1MU5iPv5ZQrb3NDLUU+TW07imJ5GD9YKi0Qiiypo+zhtL4aGaOG+870yHwuY",
	}
)

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
		"www.keytrap.test": base64Decode(signaturesC["www.keytrap.test"]),
		"keytrap.test":     base64Decode(signaturesC["keytrap.test"]),
		"ns1.keytrap.test": base64Decode(signaturesC["ns1.keytrap.test"]),
		"ZSK":              base64Decode(signaturesC["ZSK"]),
		"KSK":              base64Decode(signaturesC["KSK"]),
	}
	dnskey = map[string][]byte{
		"ZSK": base64Decode(dnskeyC["ZSK"]),
		"KSK": base64Decode(dnskeyC["KSK"]),
	}
)

func main() {
	var dnskeyrr = layers.DNSResourceRecord{
		Name:  []byte("keytrap.test"),
		Type:  layers.DNSTypeDNSKEY,
		Class: layers.DNSClassIN,
		TTL:   globalTTL,
		DNSKEY: layers.DNSKEY{
			Flags:     layers.DNSKEYFlagSecureEntryPoint,
			Protocol:  3,
			Algorithm: layers.DNSSECAlgorithmECDSAP384SHA384,
			PublicKey: dnskey["KSK"],
		},
	}

	var rrsig = layers.DNSRRSIG{
		TypeCovered: layers.DNSTypeDNSKEY,
		Algorithm:   layers.DNSSECAlgorithmECDSAP384SHA384,
		Labels:      2,
		OriginalTTL: globalTTL,
		Expiration:  expiration,
		Inception:   inception,
		KeyTag:      kskKeyTag,
		SignerName:  signerName,
		Signature:   signatures["KSK"],
	}

	var data = make([]byte, 65536)
	var offset = 0

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

	// RR = owner | type | class | ttl | rdata length | rdata
	owner := encodeDomainName("keytrap.test")
	offset += copy(data[offset:], owner)
	binary.BigEndian.PutUint16(data[offset:], uint16(dnskeyrr.Type))
	binary.BigEndian.PutUint16(data[offset+2:], uint16(dnskeyrr.Class))
	binary.BigEndian.PutUint32(data[offset+4:], uint32(dnskeyrr.TTL))
	offset += 8

	// rdata length
	dnskeyRdataLength := 4 + len(dnskeyrr.DNSKEY.PublicKey)
	binary.BigEndian.PutUint16(data[offset:], uint16(dnskeyRdataLength))
	offset += 2

	// rdata
	binary.BigEndian.PutUint16(data[offset:], uint16(dnskeyrr.DNSKEY.Flags))
	data[offset+2] = byte(dnskeyrr.DNSKEY.Protocol)
	data[offset+3] = byte(dnskeyrr.DNSKEY.Algorithm)
	offset += 4
	offset += copy(data[offset:], dnskeyrr.DNSKEY.PublicKey)

	// FIN
	data = data[:offset]
	fmt.Println("Data Length:", offset)

	// Verify
	publicKeyRawData := dnskeyrr.DNSKEY.PublicKey
	signature := rrsig.Signature

	publicKey, _ := parsePublicKey(publicKeyRawData)

	hash := sha512.Sum384(data)
	fmt.Println("Hash:", hash)

	r, s := new(big.Int), new(big.Int)
	r.SetBytes(signature[:len(signature)/2])
	s.SetBytes(signature[len(signature)/2:])
	fmt.Println("R:", r)
	fmt.Println("S:", s)

	fmt.Println("Verify:", ecdsa.Verify(publicKey, hash[:], r, s))

}

func parsePublicKey(pubKeyBytes []byte) (*ecdsa.PublicKey, error) {
	curve := elliptic.P384()
	pubKey := new(ecdsa.PublicKey)
	pubKey.Curve = curve
	pubKey.X = new(big.Int).SetBytes(pubKeyBytes[:len(pubKeyBytes)/2])
	pubKey.Y = new(big.Int).SetBytes(pubKeyBytes[len(pubKeyBytes)/2:])
	return pubKey, nil
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

func calculateKeyTag(key []byte) uint16 {
	var ac uint32
	for i := 0; i < len(key); i++ {
		if i&1 == 1 {
			ac += uint32(key[i])
		} else {
			ac += uint32(key[i]) << 8
		}
	}
	ac += ac >> 16 & 0xFFFF
	return uint16(ac & 0xFFFF)
}

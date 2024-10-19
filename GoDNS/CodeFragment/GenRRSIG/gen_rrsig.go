package codefragment

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"math/big"
	"strings"
	"time"ca

	"github.com/tochusc/gopacket/layers"
)

var timeStampC = time.Now().UTC().Unix()

// GenRRSIG 生成 RRSIG 记录
func GenRRSIG(rrset []*layers.DNSResourceRecord, keytag int, signerName, privKeyRawData []byte) layers.DNSResourceRecord {
	// 准备数据
	data := make([]byte, 65536)
	offset := 0

	rrsig := layers.DNSRRSIG{
		TypeCovered: rrset[0].Type,
		Algorithm:   layers.DNSSECAlgorithmECDSAP384SHA384,
		Labels:      uint8(strings.Count(string(rrset[0].Name), ".") + 1),
		OriginalTTL: rrset[0].TTL,
		Expiration:  uint32(timeStampC) + rrset[0].TTL*10,
		Inception:   uint32(timeStampC),
		KeyTag:      uint16(keytag),
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
		rdlen := recSize(rr)
		binary.BigEndian.PutUint16(data[offset:], uint16(rdlen))
		offset += 2
		// RDATA
		rdata := serializeRDATA(rr)
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

func encodeDomainName(domainName string) []byte {
	var domainNameBytes []byte
	for _, label := range strings.Split(domainName, ".") {
		domainNameBytes = append(domainNameBytes, byte(len(label)))
		domainNameBytes = append(domainNameBytes, []byte(label)...)
	}
	domainNameBytes = append(domainNameBytes, 0)
	return domainNameBytes
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

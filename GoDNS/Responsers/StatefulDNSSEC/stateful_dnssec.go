/**
 * @Project :   ExploitDNSSEC
 * @File    :   stateful_dnssec.go
 * @Contact :	tochus@163.com
 * @License :   (C)Copyright 2024
 * @Description: A stateful GoDNS responser implementation example
 *
 * @Modify Time        @Author     @Version    @Description
 * ----------------    --------    --------    -----------
 * 01/11/24 17:10      t0chus      0.0         None
 */

package main

import (
	"net"
	"time"

	"github.com/tochusc/godns"
	"github.com/tochusc/godns/dns"
)

// 一个可能的 Responser 实现
// StatefulSecResponser 是一个"有状态的" DNSSEC Responser 实现。
// 它能够“记住”每个客户端的查询次数和查询记录。
// 可以根据这些信息来生成不同的启用DNSSEC后的回复，或者在此基础上实现更复杂的逻辑。
type StatefulSecResponser struct {
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
}

// Response 根据 DNS 查询信息生成 DNS 回复信息。
func (d StatefulSecResponser) Response(qInfo godns.QueryInfo) (godns.ResponseInfo, error) {
	d.RegisterClient(qInfo)
	rInfo := godns.InitResp(qInfo)
	d.EnableDNSSEC(qInfo, &rInfo)

	// 可以在这里随意地构造回复...

	godns.FixCount(&rInfo)
	return rInfo, nil
}

func main() {
	// 设置 DNS 服务器配置
	var conf = godns.DNSServerConfig{
		IP:            net.IPv4(10, 10, 3, 3),
		Port:          53,
		NetworkDevice: "eth0",
		MTU:           1500,
		MAC:           net.HardwareAddr{0x02, 0x42, 0x0a, 0x0a, 0x03, 0x03},
	}

	// 创建一个 DNS 服务器
	server := godns.GoDNSSever{
		ServerConfig: conf,
		Sniffer: []*godns.Sniffer{
			godns.NewSniffer(godns.SnifferConfig{
				Device:   conf.NetworkDevice,
				Port:     conf.Port,
				PktMax:   65535,
				Protocol: godns.ProtocolUDP,
			}),
		},
		Handler: godns.NewHandler(conf,
			&StatefulSecResponser{},
		),
	}

	// 启动 DNS 服务器
	server.Start()
}

// ClientInfo 客户端信息
// 根据需求的不同，可以在这里添加更多的字段。
type ClientInfo struct {
	// 查询次数
	QueryTimes int
	// 查询记录
	QueryList []godns.QueryInfo
}

// RegisterClient 记录客户端信息
func (d *StatefulSecResponser) RegisterClient(qInfo godns.QueryInfo) {
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
func (d StatefulSecResponser) EnableDNSSEC(qInfo godns.QueryInfo, rInfo *godns.ResponseInfo) error {
	// 提取查询类型和查询名称
	qType := qInfo.DNS.Question[0].Type
	qName := qInfo.DNS.Question[0].Name

	if qType == dns.DNSRRTypeDNSKEY {
		// 如果查询类型为 DNSKEY，则返回相应的 DNSKEY 记录
		dnssecMat, ok := d.DNSSECMap[qName]
		if !ok {
			d.DNSSECMap[qName] = d.CreateDNSSECMat(qName)
			dnssecMat = d.DNSSECMap[qName]
		}
		rInfo.DNS.Answer = append(rInfo.DNS.Answer, dnssecMat.DNSKEYRespSec...)
		rInfo.DNS.Header.RCode = dns.DNSResponseCodeNoErr
	} else if qType == dns.DNSRRTypeDS {
		// 如果查询类型为 DS，则生成 DS 记录并返回
		ds := dns.GenerateDS(
			qName,
			*d.DNSSECMap[qName].DNSKEYRespSec[1].RData.(*dns.DNSRDATADNSKEY),
			d.DNSSECConf.DType,
		)

		// 生成 ZSK 签名
		rec := dns.DNSResourceRecord{
			Name:  qName,
			Type:  dns.DNSRRTypeDS,
			Class: dns.DNSClassIN,
			TTL:   86400,
			RDLen: uint16(ds.Size()),
			RData: &ds,
		}
		dnssecMat := d.DNSSECMap[qName]
		sig := dns.GenerateRRSIG(
			[]dns.DNSResourceRecord{rec},
			d.DNSSECConf.DAlgo,
			uint32(time.Now().UTC().Unix()+86400-3600),
			uint32(time.Now().UTC().Unix()-3600),
			uint16(dnssecMat.ZSKTag),
			qName,
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
	return nil
}

func (d StatefulSecResponser) CreateDNSSECMat(zoneName string) godns.DNSSECMaterial {
	pubKskRDATA, privKskBytes := dns.GenerateDNSKEY(dns.DNSSECAlgorithmECDSAP384SHA384, dns.DNSKEYFlagSecureEntryPoint)
	pubZskRDATA, privZskBytes := dns.GenerateDNSKEY(dns.DNSSECAlgorithmECDSAP384SHA384, dns.DNSKEYFlagZoneKey)
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
	keySetSig := dns.GenerateRRSIG(
		[]dns.DNSResourceRecord{
			pubZskRR,
			pubKskRR,
		},
		dns.DNSSECAlgorithmECDSAP384SHA384,
		uint32(time.Now().UTC().Unix()+86400-3600),
		uint32(time.Now().UTC().Unix()-3600),
		uint16(dns.CalculateKeyTag(pubKskRDATA)),
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
		KSKTag:        int(dns.CalculateKeyTag(pubKskRDATA)),
		ZSKTag:        int(dns.CalculateKeyTag(pubZskRDATA)),
		PrivateKSK:    privKskBytes,
		PrivateZSK:    privZskBytes,
		DNSKEYRespSec: anSec,
	}
}

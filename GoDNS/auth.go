package main

import (
	"net"

	"github.com/tochusc/godns"
	"github.com/tochusc/godns/dns"
)

// DullResponser 是一个"笨笨的" Responser 实现。
// 它会回复所查询名称的 A 记录，地址指向服务器的 IP 地址。
type MyResponser struct {
	ServerConf godns.DNSServerConfig
}

// Response 根据 DNS 查询信息生成 DNS 回复信息。
// DullResponser 会回复所查询名称的 A 记录，地址指向服务器的 IP 地址。
func (d MyResponser) Response(qInfo godns.QueryInfo) (godns.ResponseInfo, error) {
	return godns.ResponseInfo{
		MAC:  qInfo.MAC,
		IP:   qInfo.IP,
		Port: qInfo.Port,
		DNS: &dns.DNSMessage{
			Header: dns.DNSHeader{
				ID:      qInfo.DNS.Header.ID,
				QR:      true,
				OpCode:  dns.DNSOpCodeQuery,
				AA:      true,
				TC:      false,
				RD:      false,
				RA:      false,
				Z:       0,
				RCode:   dns.DNSResponseCodeNoErr,
				QDCount: qInfo.DNS.Header.QDCount,
				ANCount: 1,
				NSCount: 0,
				ARCount: 0,
			},
			Question: qInfo.DNS.Question,
			Answer: []dns.DNSResourceRecord{
				{
					Name:  qInfo.DNS.Question[0].Name,
					Type:  qInfo.DNS.Question[0].Type,
					Class: qInfo.DNS.Question[0].Class,
					TTL:   86400,
					RDLen: 0,
					RData: &dns.DNSRDATAA{Address: d.ServerConf.IP},
				},
			},
			Authority:  []dns.DNSResourceRecord{},
			Additional: []dns.DNSResourceRecord{},
		},
	}, nil
}

func main() {
	// 配置 DNS 服务器
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
		Handler: godns.NewHandler(conf, &MyResponser{ServerConf: conf}),
	}

	// 启动 DNS 服务器
	server.Start()
}

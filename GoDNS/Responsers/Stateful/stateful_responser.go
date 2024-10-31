/**
 * @Project :   ExploitDNSSEC
 * @File    :   stateful_responser.go
 * @Contact :	tochus@163.com
 * @License :   (C)Copyright 2024
 * @Description: A stateful GoDNS responser implementation example
 *
 * @Modify Time        @Author     @Version    @Description
 * ----------------    --------    --------    -----------
 * 31/10/24 21:02      t0chus      0.0         None
 */

package main

import (
	"net"

	"github.com/tochusc/godns"
	"github.com/tochusc/godns/dns"
)

// 一个可能的 Responser 实现
// StatefulResponser 是一个"有状态的" Responser 实现。
// 它能够“记住”每个客户端的查询次数和查询记录。
// 可以根据这些信息来生成不同的回复，或者在此基础上实现更复杂的逻辑。
type StatefulResponser struct {
	// 服务器配置
	ServerConf godns.DNSServerConfig
	// 默认回复
	DefaultResp godns.ResponseInfo
	// 客户端IP -> 客户端信息的映射
	ClientMap map[string]ClientInfo
}

// ClientInfo 客户端信息
// 根据需求的不同，可以在这里添加更多的字段。
type ClientInfo struct {
	// 查询次数
	QueryTimes int
	// 查询记录
	QueryList []godns.QueryInfo
}

// Response 根据 DNS 查询信息生成 DNS 回复信息。
func (d StatefulResponser) Response(qInfo godns.QueryInfo) (godns.ResponseInfo, error) {
	d.RegisterClient(qInfo)
	rInfo := d.InitResp(qInfo)

	// 可以在这里随意地构造回复...

	return rInfo, nil
}

// RegisterClient 记录客户端信息
func (d *StatefulResponser) RegisterClient(qInfo godns.QueryInfo) {
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

// InitResp 根据查询信息初始化回复信息
func (d StatefulResponser) InitResp(qInfo godns.QueryInfo) godns.ResponseInfo {
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
			&StatefulResponser{
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
			},
		),
	}

	// 启动 DNS 服务器
	server.Start()
}

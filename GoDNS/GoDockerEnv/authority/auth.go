package main

import (
	"net"

	"github.com/tochusc/godns"
)

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

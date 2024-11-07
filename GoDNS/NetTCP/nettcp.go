package main

import (
	"fmt"
	"net"
	"os"

	"github.com/tochusc/godns/dns"
)

func handleTCPConn(conn net.Conn) {
	buffer := make([]byte, 1024)
	size, err := conn.Read(buffer)
	if err != nil {
		fmt.Println("Error reading TCP connection: ", err.Error())
		os.Exit(1)
	}
	fmt.Printf("Received TCP connection from:%s, data size:%d\n",
		conn.RemoteAddr().String(), size)
	fmt.Printf("Data:\n%v\n", buffer[:size])
	msgSize := int(buffer[0])<<8 | int(buffer[1])
	fmt.Printf("Msg size: %d\n", msgSize)
	for size < msgSize {
		n, err := conn.Read(buffer[size:msgSize])
		if err != nil {
			fmt.Println("Error reading TCP connection: ", err.Error())
			os.Exit(1)
		}
		size += n
		fmt.Printf("Received more data, size: %d\n", size)
	}
	dnsMsg := dns.DNSMessage{}
	dnsMsg.DecodeFromBuffer(buffer[2:2+msgSize], 0)
	fmt.Printf("DNS Message:\n%s\n", dnsMsg.String())
	conn.Close()
}

func handlePktConn(conn net.PacketConn) {
	buffer := make([]byte, 1500)
	size, addr, err := conn.ReadFrom(buffer)
	if err != nil {
		fmt.Println("Error reading packet: ", err.Error())
		os.Exit(1)
	}
	fmt.Printf("Received packet from: %s, packet size: %d\n",
		addr.String(), size)

	fmt.Printf("Packet data:\n%v\n", buffer[:size])
	dnsMsg := dns.DNSMessage{}
	dnsMsg.DecodeFromBuffer(buffer[:size], 0)
	fmt.Printf("DNS Message:\n%s\n", dnsMsg.String())
	conn.Close()
}

func main() {
	ln, err := net.Listen("tcp", ":53")
	if err != nil {
		fmt.Println("Error listening: ", err.Error())
		os.Exit(1)
	}
	pktConn, err := net.ListenPacket("udp", ":53")
	if err != nil {
		fmt.Println("Error listening: ", err.Error())
		os.Exit(1)
	}

	go handlePktConn(pktConn)

	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Println("Error accepting: ", err.Error())
			os.Exit(1)
		}
		go handleTCPConn(conn)
	}
}

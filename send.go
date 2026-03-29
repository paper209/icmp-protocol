package main

import "study/protocol"

func main() {
	protocol.Send([4]byte{10, 0, 0, 2}, []byte("hello icmp"))
}

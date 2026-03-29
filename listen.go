package main

import "study/protocol"

func main() {
	err := protocol.Listen()
	if err != nil {
		panic(err)
	}
}

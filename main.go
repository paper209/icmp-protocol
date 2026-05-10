package main

import (
	"fmt"
	"study/protocol"
	"time"
)

// src = 10.0.0.1
func Write() {
	c, err := protocol.NewConnection([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2})
	if err != nil {
		panic(err)
	}

	err = c.Write([]byte("hello"))
	if err != nil {
		panic(err)
	}
}

// src = 10.0.0.2
func Read() {
	c, err := protocol.NewConnection([4]byte{10, 0, 0, 2}, [4]byte{10, 0, 0, 1})
	if err != nil {
		panic(err)
	}

	buf := make([]byte, 150)
	for {
		n, err := c.Read(buf)
		if err != nil {
			panic(err)
		}

		fmt.Println(buf[:n])
		time.Sleep(1000 * time.Millisecond)
	}
}

func main() {
	Read()
}

package protocol

import (
	"encoding/binary"
	"fmt"
	"log"
	"math/rand"
	"study/icmp"
	"syscall"
)

const (
	handshakeRequest  = 0
	handshakeResponse = 1

	dataRequest  = 2
	dataResponse = 3
)

func openSocket() (int, error) {
	s, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err != nil {
		return s, fmt.Errorf("socket error: %w", err)
	}

	return s, nil
}

func ReadData(address [4]byte, identify uint16, size uint16) {
	s, err := openSocket()
	if err != nil {
		log.Printf("socket error: %s\n", err.Error())
		return
	}
	defer syscall.Close(s)

	maxSequence := (int(size)+255)/256 - 1
	buf := make([]byte, size)
	for {
		e, err := icmp.ReadEchoIdentifier(s, identify)
		if err != nil {
			log.Printf("read echo error: %s\n", err.Error())
			return
		} else if len(e.Data) < 2 {
			continue
		} else if e.Data[0] != dataRequest {
			continue
		}

		copy(buf[e.Sequence*256:], e.Data[1:])

		// 데이터 전송 응답
		reply := make([]byte, 3)
		reply[0] = dataResponse
		binary.BigEndian.PutUint16(reply[1:], uint16(len(e.Data[1:])))

		er := &icmp.Echo{
			Identifier: identify,
			Sequence:   e.Sequence,
			Data:       reply,
		}
		err = er.SendEcho(address)
		if err != nil {
			log.Printf("send echo error: %s\n", err.Error())
			return
		}

		if e.Sequence == uint16(maxSequence) {
			break
		}
	}

	fmt.Println(string(buf))
}

func Listen() error {
	s, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err != nil {
		return fmt.Errorf("socket error: %w", err)
	}
	defer syscall.Close(s)

	for {
		ih, e, err := icmp.ReadEcho(s)
		if err != nil {
			log.Printf("icmp echo read error: %s", err.Error())
			continue
		}

		if e.Data[0] == 0 {
			size := binary.BigEndian.Uint16(e.Data[1:])

			// 응답
			buf := make([]byte, 3)
			buf[0] = 1
			binary.BigEndian.PutUint16(buf[1:], 256) // 최대 크기

			e := &icmp.Echo{
				Identifier: e.Identifier,
				Sequence:   e.Sequence,
				Data:       buf,
			}
			err = e.SendEcho(ih.SourceAddress)
			if err != nil {
				return fmt.Errorf("send echo error: %w", err)
			}

			ReadData(ih.SourceAddress, e.Identifier, size)
		}
	}
}

func Send(address [4]byte, data []byte) error {
	identifier := uint16(rand.Intn(65536))

	s, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err != nil {
		return fmt.Errorf("socket error: %w", err)
	}
	defer syscall.Close(s)

	buf := make([]byte, 3)
	buf[0] = handshakeRequest
	binary.BigEndian.PutUint16(buf[1:], uint16(len(data)))

	e := &icmp.Echo{
		Identifier: identifier,
		Sequence:   0,
		Data:       buf,
	}
	err = e.SendEcho(address)
	if err != nil {
		return fmt.Errorf("send error: %w", err)
	}

	echo, err := icmp.ReadEchoIdentifier(s, identifier)
	if err != nil {
		return fmt.Errorf("read echo error: %w", err)
	} else if len(echo.Data) < 3 {
		return fmt.Errorf("handshake reply error: %d", len(echo.Data))
	} else if echo.Data[0] != handshakeResponse {
		return fmt.Errorf("is not handshake reply type: %d", echo.Data[0])
	}

	// 수신 받은 한 패킷당 최대로 받을수 있는 데이터의 크기
	sequence := 0
	max := binary.BigEndian.Uint16(echo.Data[1:])
	for i := 0; i < len(data); i += int(max) {
		end := i + int(max)
		if end > len(data) {
			end = len(data)
		}

		buf := make([]byte, 1+(end-i))
		buf[0] = dataRequest
		copy(buf[1:], data[i:end])

		for {
			e := &icmp.Echo{
				Identifier: identifier,
				Sequence:   uint16(sequence),
				Data:       buf,
			}
			err := e.SendEcho(address)
			if err != nil {
				return fmt.Errorf("send error: %w", err)
			}

			echo, err := icmp.ReadEchoIdentifier(s, identifier)
			if err != nil {
				return fmt.Errorf("read echo error: %w", err)
			} else if len(echo.Data) < 3 {
				return fmt.Errorf("data reply error: %d", len(echo.Data))
			} else if echo.Data[0] != dataResponse {
				return fmt.Errorf("is not data reply type: %d", echo.Data[0])
			} else if echo.Sequence != uint16(sequence) {
				continue
			} else if uint16(end-i) != binary.BigEndian.Uint16(echo.Data[1:]) {
				continue
			}

			break
		}

		sequence++
	}

	return nil
}

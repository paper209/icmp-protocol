package protocol

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"study/icmp"
	"syscall"
	"time"
)

const (
	HandshakeReq = 0
	HandshakeRp  = 1

	DataReq = 2
	DataRp  = 3
)

func setTimeout(s int, t time.Duration) error {
	tv := syscall.NsecToTimeval(t.Nanoseconds())
	err := syscall.SetsockoptTimeval(s, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
	if err != nil {
		return fmt.Errorf("set time error: %w", err)
	}

	err = syscall.SetsockoptTimeval(s, syscall.SOL_SOCKET, syscall.SO_SNDTIMEO, &tv)
	if err != nil {
		return fmt.Errorf("set time error: %w", err)
	}

	return nil
}

func Send(address [4]byte, data []byte) error {
	identifier := uint16(rand.Intn(65536))

	s, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err != nil {
		return fmt.Errorf("socket error: %w", err)
	}
	defer syscall.Close(s)
	setTimeout(s, 10*time.Second)

	buf := make([]byte, 3)
	buf[0] = HandshakeReq
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

	echo, err := icmp.ReadEcho(s, identifier)
	if err != nil {
		return fmt.Errorf("read echo error: %w", err)
	} else if len(echo.Data) < 3 {
		return fmt.Errorf("handshake reply error: %d", len(echo.Data))
	} else if echo.Data[0] != HandshakeRp {
		return fmt.Errorf("is not handshake reply type: %d", echo.Data[0])
	}

	// 수신 받은 한 패킷당 최대로 받을수 있는 데이터의 크기
	max := binary.BigEndian.Uint16(echo.Data[1:])

	return nil
}

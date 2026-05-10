package protocol

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"study/icmp"
	"sync"
	"syscall"
	"time"
)

type Connection struct {
	Socket int
	Src    [4]byte
	Dst    [4]byte

	Mu         sync.Mutex
	IsClosed   bool
	ReadBuffer []byte
}

const (
	handshakeRequest  = 0
	handshakeResponse = 1

	dataRequest  = 2
	dataResponse = 3
)

const (
	maxSize    = 2
	maxBufSize = 256
)

func (c *Connection) isClosed() bool {
	c.Mu.Lock()
	defer c.Mu.Unlock()
	return c.IsClosed
}

func (c *Connection) Close() error {
	c.Mu.Lock()
	defer c.Mu.Unlock()

	c.IsClosed = true
	return syscall.Close(c.Socket)
}

// open socket
func openSocket() (int, error) {
	s, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err != nil {
		return s, fmt.Errorf("socket error: %w", err)
	}

	return s, nil
}

// set read timeout
func setReadTimeout(fd int, t time.Duration) error {
	tv := syscall.NsecToTimeval(t.Nanoseconds())
	return syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
}

func NewConnection(src [4]byte, dst [4]byte) (*Connection, error) {
	s, err := openSocket()
	if err != nil {
		return nil, fmt.Errorf("socket error: %w", err)
	}

	c := &Connection{
		Socket:   s,
		IsClosed: false,

		Src: src,
		Dst: dst,
	}
	go c.listen()

	return c, nil
}

func (c *Connection) Read(buf []byte) (n int, err error) {
	c.Mu.Lock()
	defer c.Mu.Unlock()

	if c.IsClosed {
		return 0, fmt.Errorf("connection closed")
	} else if len(c.ReadBuffer) == 0 {
		return 0, nil
	}

	n = copy(buf, c.ReadBuffer)
	c.ReadBuffer = c.ReadBuffer[n:]
	return n, nil
}

// write data
func (c *Connection) Write(data []byte) error {
	s, err := openSocket()
	if err != nil {
		return err
	}
	setReadTimeout(s, 5*time.Second) // 타임아웃 설정
	defer syscall.Close(s)

	identifier := uint16(rand.Intn(65536))

	buf := make([]byte, 3)
	buf[0] = handshakeRequest
	binary.BigEndian.PutUint16(buf[1:], uint16(len(data)))

	e := &icmp.Echo{
		Identifier: identifier,
		Sequence:   0,
		Data:       buf,
	}
	err = e.SendEcho(c.Src, c.Dst)
	if err != nil {
		return fmt.Errorf("send error: %w", err)
	}

	echo, err := icmp.ReadEchoIdentifier(s, c.Dst, identifier)
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

		success := false
		for retry := 0; retry < 3; retry++ {
			e := &icmp.Echo{
				Identifier: identifier,
				Sequence:   uint16(sequence),
				Data:       buf,
			}
			err := e.SendEcho(c.Src, c.Dst)
			if err != nil {
				return fmt.Errorf("send error: %w", err)
			}

			echo, err := icmp.ReadEchoIdentifier(s, c.Dst, identifier)
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

			success = true
			break
		}

		if !success {
			return fmt.Errorf("send sequence error: %d", sequence)
		}

		sequence++

		time.Sleep(10 * time.Millisecond)
	}

	return nil
}

func (c *Connection) listen() {
	defer c.Close()
	for {
		if c.isClosed() {
			return
		}

		e, err := icmp.ReadEchoAddress(c.Socket, c.Dst)
		if err != nil {
			return
		}

		if e.Data[0] == 0 {
			size := binary.BigEndian.Uint16(e.Data[1:])

			// 응답
			buf := make([]byte, 3)
			buf[0] = 1
			binary.BigEndian.PutUint16(buf[1:], maxSize) // 최대 크기

			e := &icmp.Echo{
				Identifier: e.Identifier,
				Sequence:   e.Sequence,
				Data:       buf,
			}
			err = e.SendEcho(c.Src, c.Dst)
			if err != nil {
				return
			}

			c.readData(e.Identifier, size)
		}
	}
}

func (c *Connection) readData(identifier uint16, size uint16) {
	s, err := openSocket()
	if err != nil {
		return
	}
	setReadTimeout(s, 5*time.Second) // 타임아웃 설정
	defer syscall.Close(s)

	// 버퍼 사이즈 검증 추가
	if size > maxBufSize {
		return
	}

	buf := make([]byte, size)
	maxSequence := (int(size)+(maxSize-1))/maxSize - 1
	for {
		if c.isClosed() {
			return
		}

		e, err := icmp.ReadEchoIdentifier(s, c.Dst, identifier)
		if err != nil {
			c.Close()
			return
		} else if len(e.Data) < 2 {
			continue
		} else if e.Data[0] != dataRequest {
			continue
		} else if e.Sequence > uint16(maxSequence) { // Sequence 검증 추가
			continue
		}

		copy(buf[e.Sequence*maxSize:], e.Data[1:])

		// 데이터 전송 응답
		reply := make([]byte, 3)
		reply[0] = dataResponse
		binary.BigEndian.PutUint16(reply[1:], uint16(len(e.Data[1:])))

		er := &icmp.Echo{
			Identifier: identifier,
			Sequence:   e.Sequence,
			Data:       reply,
		}
		err = er.SendEcho(c.Src, c.Dst)
		if err != nil {
			c.Close()
			return
		}

		if e.Sequence == uint16(maxSequence) {
			break
		}
	}

	c.Mu.Lock()
	c.ReadBuffer = append(c.ReadBuffer, buf...)
	c.Mu.Unlock()
}

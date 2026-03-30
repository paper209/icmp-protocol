package icmp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"study/checksum"
	"study/ip"
	"syscall"
)

// total bytes = 4
type Header struct {
	Type     uint8  // 1
	Code     uint8  // 1
	Checksum uint16 // 2
}

// total bytes = 4
type Echo struct {
	Identifier uint16
	Sequence   uint16
	Data       []byte
}

func (h *Header) BuildHeader(buf []byte) {
	buf[0] = h.Type
	buf[1] = h.Code
	binary.BigEndian.PutUint16(buf[2:4], 0)
}

func DecodeHeader(buf []byte) (*Header, error) {
	if len(buf) < 24 {
		return nil, errors.New("invalid length")
	} else if checksum.Checksum(buf[20:]) != 0 {
		return nil, errors.New("invalid checksum")
	}

	return &Header{
		Type:     buf[20],
		Code:     buf[21],
		Checksum: binary.BigEndian.Uint16(buf[22:24]),
	}, nil
}

func decodeEcho(buf []byte) (*Echo, error) {
	if len(buf) < 28 {
		return nil, errors.New("invalid length")
	}

	return &Echo{
		Identifier: binary.BigEndian.Uint16(buf[24:26]),
		Sequence:   binary.BigEndian.Uint16(buf[26:28]),
		Data:       buf[28:],
	}, nil
}

func (e *Echo) buildEchoRequest() []byte {
	buf := make([]byte, 8+len(e.Data))

	h := &Header{
		Type:     8,
		Code:     0,
		Checksum: 0,
	}
	h.BuildHeader(buf)

	binary.BigEndian.PutUint16(buf[4:6], e.Identifier)
	binary.BigEndian.PutUint16(buf[6:8], e.Sequence)
	copy(buf[8:], e.Data)
	binary.BigEndian.PutUint16(buf[2:4], checksum.Checksum(buf))

	return buf
}

func Read(s int) ([]byte, error) {
	buf := make([]byte, 1500)
	n, _, err := syscall.Recvfrom(s, buf, 0)
	if err != nil {
		return nil, fmt.Errorf("socket error: %w", err)
	}
	return buf[:n], nil
}

func ReadEcho(s int) (*ip.Header, *Echo, error) {
	for {
		buf, err := Read(s)
		if err != nil {
			return nil, nil, fmt.Errorf("read error: %w", err)
		}

		ih, err := ip.DecodeHeader(buf)
		if err != nil {
			return nil, nil, fmt.Errorf("decode ip header error: %w", err)
		}

		h, err := DecodeHeader(buf)
		if err != nil {
			return nil, nil, fmt.Errorf("decode icmp header error: %w", err)
		} else if h.Type != 8 {
			continue
		}

		e, err := decodeEcho(buf)
		if err != nil {
			return nil, nil, fmt.Errorf("decode echo error: %w", err)
		}

		return ih, e, nil
	}
}

func ReadEchoIdentifier(s int, identifier uint16) (*Echo, error) {
	for {
		_, e, err := ReadEcho(s)
		if err != nil {
			return nil, fmt.Errorf("raed echo error: %w", err)
		}

		if e.Identifier == identifier {
			return e, nil
		}
	}
}

func (e *Echo) SendEcho(address [4]byte) error {
	ih := &ip.Header{
		VersionIHL:         (4 << 4) | (5 & 0x0F),
		Tos:                0,
		TotalLength:        uint16(20 + 8 + len(e.Data)),
		Identification:     0,
		FlagsFragment:      0x4000, // df = 1
		TTL:                64,
		Protocol:           1,                    // icmp
		SourceAddress:      [4]byte{10, 0, 0, 2}, // 사용시 수정해야함
		DestinationAddress: address,
	}
	buf := ih.BuildHeader()
	buf = append(buf, e.buildEchoRequest()...)

	s, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return fmt.Errorf("socket errror: %s", err.Error())
	}
	defer syscall.Close(s)

	err = syscall.SetsockoptInt(s, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
	if err != nil {
		return fmt.Errorf("socket option error: %s", err.Error())
	}

	err = syscall.Sendto(s, buf, 0, &syscall.SockaddrInet4{
		Port: 0,
		Addr: address,
	})
	if err != nil {
		return fmt.Errorf("socket send error: %s", err.Error())
	}

	return nil
}

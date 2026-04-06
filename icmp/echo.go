package icmp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"study/ip"
	"study/util"
	"syscall"
)

// total bytes = 4
type Echo struct {
	Identifier uint16
	Sequence   uint16
	Data       []byte
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
	h.buildHeader(buf)

	binary.BigEndian.PutUint16(buf[4:6], e.Identifier)
	binary.BigEndian.PutUint16(buf[6:8], e.Sequence)
	copy(buf[8:], e.Data)
	binary.BigEndian.PutUint16(buf[2:4], util.Checksum(buf))

	return buf
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

		h, err := decodeHeader(buf)
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

func ReadEchoIdentifier(s int, address [4]byte, identifier uint16) (*Echo, error) {
	for {
		ih, e, err := ReadEcho(s)
		if err != nil {
			return nil, fmt.Errorf("raed echo error: %w", err)
		}

		// 아이피 헤더 검증 추가
		if e.Identifier == identifier && ih.SourceAddress == address {
			return e, nil
		}
	}
}

func (e *Echo) SendEcho(address [4]byte) error {
	src, err := util.SourceIP()
	if err != nil {
		return fmt.Errorf("get source ip error: %w", err)
	}

	log.Println(e.Data)

	ih := &ip.Header{
		VersionIHL:         (4 << 4) | (5 & 0x0F),
		Tos:                0,
		TotalLength:        uint16(20 + 8 + len(e.Data)),
		Identification:     0,
		FlagsFragment:      0x4000, // df = 1
		TTL:                64,
		Protocol:           1, // icmp
		SourceAddress:      src,
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

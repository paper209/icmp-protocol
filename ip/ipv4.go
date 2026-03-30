package ip

import (
	"encoding/binary"
	"errors"
	"study/util"
)

// total bytes = 20
type Header struct {
	VersionIHL         uint8
	Tos                uint8
	TotalLength        uint16
	Identification     uint16
	FlagsFragment      uint16
	TTL                uint8
	Protocol           uint8
	util               uint16
	SourceAddress      [4]byte
	DestinationAddress [4]byte
}

func (h *Header) BuildHeader() []byte {
	buf := make([]byte, 20)
	buf[0] = h.VersionIHL
	buf[1] = h.Tos
	binary.BigEndian.PutUint16(buf[2:], h.TotalLength)
	binary.BigEndian.PutUint16(buf[4:], h.Identification)
	binary.BigEndian.PutUint16(buf[6:], h.FlagsFragment)
	buf[8] = h.TTL
	buf[9] = h.Protocol
	binary.BigEndian.PutUint16(buf[10:], 0)
	copy(buf[12:16], h.SourceAddress[:])
	copy(buf[16:20], h.DestinationAddress[:])

	binary.BigEndian.PutUint16(buf[10:], util.Checksum(buf))

	return buf
}

func DecodeHeader(buf []byte) (*Header, error) {
	if len(buf) < 20 {
		return nil, errors.New("invalid length")
	} else if util.Checksum(buf[:20]) != 0 {
		return nil, errors.New("invalid util")
	}

	return &Header{
		VersionIHL:         buf[0],
		Tos:                buf[1],
		TotalLength:        binary.BigEndian.Uint16(buf[2:4]),
		Identification:     binary.BigEndian.Uint16(buf[4:6]),
		FlagsFragment:      binary.BigEndian.Uint16(buf[6:8]),
		TTL:                buf[8],
		Protocol:           buf[9],
		util:               binary.BigEndian.Uint16(buf[10:12]),
		SourceAddress:      [4]byte{buf[12], buf[13], buf[14], buf[15]},
		DestinationAddress: [4]byte{buf[16], buf[17], buf[18], buf[19]},
	}, nil
}

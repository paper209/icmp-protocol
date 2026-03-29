package checksum

import "encoding/binary"

func Checksum(buf []byte) uint16 {
	var checksum uint32
	if len(buf)%2 != 0 {
		buf = append(buf, 0)
	}

	for i := 0; i < len(buf); i += 2 {
		checksum += uint32(binary.BigEndian.Uint16(buf[i : i+2]))
	}

	for (checksum >> 16) != 0 {
		checksum = (checksum & 0xFFFF) + (checksum >> 16)
	}

	return ^uint16(checksum) // NOT
}

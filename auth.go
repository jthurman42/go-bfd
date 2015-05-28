package bfd

import (
	"bytes"
	"encoding/binary"
)

/*
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |   Auth Type   |   Auth Len    |    Authentication Data...     |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
type BfdAuthHeader struct {
	Type   AuthenticationType
	Length uint8
	Data   []byte
}

type AuthenticationType uint8

const (
	RESERVED        AuthenticationType = 0 // Reserved
	SIMPLE          AuthenticationType = 1 // Simple Password
	KEYED_MD5       AuthenticationType = 2 // Keyed MD5
	METICULOUS_MD5  AuthenticationType = 3 // Meticulous Keyed MD5
	KEYED_SHA1      AuthenticationType = 4 // Keyed SHA1
	METICULOUS_SHA1 AuthenticationType = 5 // Meticulous Keyed SHA1
)

/*
 * Decode the Auth header section
 */
func decodeBfdAuthHeader(data []byte) (*BfdAuthHeader, error) {
	header := &BfdAuthHeader{}
	header.Type = AuthenticationType(data[0])
	header.Length = data[1]
	header.Data = data[2:]

	return header, nil
}

func (h *BfdAuthHeader) Marshal() []byte {
	buf := bytes.NewBuffer([]uint8{})
	binary.Write(buf, binary.BigEndian, h.Type)
	binary.Write(buf, binary.BigEndian, h.Length)
	binary.Write(buf, binary.BigEndian, h.Data)

	return buf.Bytes()
}

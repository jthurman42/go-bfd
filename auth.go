package bfd

import (
	"bytes"
	"encoding/binary"
	"errors"
)

/*
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |   Auth Type   |   Auth Len    |    Authentication Data...     |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |   Auth Type   |   Auth Len    |  Auth Key ID  |  Password...  |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                              ...                              |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |   Auth Type   |   Auth Len    |  Auth Key ID  |   Reserved    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                        Sequence Number                        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                      Auth Key/Digest...                       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                              ...                              |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
type BfdAuthHeader struct {
	Type           AuthenticationType
	AuthKeyID      uint8
	SequenceNumber uint32
	AuthData       []byte
}

type AuthenticationType uint8

const (
	BFD_AUTH_TYPE_RESERVED        AuthenticationType = 0 // Reserved
	BFD_AUTH_TYPE_SIMPLE          AuthenticationType = 1 // Simple Password
	BFD_AUTH_TYPE_KEYED_MD5       AuthenticationType = 2 // Keyed MD5
	BFD_AUTH_TYPE_METICULOUS_MD5  AuthenticationType = 3 // Meticulous Keyed MD5
	BFD_AUTH_TYPE_KEYED_SHA1      AuthenticationType = 4 // Keyed SHA1
	BFD_AUTH_TYPE_METICULOUS_SHA1 AuthenticationType = 5 // Meticulous Keyed SHA1
)

/*
 * Decode the Auth header section
 */
func decodeBfdAuthHeader(data []byte) (*BfdAuthHeader, error) {
	var err error
	h := &BfdAuthHeader{}

	h.Type = AuthenticationType(data[0])
	length := uint8(data[1])

	if length > 0 {
		h.AuthKeyID = uint8(data[2])

		switch h.Type {
		case BFD_AUTH_TYPE_SIMPLE:
			h.AuthData = data[3:]
			break
		case BFD_AUTH_TYPE_KEYED_MD5, BFD_AUTH_TYPE_METICULOUS_MD5:
			h.SequenceNumber = binary.BigEndian.Uint32(data[4:8])
			h.AuthData = data[8:]
			if len(h.AuthData) != 16 {
				err = errors.New("Invalid MD5 Auth Key/Digest length!")
			}
		case BFD_AUTH_TYPE_KEYED_SHA1, BFD_AUTH_TYPE_METICULOUS_SHA1:
			h.SequenceNumber = binary.BigEndian.Uint32(data[4:8])
			h.AuthData = data[8:]
			if len(h.AuthData) != 20 {
				err = errors.New("Invalid SHA1 Auth Key/Hash length!")
			}
		default:
			err = errors.New("Unsupported Authentication type!")
		}
	}

	if err != nil {
		return nil, err
	}

	return h, nil
}

/*
 * Marshal the Auth header section
 */
func (h *BfdAuthHeader) Marshal() []byte {
	buf := bytes.NewBuffer([]uint8{})
	var length uint8

	if h.Type != BFD_AUTH_TYPE_SIMPLE {
		length = uint8(len(h.AuthData) + 8)
	} else {
		length = uint8(len(h.AuthData) + 3)
	}

	binary.Write(buf, binary.BigEndian, h.Type)
	binary.Write(buf, binary.BigEndian, length)
	binary.Write(buf, binary.BigEndian, h.AuthKeyID)

	if h.Type != BFD_AUTH_TYPE_SIMPLE {
		binary.Write(buf, binary.BigEndian, uint8(0))
		binary.Write(buf, binary.BigEndian, h.SequenceNumber)
	}

	binary.Write(buf, binary.BigEndian, h.AuthData)

	return buf.Bytes()
}

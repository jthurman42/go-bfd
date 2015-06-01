package bfd

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

type BfdState uint8

const (
	STATE_ADMIN_DOWN BfdState = 0 // AdminDown
	STATE_DOWN       BfdState = 1 // Down
	STATE_INIT       BfdState = 2 // Init
	STATE_UP         BfdState = 3 // Up
)

type BfdDiagnostic uint8

const (
	DIAG_NONE                 BfdDiagnostic = 0 // No Diagnostic
	DIAG_TIME_EXPIRED         BfdDiagnostic = 1 // Control Detection Time Expired
	DIAG_ECHO_FAILED          BfdDiagnostic = 2 // Echo Function Failed
	DIAG_NEIGHBOR_SIGNAL_DOWN BfdDiagnostic = 3 // Neighbor Signaled Session Down
	DIAG_FORWARD_PLANE_RESET  BfdDiagnostic = 4 // Forwarding Plane Reset
	DIAG_PATH_DOWN            BfdDiagnostic = 5 // Path Down
	DIAG_CONCAT_PATH_DOWN     BfdDiagnostic = 6 // Concatenated Path Down
	DIAG_ADMIN_DOWN           BfdDiagnostic = 7 // Administratively Down
	DIAG_REV_CONCAT_PATH_DOWN BfdDiagnostic = 8 // Reverse Concatenated Path Down
)

/*
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |Vers |  Diag   |Sta|P|F|C|A|D|M|  Detect Mult  |    Length     |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                       My Discriminator                        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                      Your Discriminator                       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Desired Min TX Interval                    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                   Required Min RX Interval                    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                 Required Min Echo RX Interval                 |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * An optional Authentication Section MAY be present
 */

type BfdControlPacket struct {
	Version                   uint8
	Diagnostic                BfdDiagnostic
	State                     BfdState
	Poll                      bool
	Final                     bool
	ControlPlaneIndependent   bool
	AuthPresent               bool
	Demand                    bool
	Multipoint                bool // Must always be zero
	DetectMult                uint8
	MyDiscriminator           uint32
	YourDiscriminator         uint32
	DesiredMinTxInterval      time.Duration
	RequiredMinRxInterval     time.Duration
	RequiredMinEchoRxInterval time.Duration
	AuthHeader                *BfdAuthHeader
}

var BfdControlPacketDefaults = BfdControlPacket{
	Version:    1,
	Diagnostic: DIAG_NONE,
	State:      STATE_DOWN,
	Poll:       false,
	Final:      false,
	ControlPlaneIndependent:   false,
	AuthPresent:               false,
	Demand:                    false,
	Multipoint:                false,
	DetectMult:                3,
	MyDiscriminator:           0,
	YourDiscriminator:         0,
	DesiredMinTxInterval:      1000000,
	RequiredMinRxInterval:     1000000,
	RequiredMinEchoRxInterval: 0,
	AuthHeader:                nil,
}

/*
 * Decode the control packet
 */
func decodeBfdPacket(data []byte) (*BfdControlPacket, error) {
	var err error
	packet := &BfdControlPacket{}

	packet.Version = uint8((data[0] & 0xE0) >> 5)
	packet.Diagnostic = BfdDiagnostic(data[0] & 0x1F)

	packet.State = BfdState((data[1] & 0xD0) >> 6)

	// bit flags
	packet.Poll = (data[1]&0x20 != 0)
	packet.Final = (data[1]&0x10 != 0)
	packet.ControlPlaneIndependent = (data[1]&0x08 != 0)
	packet.AuthPresent = (data[1]&0x04 != 0)
	packet.Demand = (data[1]&0x02 != 0)
	packet.Multipoint = (data[1]&0x01 != 0)
	packet.DetectMult = uint8(data[2])

	length := uint8(data[3]) // No need to store this
	if uint8(len(data)) != length {
		err = errors.New("Packet length mis-match!")
		return nil, err
	}

	packet.MyDiscriminator = binary.BigEndian.Uint32(data[4:8])
	packet.YourDiscriminator = binary.BigEndian.Uint32(data[8:12])
	packet.DesiredMinTxInterval = time.Duration(binary.BigEndian.Uint32(data[12:16]))
	packet.RequiredMinRxInterval = time.Duration(binary.BigEndian.Uint32(data[16:20]))
	packet.RequiredMinEchoRxInterval = time.Duration(binary.BigEndian.Uint32(data[20:24]))

	if packet.AuthPresent {
		if len(data) > 24 {
			packet.AuthHeader, err = decodeBfdAuthHeader(data[24:])
		} else {
			err = errors.New("Header flag set, but packet too short!")
		}
	}

	return packet, err
}

func (p *BfdControlPacket) Marshal() []byte {
	var auth []byte
	buf := bytes.NewBuffer([]uint8{})
	flags := uint8(0)
	length := uint8(24)

	binary.Write(buf, binary.BigEndian, (p.Version<<5 | (uint8(p.Diagnostic) & 0x1f)))

	if p.Poll {
		flags |= 0x20
	}
	if p.Final {
		flags |= 0x10
	}
	if p.ControlPlaneIndependent {
		flags |= 0x08
	}
	if p.AuthPresent && (p.AuthHeader != nil) {
		flags |= 0x04
		auth = p.AuthHeader.Marshal()
		length += uint8(len(auth))
	}
	if p.Demand {
		flags |= 0x02
	}
	if p.Multipoint {
		flags |= 0x01
	}

	binary.Write(buf, binary.BigEndian, (uint8(p.State)<<6 | flags))
	binary.Write(buf, binary.BigEndian, p.DetectMult)
	binary.Write(buf, binary.BigEndian, length)

	binary.Write(buf, binary.BigEndian, p.MyDiscriminator)
	binary.Write(buf, binary.BigEndian, p.YourDiscriminator)
	binary.Write(buf, binary.BigEndian, uint32(p.DesiredMinTxInterval))
	binary.Write(buf, binary.BigEndian, uint32(p.RequiredMinRxInterval))
	binary.Write(buf, binary.BigEndian, uint32(p.RequiredMinEchoRxInterval))

	if len(auth) > 0 {
		binary.Write(buf, binary.BigEndian, auth)
	}

	return buf.Bytes()
}

func (p *BfdControlPacket) String() string {
	return fmt.Sprintf("[Ver: %d]", p.Version)
}

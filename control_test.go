package bfd

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"
)

type bfdControlPacketTestSet struct {
	Name   string
	Data   []byte
	Packet BfdControlPacket
}

var tests = []bfdControlPacketTestSet{
	{
		Name: "Default",
		Data: []byte{
			0x20,                   // Version 1, No Diagnostics
			0x40,                   // Session State: DOWN, Message Flags: None
			0x03,                   // Detect Time Multiplier (3)
			0x18,                   // Message Length (24)
			0x00, 0x00, 0x00, 0x00, // My Discriminator (0)
			0x00, 0x00, 0x00, 0x00, // Your Discriminator (0)
			0x00, 0x0f, 0x42, 0x40, // Desired Min TX interval (1000000)
			0x00, 0x0f, 0x42, 0x40, // Required Min RX interval (1000000)
			0x00, 0x00, 0x00, 0x00, // Required Min Echo interval (0)
		},
		Packet: BfdControlPacketDefaults,
	},
	{
		Name: "Discriminator",
		Data: []byte{
			0x20, 0x40, 0x03, 0x18, 0x00, 0x00, 0x00, 0x01, // Mine:   1
			0x00, 0x00, 0x00, 0x19, 0x00, 0x0f, 0x42, 0x40, // Yours: 25
			0x00, 0x0f, 0x42, 0x40, 0x00, 0x00, 0x00, 0x00,
		},
		Packet: BfdControlPacket{
			Version: 1, Diagnostic: DIAG_NONE, State: STATE_DOWN,
			Poll: false, Final: false, ControlPlaneIndependent: false, AuthPresent: false, Demand: false, Multipoint: false,
			DetectMult: 3, MyDiscriminator: 1, YourDiscriminator: 25,
			DesiredMinTxInterval: 1000000, RequiredMinRxInterval: 1000000, RequiredMinEchoRxInterval: 0,
			AuthHeader: nil,
		},
	},
	{
		Name: "State: Admin Down",
		Data: []byte{
			0x20, 0x00, 0x03, 0x18, 0x00, 0x00, 0x00, 0x01, // State: Admin Down
			0x00, 0x00, 0x00, 0x19, 0x00, 0x0f, 0x42, 0x40,
			0x00, 0x0f, 0x42, 0x40, 0x00, 0x00, 0x00, 0x00,
		},
		Packet: BfdControlPacket{
			Version: 1, Diagnostic: DIAG_NONE, State: STATE_ADMIN_DOWN,
			Poll: false, Final: false, ControlPlaneIndependent: false, AuthPresent: false, Demand: false, Multipoint: false,
			DetectMult: 3, MyDiscriminator: 1, YourDiscriminator: 25,
			DesiredMinTxInterval: 1000000, RequiredMinRxInterval: 1000000, RequiredMinEchoRxInterval: 0,
			AuthHeader: nil,
		},
	},
	{
		Name: "State: Init",
		Data: []byte{
			0x20, 0x80, 0x03, 0x18, 0x00, 0x00, 0x00, 0x01, // State: Init
			0x00, 0x00, 0x00, 0x19, 0x00, 0x0f, 0x42, 0x40,
			0x00, 0x0f, 0x42, 0x40, 0x00, 0x00, 0x00, 0x00,
		},
		Packet: BfdControlPacket{
			Version: 1, Diagnostic: DIAG_NONE, State: STATE_INIT,
			Poll: false, Final: false, ControlPlaneIndependent: false, AuthPresent: false, Demand: false, Multipoint: false,
			DetectMult: 3, MyDiscriminator: 1, YourDiscriminator: 25,
			DesiredMinTxInterval: 1000000, RequiredMinRxInterval: 1000000, RequiredMinEchoRxInterval: 0,
			AuthHeader: nil,
		},
	},
	{
		Name: "State: UP",
		Data: []byte{
			0x20, 0xc0, 0x03, 0x18, 0x00, 0x00, 0x00, 0x01, // State: UP
			0x00, 0x00, 0x00, 0x19, 0x00, 0x0f, 0x42, 0x40,
			0x00, 0x0f, 0x42, 0x40, 0x00, 0x00, 0x00, 0x00,
		},
		Packet: BfdControlPacket{
			Version: 1, Diagnostic: DIAG_NONE, State: STATE_UP,
			Poll: false, Final: false, ControlPlaneIndependent: false, AuthPresent: false, Demand: false, Multipoint: false,
			DetectMult: 3, MyDiscriminator: 1, YourDiscriminator: 25,
			DesiredMinTxInterval: 1000000, RequiredMinRxInterval: 1000000, RequiredMinEchoRxInterval: 0,
			AuthHeader: nil,
		},
	},
	{
		Name: "Flag: Poll",
		Data: []byte{0x20, 0xe0, 0x03, 0x18, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x19, 0x00, 0x0f, 0x42, 0x40, 0x00, 0x0f, 0x42, 0x40, 0x00, 0x00, 0x00, 0x00},
		Packet: BfdControlPacket{
			Version: 1, Diagnostic: DIAG_NONE, State: STATE_UP,
			Poll: true, Final: false, ControlPlaneIndependent: false, AuthPresent: false, Demand: false, Multipoint: false,
			DetectMult: 3, MyDiscriminator: 1, YourDiscriminator: 25,
			DesiredMinTxInterval: 1000000, RequiredMinRxInterval: 1000000, RequiredMinEchoRxInterval: 0,
			AuthHeader: nil,
		},
	},
	{
		Name: "Flag: Final",
		Data: []byte{0x20, 0xd0, 0x03, 0x18, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x19, 0x00, 0x0f, 0x42, 0x40, 0x00, 0x0f, 0x42, 0x40, 0x00, 0x00, 0x00, 0x00},
		Packet: BfdControlPacket{
			Version: 1, Diagnostic: DIAG_NONE, State: STATE_UP,
			Poll: false, Final: true, ControlPlaneIndependent: false, AuthPresent: false, Demand: false, Multipoint: false,
			DetectMult: 3, MyDiscriminator: 1, YourDiscriminator: 25,
			DesiredMinTxInterval: 1000000, RequiredMinRxInterval: 1000000, RequiredMinEchoRxInterval: 0,
			AuthHeader: nil,
		},
	},
	{
		Name: "Flag: Control Plane Independent",
		Data: []byte{0x20, 0xc8, 0x03, 0x18, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x19, 0x00, 0x0f, 0x42, 0x40, 0x00, 0x0f, 0x42, 0x40, 0x00, 0x00, 0x00, 0x00},
		Packet: BfdControlPacket{
			Version: 1, Diagnostic: DIAG_NONE, State: STATE_UP,
			Poll: false, Final: false, ControlPlaneIndependent: true, AuthPresent: false, Demand: false, Multipoint: false,
			DetectMult: 3, MyDiscriminator: 1, YourDiscriminator: 25,
			DesiredMinTxInterval: 1000000, RequiredMinRxInterval: 1000000, RequiredMinEchoRxInterval: 0,
			AuthHeader: nil,
		},
	},
	{
		Name: "Flag: Demand",
		Data: []byte{0x20, 0xc2, 0x03, 0x18, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x19, 0x00, 0x0f, 0x42, 0x40, 0x00, 0x0f, 0x42, 0x40, 0x00, 0x00, 0x00, 0x00},
		Packet: BfdControlPacket{
			Version: 1, Diagnostic: DIAG_NONE, State: STATE_UP,
			Poll: false, Final: false, ControlPlaneIndependent: false, AuthPresent: false, Demand: true, Multipoint: false,
			DetectMult: 3, MyDiscriminator: 1, YourDiscriminator: 25,
			DesiredMinTxInterval: 1000000, RequiredMinRxInterval: 1000000, RequiredMinEchoRxInterval: 0,
			AuthHeader: nil,
		},
	},
	{
		Name: "Flag: Multipoint",
		Data: []byte{0x20, 0xc1, 0x03, 0x18, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x19, 0x00, 0x0f, 0x42, 0x40, 0x00, 0x0f, 0x42, 0x40, 0x00, 0x00, 0x00, 0x00},
		Packet: BfdControlPacket{
			Version: 1, Diagnostic: DIAG_NONE, State: STATE_UP,
			Poll: false, Final: false, ControlPlaneIndependent: false, AuthPresent: false, Demand: false, Multipoint: true,
			DetectMult: 3, MyDiscriminator: 1, YourDiscriminator: 25,
			DesiredMinTxInterval: 1000000, RequiredMinRxInterval: 1000000, RequiredMinEchoRxInterval: 0,
			AuthHeader: nil,
		},
	},
	{
		Name: "Detection: Multiplier",
		Data: []byte{0x20, 0xc0, 0x0a, 0x18, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x19, 0x00, 0x0f, 0x42, 0x40, 0x00, 0x0f, 0x42, 0x40, 0x00, 0x00, 0x00, 0x00},
		Packet: BfdControlPacket{
			Version: 1, Diagnostic: DIAG_NONE, State: STATE_UP,
			Poll: false, Final: false, ControlPlaneIndependent: false, AuthPresent: false, Demand: false, Multipoint: false,
			DetectMult: 10, MyDiscriminator: 1, YourDiscriminator: 25,
			DesiredMinTxInterval: 1000000, RequiredMinRxInterval: 1000000, RequiredMinEchoRxInterval: 0,
			AuthHeader: nil,
		},
	},
	{
		Name: "Detection: DesiredMinTxInterval",
		Data: []byte{0x20, 0xc0, 0x0a, 0x18, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x19, 0x00, 0x2d, 0xc6, 0xc0, 0x00, 0x0f, 0x42, 0x40, 0x00, 0x00, 0x00, 0x00},
		Packet: BfdControlPacket{
			Version: 1, Diagnostic: DIAG_NONE, State: STATE_UP,
			Poll: false, Final: false, ControlPlaneIndependent: false, AuthPresent: false, Demand: false, Multipoint: false,
			DetectMult: 10, MyDiscriminator: 1, YourDiscriminator: 25,
			DesiredMinTxInterval: 3000000, RequiredMinRxInterval: 1000000, RequiredMinEchoRxInterval: 0,
			AuthHeader: nil,
		},
	},
	{
		Name: "Detection: RequiredMinRxInterval",
		Data: []byte{0x20, 0xc0, 0x0a, 0x18, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x19, 0x00, 0x0f, 0x42, 0x40, 0x00, 0x2d, 0xc6, 0xc0, 0x00, 0x00, 0x00, 0x00},
		Packet: BfdControlPacket{
			Version: 1, Diagnostic: DIAG_NONE, State: STATE_UP,
			Poll: false, Final: false, ControlPlaneIndependent: false, AuthPresent: false, Demand: false, Multipoint: false,
			DetectMult: 10, MyDiscriminator: 1, YourDiscriminator: 25,
			DesiredMinTxInterval: 1000000, RequiredMinRxInterval: 3000000, RequiredMinEchoRxInterval: 0,
			AuthHeader: nil,
		},
	},
	{
		Name: "Detection: RequiredMinEchoRxInterval",
		Data: []byte{0x20, 0xc0, 0x0a, 0x18, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x19, 0x00, 0x0f, 0x42, 0x40, 0x00, 0x0f, 0x42, 0x40, 0x00, 0x0f, 0x42, 0x40},
		Packet: BfdControlPacket{
			Version: 1, Diagnostic: DIAG_NONE, State: STATE_UP,
			Poll: false, Final: false, ControlPlaneIndependent: false, AuthPresent: false, Demand: false, Multipoint: false,
			DetectMult: 10, MyDiscriminator: 1, YourDiscriminator: 25,
			DesiredMinTxInterval: 1000000, RequiredMinRxInterval: 1000000, RequiredMinEchoRxInterval: 1000000,
			AuthHeader: nil,
		},
	},
	{
		Name: "Authentication: SIMPLE",
		Data: []byte{
			0x20, 0xc4, 0x03, 0x23, 0x00, 0x00, 0x00, 0x01, // State: UP, Auth Present
			0x00, 0x00, 0x00, 0x19, 0x00, 0x0f, 0x42, 0x40,
			0x00, 0x0f, 0x42, 0x40, 0x00, 0x00, 0x00, 0x00,
			0x01, 0x0b, 0x01,
			0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, // password
		},
		Packet: BfdControlPacket{
			Version: 1, Diagnostic: DIAG_NONE, State: STATE_UP,
			Poll: false, Final: false, ControlPlaneIndependent: false, AuthPresent: true, Demand: false, Multipoint: false,
			DetectMult: 3, MyDiscriminator: 1, YourDiscriminator: 25,
			DesiredMinTxInterval: 1000000, RequiredMinRxInterval: 1000000, RequiredMinEchoRxInterval: 0,
			AuthHeader: &BfdAuthHeader{
				Type:      BFD_AUTH_TYPE_SIMPLE,
				AuthKeyID: 1,
				AuthData:  []byte{0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64},
			},
		},
	},
	{
		Name: "Authentication: Keyed MD5",
		Data: []byte{
			0x20, 0xc4, 0x03, 0x30, 0x00, 0x00, 0x00, 0x01, // State: UP, Auth Present
			0x00, 0x00, 0x00, 0x19, 0x00, 0x0f, 0x42, 0x40,
			0x00, 0x0f, 0x42, 0x40, 0x00, 0x00, 0x00, 0x00,
			0x02, 0x18, 0x01, 0x00,
			0x00, 0x00, 0x00, 0x01,
			0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, // abcdefghijklmnop
		},
		Packet: BfdControlPacket{
			Version: 1, Diagnostic: DIAG_NONE, State: STATE_UP,
			Poll: false, Final: false, ControlPlaneIndependent: false, AuthPresent: true, Demand: false, Multipoint: false,
			DetectMult: 3, MyDiscriminator: 1, YourDiscriminator: 25,
			DesiredMinTxInterval: 1000000, RequiredMinRxInterval: 1000000, RequiredMinEchoRxInterval: 0,
			AuthHeader: &BfdAuthHeader{
				Type:           BFD_AUTH_TYPE_KEYED_MD5,
				AuthKeyID:      1,
				SequenceNumber: 1,
				AuthData:       []byte{0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70},
			},
		},
	},
	{
		Name: "Authentication: Keyed SHA1",
		Data: []byte{
			0x20, 0xc4, 0x03, 0x34, 0x00, 0x00, 0x00, 0x01, // State: UP, Auth Present
			0x00, 0x00, 0x00, 0x19, 0x00, 0x0f, 0x42, 0x40,
			0x00, 0x0f, 0x42, 0x40, 0x00, 0x00, 0x00, 0x00,
			0x04, 0x1c, 0x01, 0x00,
			0x00, 0x00, 0x00, 0x01,
			0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, // abcdefghijklmnopqrst
		},
		Packet: BfdControlPacket{
			Version: 1, Diagnostic: DIAG_NONE, State: STATE_UP,
			Poll: false, Final: false, ControlPlaneIndependent: false, AuthPresent: true, Demand: false, Multipoint: false,
			DetectMult: 3, MyDiscriminator: 1, YourDiscriminator: 25,
			DesiredMinTxInterval: 1000000, RequiredMinRxInterval: 1000000, RequiredMinEchoRxInterval: 0,
			AuthHeader: &BfdAuthHeader{
				Type:           BFD_AUTH_TYPE_KEYED_SHA1,
				AuthKeyID:      1,
				SequenceNumber: 1,
				AuthData:       []byte{0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74},
			},
		},
	},
}

/*
 * Loop through the data sets to test decoding
 */
func TestDecodeBfdControlPacket(t *testing.T) {
	var got *BfdControlPacket
	var err error

	for _, e := range tests {
		got, err = decodeBfdPacket(e.Data)
		if err != nil {
			fmt.Println("Error decoding BFD Control Packet:", err)
		}
		if !reflect.DeepEqual(&e.Packet, got) {
			t.Errorf("BFD mismatch for test '%s', \nexpected:\n%#v\n\ngot:\n%#v\n\n", e.Name, e.Packet, got)
			if e.Packet.AuthHeader != nil {
				t.Errorf("Auth expected:\n%#v\n\ngot:\n%#v\n\n", e.Packet.AuthHeader, got.AuthHeader)
			}
		}
	}
}

/*
 * Loop through the data sets to test marshalling
 */
func TestMarshalBfdControlPacket(t *testing.T) {
	var got []byte

	for _, e := range tests {
		got = e.Packet.Marshal()
		if got == nil {
			fmt.Println("Error Marshalling BFD Control Packet:", e.Name)
		}
		if !bytes.Equal(e.Data, got) {
			t.Errorf("BFD mismatch for test '%s', \nexpected:\n%#v\n\ngot:\n%#v\n\n", e.Name, e.Data, got)
		}
	}
}

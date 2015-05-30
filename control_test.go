package bfd

import (
	"fmt"
	"reflect"
	"testing"
)

type bfdControlPacketTestSet struct {
	Name     string
	Raw      []byte
	Expected BfdControlPacket
}

var tests = []bfdControlPacketTestSet{
	{
		Name: "Default",
		Raw: []byte{
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
		Expected: BfdControlPacketDefaults,
	},
	{
		Name: "Discriminator",
		Raw: []byte{
			0x20, 0x40, 0x03, 0x18, 0x00, 0x00, 0x00, 0x01, // Mine:   1
			0x00, 0x00, 0x00, 0x19, 0x00, 0x0f, 0x42, 0x40, // Yours: 25
			0x00, 0x0f, 0x42, 0x40, 0x00, 0x00, 0x00, 0x00,
		},
		Expected: BfdControlPacket{
			Version: 1, Diagnostic: DIAG_NONE, State: STATE_DOWN,
			Poll: false, Final: false, ControlPlaneIndependent: false, AuthPresent: false, Demand: false, Multipoint: false,
			DetectMult: 3, MyDiscriminator: 1, YourDiscriminator: 25,
			DesiredMinTxInterval: 1000000, RequiredMinRxInterval: 1000000, RequiredMinEchoRxInterval: 0,
			AuthHeader: nil,
		},
	},
	{
		Name: "State: Admin Down",
		Raw: []byte{
			0x20, 0x00, 0x03, 0x18, 0x00, 0x00, 0x00, 0x01, // State: Admin Down
			0x00, 0x00, 0x00, 0x19, 0x00, 0x0f, 0x42, 0x40,
			0x00, 0x0f, 0x42, 0x40, 0x00, 0x00, 0x00, 0x00,
		},
		Expected: BfdControlPacket{
			Version: 1, Diagnostic: DIAG_NONE, State: STATE_ADMIN_DOWN,
			Poll: false, Final: false, ControlPlaneIndependent: false, AuthPresent: false, Demand: false, Multipoint: false,
			DetectMult: 3, MyDiscriminator: 1, YourDiscriminator: 25,
			DesiredMinTxInterval: 1000000, RequiredMinRxInterval: 1000000, RequiredMinEchoRxInterval: 0,
			AuthHeader: nil,
		},
	},
	{
		Name: "State: Init",
		Raw: []byte{
			0x20, 0x80, 0x03, 0x18, 0x00, 0x00, 0x00, 0x01, // State: Init
			0x00, 0x00, 0x00, 0x19, 0x00, 0x0f, 0x42, 0x40,
			0x00, 0x0f, 0x42, 0x40, 0x00, 0x00, 0x00, 0x00,
		},
		Expected: BfdControlPacket{
			Version: 1, Diagnostic: DIAG_NONE, State: STATE_INIT,
			Poll: false, Final: false, ControlPlaneIndependent: false, AuthPresent: false, Demand: false, Multipoint: false,
			DetectMult: 3, MyDiscriminator: 1, YourDiscriminator: 25,
			DesiredMinTxInterval: 1000000, RequiredMinRxInterval: 1000000, RequiredMinEchoRxInterval: 0,
			AuthHeader: nil,
		},
	},
	{
		Name: "State: UP",
		Raw: []byte{
			0x20, 0xc0, 0x03, 0x18, 0x00, 0x00, 0x00, 0x01, // State: UP
			0x00, 0x00, 0x00, 0x19, 0x00, 0x0f, 0x42, 0x40,
			0x00, 0x0f, 0x42, 0x40, 0x00, 0x00, 0x00, 0x00,
		},
		Expected: BfdControlPacket{
			Version: 1, Diagnostic: DIAG_NONE, State: STATE_UP,
			Poll: false, Final: false, ControlPlaneIndependent: false, AuthPresent: false, Demand: false, Multipoint: false,
			DetectMult: 3, MyDiscriminator: 1, YourDiscriminator: 25,
			DesiredMinTxInterval: 1000000, RequiredMinRxInterval: 1000000, RequiredMinEchoRxInterval: 0,
			AuthHeader: nil,
		},
	},
	{
		Name: "Flag: Poll",
		Raw:  []byte{0x20, 0xe0, 0x03, 0x18, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x19, 0x00, 0x0f, 0x42, 0x40, 0x00, 0x0f, 0x42, 0x40, 0x00, 0x00, 0x00, 0x00},
		Expected: BfdControlPacket{
			Version: 1, Diagnostic: DIAG_NONE, State: STATE_UP,
			Poll: true, Final: false, ControlPlaneIndependent: false, AuthPresent: false, Demand: false, Multipoint: false,
			DetectMult: 3, MyDiscriminator: 1, YourDiscriminator: 25,
			DesiredMinTxInterval: 1000000, RequiredMinRxInterval: 1000000, RequiredMinEchoRxInterval: 0,
			AuthHeader: nil,
		},
	},
	{
		Name: "Flag: Final",
		Raw:  []byte{0x20, 0xd0, 0x03, 0x18, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x19, 0x00, 0x0f, 0x42, 0x40, 0x00, 0x0f, 0x42, 0x40, 0x00, 0x00, 0x00, 0x00},
		Expected: BfdControlPacket{
			Version: 1, Diagnostic: DIAG_NONE, State: STATE_UP,
			Poll: false, Final: true, ControlPlaneIndependent: false, AuthPresent: false, Demand: false, Multipoint: false,
			DetectMult: 3, MyDiscriminator: 1, YourDiscriminator: 25,
			DesiredMinTxInterval: 1000000, RequiredMinRxInterval: 1000000, RequiredMinEchoRxInterval: 0,
			AuthHeader: nil,
		},
	},
	{
		Name: "Flag: Control Plane Independent",
		Raw:  []byte{0x20, 0xc8, 0x03, 0x18, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x19, 0x00, 0x0f, 0x42, 0x40, 0x00, 0x0f, 0x42, 0x40, 0x00, 0x00, 0x00, 0x00},
		Expected: BfdControlPacket{
			Version: 1, Diagnostic: DIAG_NONE, State: STATE_UP,
			Poll: false, Final: false, ControlPlaneIndependent: true, AuthPresent: false, Demand: false, Multipoint: false,
			DetectMult: 3, MyDiscriminator: 1, YourDiscriminator: 25,
			DesiredMinTxInterval: 1000000, RequiredMinRxInterval: 1000000, RequiredMinEchoRxInterval: 0,
			AuthHeader: nil,
		},
	},
	{
		Name: "Flag: Demand",
		Raw:  []byte{0x20, 0xc2, 0x03, 0x18, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x19, 0x00, 0x0f, 0x42, 0x40, 0x00, 0x0f, 0x42, 0x40, 0x00, 0x00, 0x00, 0x00},
		Expected: BfdControlPacket{
			Version: 1, Diagnostic: DIAG_NONE, State: STATE_UP,
			Poll: false, Final: false, ControlPlaneIndependent: false, AuthPresent: false, Demand: true, Multipoint: false,
			DetectMult: 3, MyDiscriminator: 1, YourDiscriminator: 25,
			DesiredMinTxInterval: 1000000, RequiredMinRxInterval: 1000000, RequiredMinEchoRxInterval: 0,
			AuthHeader: nil,
		},
	},
	{
		Name: "Flag: Multipoint",
		Raw:  []byte{0x20, 0xc1, 0x03, 0x18, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x19, 0x00, 0x0f, 0x42, 0x40, 0x00, 0x0f, 0x42, 0x40, 0x00, 0x00, 0x00, 0x00},
		Expected: BfdControlPacket{
			Version: 1, Diagnostic: DIAG_NONE, State: STATE_UP,
			Poll: false, Final: false, ControlPlaneIndependent: false, AuthPresent: false, Demand: false, Multipoint: true,
			DetectMult: 3, MyDiscriminator: 1, YourDiscriminator: 25,
			DesiredMinTxInterval: 1000000, RequiredMinRxInterval: 1000000, RequiredMinEchoRxInterval: 0,
			AuthHeader: nil,
		},
	},
	{
		Name: "Detection: Multiplier",
		Raw:  []byte{0x20, 0xc0, 0x0a, 0x18, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x19, 0x00, 0x0f, 0x42, 0x40, 0x00, 0x0f, 0x42, 0x40, 0x00, 0x00, 0x00, 0x00},
		Expected: BfdControlPacket{
			Version: 1, Diagnostic: DIAG_NONE, State: STATE_UP,
			Poll: false, Final: false, ControlPlaneIndependent: false, AuthPresent: false, Demand: false, Multipoint: false,
			DetectMult: 10, MyDiscriminator: 1, YourDiscriminator: 25,
			DesiredMinTxInterval: 1000000, RequiredMinRxInterval: 1000000, RequiredMinEchoRxInterval: 0,
			AuthHeader: nil,
		},
	},
	{
		Name: "Detection: DesiredMinTxInterval",
		Raw:  []byte{0x20, 0xc0, 0x0a, 0x18, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x19, 0x00, 0x2d, 0xc6, 0xc0, 0x00, 0x0f, 0x42, 0x40, 0x00, 0x00, 0x00, 0x00},
		Expected: BfdControlPacket{
			Version: 1, Diagnostic: DIAG_NONE, State: STATE_UP,
			Poll: false, Final: false, ControlPlaneIndependent: false, AuthPresent: false, Demand: false, Multipoint: false,
			DetectMult: 10, MyDiscriminator: 1, YourDiscriminator: 25,
			DesiredMinTxInterval: 3000000, RequiredMinRxInterval: 1000000, RequiredMinEchoRxInterval: 0,
			AuthHeader: nil,
		},
	},
	{
		Name: "Detection: RequiredMinRxInterval",
		Raw:  []byte{0x20, 0xc0, 0x0a, 0x18, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x19, 0x00, 0x0f, 0x42, 0x40, 0x00, 0x2d, 0xc6, 0xc0, 0x00, 0x00, 0x00, 0x00},
		Expected: BfdControlPacket{
			Version: 1, Diagnostic: DIAG_NONE, State: STATE_UP,
			Poll: false, Final: false, ControlPlaneIndependent: false, AuthPresent: false, Demand: false, Multipoint: false,
			DetectMult: 10, MyDiscriminator: 1, YourDiscriminator: 25,
			DesiredMinTxInterval: 1000000, RequiredMinRxInterval: 3000000, RequiredMinEchoRxInterval: 0,
			AuthHeader: nil,
		},
	},
	{
		Name: "Detection: RequiredMinEchoRxInterval",
		Raw:  []byte{0x20, 0xc0, 0x0a, 0x18, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x19, 0x00, 0x0f, 0x42, 0x40, 0x00, 0x0f, 0x42, 0x40, 0x00, 0x0f, 0x42, 0x40},
		Expected: BfdControlPacket{
			Version: 1, Diagnostic: DIAG_NONE, State: STATE_UP,
			Poll: false, Final: false, ControlPlaneIndependent: false, AuthPresent: false, Demand: false, Multipoint: false,
			DetectMult: 10, MyDiscriminator: 1, YourDiscriminator: 25,
			DesiredMinTxInterval: 1000000, RequiredMinRxInterval: 1000000, RequiredMinEchoRxInterval: 1000000,
			AuthHeader: nil,
		},
	},
}

/*
 * Loop through the data sets above testing different packets
 */
func TestDataSet(t *testing.T) {
	var got *BfdControlPacket
	var err error

	for _, e := range tests {
		got, err = decodeBfdPacket(e.Raw)
		if err != nil {
			fmt.Println("Error decodeing BFD Control Packet:", err)
		}
		if !reflect.DeepEqual(&e.Expected, got) {
			t.Errorf("BFD mismatch for test '%s', \nexpected:\n%#v\n\ngot:\n%#v\n\n", e.Name, e.Expected, got)
		}
	}
}

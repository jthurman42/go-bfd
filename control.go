package bfd

/*
import (
	"bytes"
)
*/
const (
	STATE_ADMIN_DOWN = 0 // AdminDown
	STATE_DOWN       = 1 // Down
	STATE_INIT       = 2 // Init
	STATE_UP         = 3 // Up
)

const (
	DIAG_NONE                 = 0 // No Diagnostic
	DIAG_TIME_EXPIRED         = 1 // Control Detection Time Expired
	DIAG_ECHO_FAILED          = 2 // Echo Function Failed
	DIAG_NEIGHBOR_SIGNAL_DOWN = 3 // Neighbor Signaled Session Down
	DIAG_FORWARD_PLANE_RESET  = 4 // Forwarding Plane Reset
	DIAG_PATH_DOWN            = 5 // Path Down
	DIAG_CONCAT_PATH_DOWN     = 6 // Concatenated Path Down
	DIAG_ADMIN_DOWN           = 7 // Administratively Down
	DIAG_REV_CONCAT_PATH_DOWN = 8 // Reverse Concatenated Path Down
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

 * An optional Authentication Section MAY be present:

 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |   Auth Type   |   Auth Len    |    Authentication Data...     |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
type BfdControlPacket struct {
	Header                    uint8
	Flags                     uint8
	DetectMult                uint8
	Len                       uint8
	LocalDiscr                uint32
	RemoteDiscr               uint32
	DesiredMinTxInterval      uint32
	RequiredMinRxInterval     uint32
	RequiredMinEchoRxInterval uint32
}

/*
 *
func DecodeBfdPacket(data []byte) (*BfdStatus, err) {
	packet = BfdControlPacket{}
}
*/

package bfd

type BfdStatus struct {
	SessionState          int
	RemoteSessionState    int
	LocalDiscr            uint32
	RemoteDiscr           uint32
	LocalDiat             int
	DesiredMinTxInterval  int
	RequiredMinRxInterval int
	RemoteMinRxInterval   int
	DemandMode            bool
	RemoteDemandMode      bool
	DetectMult            uint8
	AuthType              AuthenticationType
	RcvAuthSeq            uint32
	XmitAuthSeq           uint32
	AuthSeqKnown          bool
}

/* State Machine
                             +--+
                             |  | UP, ADMIN DOWN, TIMER
                             |  V
                     DOWN  +------+  INIT
              +------------|      |------------+
              |            | DOWN |            |
              |  +-------->|      |<--------+  |
              |  |         +------+         |  |
              |  |                          |  |
              |  |               ADMIN DOWN,|  |
              |  |ADMIN DOWN,          DOWN,|  |
              |  |TIMER                TIMER|  |
              V  |                          |  V
            +------+                      +------+
       +----|      |                      |      |----+
   DOWN|    | INIT |--------------------->|  UP  |    |INIT, UP
       +--->|      | INIT, UP             |      |<---+
            +------+                      +------+
*/

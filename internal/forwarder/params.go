package forwarder

import (
	"encoding/binary"
	"time"
)

const controlStreamTimeout = 10 * time.Second

var controlProtocolEndian = binary.BigEndian

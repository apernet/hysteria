package l2tp

// ProxyInfo holds the PPP LCP negotiation and authentication results
// collected by the LAC during the initial PPP phase. These values are
// forwarded to the LNS as proxy AVPs in the L2TP ICCN message.
type ProxyInfo struct {
	// Raw LCP Config-Request packets (Code, ID, Length, Options).
	// No FF 03 address/control bytes, no PPP protocol field.
	InitialReceivedCONFREQ []byte
	LastSentCONFREQ        []byte
	LastReceivedCONFREQ    []byte

	AuthType      uint16 // 2 = PPP CHAP, 3 = PPP PAP (per RFC 2661 Section 4.4.5)
	AuthName      string // PPP username (e.g. user@ispA.com)
	AuthChallenge []byte // CHAP challenge sent by LAC (CHAP only)
	AuthID        byte   // CHAP: challenge ID; PAP: Authenticate-Request Identifier
	AuthResponse  []byte // CHAP: response hash; PAP: cleartext password

	Realm string // extracted from AuthName (part after last '@')

	EndpointDiscriminator []byte // Multilink PPP endpoint discriminator (class + address from LCP option 19); nil if not present
}

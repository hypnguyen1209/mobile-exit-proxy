package main

// TLS ClientHello SNI (Server Name Indication) parser.
// Extracts the hostname from the first TLS record without consuming the bytes,
// so the full ClientHello can still be forwarded to Burp or the destination.

// ParseTLSClientHelloSNI extracts the SNI hostname from a TLS ClientHello message.
// Returns empty string if the data is not a valid ClientHello or has no SNI extension.
func ParseTLSClientHelloSNI(data []byte) string {
	// TLS record header: ContentType(1) + Version(2) + Length(2)
	if len(data) < 5 {
		return ""
	}
	// ContentType must be Handshake (0x16)
	if data[0] != 0x16 {
		return ""
	}

	// Record length
	recordLen := int(data[3])<<8 | int(data[4])
	if len(data) < 5+recordLen {
		// We may have a partial record — try to parse what we have.
		recordLen = len(data) - 5
	}
	record := data[5 : 5+recordLen]

	// Handshake header: Type(1) + Length(3)
	if len(record) < 4 {
		return ""
	}
	// Handshake type must be ClientHello (0x01)
	if record[0] != 0x01 {
		return ""
	}

	handshakeLen := int(record[1])<<16 | int(record[2])<<8 | int(record[3])
	if len(record) < 4+handshakeLen {
		handshakeLen = len(record) - 4
	}
	hello := record[4 : 4+handshakeLen]

	// ClientHello structure:
	//   Version(2) + Random(32) + SessionIDLen(1) + SessionID(var)
	//   + CipherSuitesLen(2) + CipherSuites(var)
	//   + CompressionMethodsLen(1) + CompressionMethods(var)
	//   + ExtensionsLen(2) + Extensions(var)

	pos := 0

	// Version (2 bytes)
	if pos+2 > len(hello) {
		return ""
	}
	pos += 2

	// Random (32 bytes)
	if pos+32 > len(hello) {
		return ""
	}
	pos += 32

	// Session ID
	if pos+1 > len(hello) {
		return ""
	}
	sessionIDLen := int(hello[pos])
	pos++
	if pos+sessionIDLen > len(hello) {
		return ""
	}
	pos += sessionIDLen

	// Cipher Suites
	if pos+2 > len(hello) {
		return ""
	}
	cipherSuitesLen := int(hello[pos])<<8 | int(hello[pos+1])
	pos += 2
	if pos+cipherSuitesLen > len(hello) {
		return ""
	}
	pos += cipherSuitesLen

	// Compression Methods
	if pos+1 > len(hello) {
		return ""
	}
	compressionLen := int(hello[pos])
	pos++
	if pos+compressionLen > len(hello) {
		return ""
	}
	pos += compressionLen

	// Extensions
	if pos+2 > len(hello) {
		return ""
	}
	extensionsLen := int(hello[pos])<<8 | int(hello[pos+1])
	pos += 2
	if pos+extensionsLen > len(hello) {
		extensionsLen = len(hello) - pos
	}

	extensions := hello[pos : pos+extensionsLen]
	return findSNI(extensions)
}

// findSNI walks TLS extensions to find the SNI extension (type 0x0000).
func findSNI(extensions []byte) string {
	pos := 0
	for pos+4 <= len(extensions) {
		extType := int(extensions[pos])<<8 | int(extensions[pos+1])
		extLen := int(extensions[pos+2])<<8 | int(extensions[pos+3])
		pos += 4

		if pos+extLen > len(extensions) {
			return ""
		}

		if extType == 0 { // SNI extension
			return parseSNIExtension(extensions[pos : pos+extLen])
		}

		pos += extLen
	}
	return ""
}

// parseSNIExtension parses the SNI extension data.
// Format: ServerNameListLen(2) + [NameType(1) + NameLen(2) + Name(var)]*
func parseSNIExtension(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	listLen := int(data[0])<<8 | int(data[1])
	if len(data) < 2+listLen {
		listLen = len(data) - 2
	}

	pos := 2
	for pos+3 <= 2+listLen {
		nameType := data[pos]
		nameLen := int(data[pos+1])<<8 | int(data[pos+2])
		pos += 3

		if pos+nameLen > len(data) {
			return ""
		}

		if nameType == 0 { // host_name
			return string(data[pos : pos+nameLen])
		}

		pos += nameLen
	}
	return ""
}

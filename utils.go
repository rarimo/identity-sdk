package identity

import (
	"encoding/hex"
)

func convertEndianSwappedCoreStateHashHex(hash string) string {
	// Remove the "0x" prefix and decode the hex string
	decodedHash, err := hex.DecodeString(hash[2:])
	if err != nil {
		return ""
	}

	// Reverse the byte order (little-endian to big-endian)
	reverseBytes(decodedHash)

	// Convert the reversed byte array back to a hex string
	convertedStateHash := hex.EncodeToString(decodedHash)

	// Add "0x" prefix if necessary
	if len(convertedStateHash) < 64 {
		return "0x0" + convertedStateHash
	}
	return "0x" + convertedStateHash
}

func reverseBytes(data []byte) {
	for i, j := 0, len(data)-1; i < j; i, j = i+1, j-1 {
		data[i], data[j] = data[j], data[i]
	}
}

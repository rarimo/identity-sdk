package identity

import (
	"encoding/hex"
)

func hexEndianSwap(hash string) string {
	if hash[:2] == "0x" {
		hash = hash[2:]
	}

	// Remove the "0x" prefix and decode the hex string
	decodedHash, err := hex.DecodeString(hash)
	if err != nil {
		return ""
	}

	// Reverse the byte order (little-endian to big-endian)
	reverseBytes(decodedHash)

	// Convert the reversed byte array back to a hex string
	convertedStateHash := hex.EncodeToString(decodedHash)

	zeroesToAddNumber := 64 - len(convertedStateHash)
	var zeroesToAdd string
	for i := 0; i < zeroesToAddNumber; i++ {
		zeroesToAdd += "0"
	}

	return convertedStateHash + zeroesToAdd
}

func reverseBytes(data []byte) {
	for i, j := 0, len(data)-1; i < j; i, j = i+1, j-1 {
		data[i], data[j] = data[j], data[i]
	}
}

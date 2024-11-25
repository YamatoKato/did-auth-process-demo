package crypto

import (
	"crypto/ed25519"
	"encoding/base64"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
)

// 署名を検証
func VerifySignature(
	publicKey ed25519.PublicKey,
	message []byte,
	signature []byte,
) bool {
	return ed25519.Verify(publicKey, message, signature)
}

// secp256k1署名の検証
func VerifySignatureForSecp256k1(pubKeyBytes []byte, data string, signature []byte) bool {
	// 公開鍵の復元
	pubKey, _ := btcec.ParsePubKey(pubKeyBytes)

	// 署名の復元
	sig, _ := ecdsa.ParseDERSignature(signature)

	// 署名の検証
	return sig.Verify([]byte(data), pubKey)
}

// Base64形式でエンコード
func EncodeBase64(data []byte) string {
	return base64.URLEncoding.EncodeToString(data)
}

// Base64形式でデコード
func DecodeBase64(data string) ([]byte, error) {
	return base64.URLEncoding.DecodeString(data)
}

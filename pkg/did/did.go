package did

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"
)

// DIDから公開鍵を抽出
func ExtractPublicKeyFromDID(did string) (ed25519.PublicKey, error) {
	if !strings.HasPrefix(did, "did:key:") {
		return nil, errors.New("無効なDID形式です")
	}

	// DIDのプレフィックスを除去して公開鍵部分を取り出す
	keyBase64 := strings.TrimPrefix(did, "did:key:")
	pubKeyBytes, err := base64.URLEncoding.DecodeString(keyBase64)
	if err != nil {
		return nil, errors.New("公開鍵のデコードに失敗しました")
	}

	return ed25519.PublicKey(pubKeyBytes), nil
}

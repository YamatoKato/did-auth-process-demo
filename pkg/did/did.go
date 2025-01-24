package did

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
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

// 公開鍵からdid:keyを生成
func GenerateDIDFromPubKey(pubKey []byte) string {
	// Ref: https://w3c-ccg.github.io/did-method-key/#example-1
	keyBase64 := base64.URLEncoding.EncodeToString(pubKey)
	return fmt.Sprintf("did:key:%s", keyBase64)
}

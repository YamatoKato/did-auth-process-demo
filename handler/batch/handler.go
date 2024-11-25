package batch

import (
	"encoding/json"
	"io"
	"log"
	"net/http"

	cryptoPkg "github.com/YamatoKato/did-auth-process-demo/pkg/crypto"
	"github.com/YamatoKato/did-auth-process-demo/pkg/did"
)

func Handle(w http.ResponseWriter, r *http.Request) {
	// リクエストボディを読み取る
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Println("リクエストボディの読み取りに失敗しました")
		http.Error(w, "リクエストボディの読み取りに失敗しました", http.StatusBadRequest)
		return
	}

	// リクエストデータのパース
	var reqData []struct {
		DIDKey           string `json:"did_key"`
		EncodedSignature string `json:"encoded_signature"`
	}
	err = json.Unmarshal(body, &reqData)
	if err != nil {
		log.Println("リクエストデータのパースに失敗しました")
		http.Error(w, "リクエストデータのパースに失敗しました", http.StatusBadRequest)
		return
	}

	for _, data := range reqData {
		// DIDから公開鍵の取得
		pubKey, err := did.ExtractPublicKeyFromDID(data.DIDKey)
		if err != nil {
			log.Println("DIDから公開鍵の取得に失敗しました")
			http.Error(w, "DIDから公開鍵の取得に失敗しました", http.StatusBadRequest)
			return
		}

		// Base64形式の署名をデコード
		signature, err := cryptoPkg.DecodeBase64(data.EncodedSignature)
		if err != nil {
			log.Println("Base64形式の署名のデコードに失敗しました")
			http.Error(w, "Base64形式の署名のデコードに失敗しました", http.StatusBadRequest)
			return
		}

		// 署名の検証
		isValid := cryptoPkg.VerifySignature(
			pubKey,
			[]byte(data.DIDKey),
			signature,
		)
		if !isValid {
			log.Println("無効な署名です")
			http.Error(w, "無効な署名です", http.StatusBadRequest)
			return
		}
	}

	// 全ての署名が有効
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

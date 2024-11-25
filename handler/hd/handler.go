package hd

import (
	"encoding/json"
	"io"
	"log"
	"net/http"

	cryptoPkg "github.com/YamatoKato/did-auth-process-demo/pkg/crypto"
	"github.com/YamatoKato/did-auth-process-demo/pkg/did"
	"github.com/YamatoKato/did-auth-process-demo/pkg/hd"
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
	var reqData struct {
		DIDKey           string   `json:"did_key"` // did:key:base64url(parentPublicKey)
		EncodedSignature string   `json:"encoded_signature"`
		ChildNums        []uint32 `json:"childNums"`
		ChainCode        string   `json:"chainCode"`
	}
	err = json.Unmarshal(body, &reqData)
	if err != nil {
		log.Println("リクエストデータのパースに失敗しました")
		http.Error(w, "リクエストデータのパースに失敗しました", http.StatusBadRequest)
		return
	}

	// DIDから公開鍵の取得
	pubKey, err := did.ExtractPublicKeyFromDID(reqData.DIDKey)
	if err != nil {
		log.Println("DIDから公開鍵の取得に失敗しました")
		http.Error(w, "DIDから公開鍵の取得に失敗しました", http.StatusBadRequest)
		return
	}

	// Base64形式の署名をデコード
	signature, err := cryptoPkg.DecodeBase64(reqData.EncodedSignature)
	if err != nil {
		log.Println("Base64形式の署名のデコードに失敗しました")
		http.Error(w, "Base64形式の署名のデコードに失敗しました", http.StatusBadRequest)
		return
	}

	// 署名の検証
	isValid := cryptoPkg.VerifySignatureForSecp256k1(
		pubKey,
		reqData.DIDKey,
		signature,
	)
	if !isValid {
		log.Println("無効な署名です")
		http.Error(w, "無効な署名です", http.StatusBadRequest)
		return
	}

	// レスポンスデータの構造体
	type ResponseData struct {
		PublicKey string `json:"publicKey"`
		ChainCode string `json:"chainCode"`
		ChildNum  uint32 `json:"childNum"`
		Depth     uint8  `json:"depth"`
	}

	resData := make([]ResponseData, len(reqData.ChildNums))

	for _, childNum := range reqData.ChildNums {
		// 子公開鍵の生成
		chainCode, err := cryptoPkg.DecodeBase64(reqData.ChainCode)
		if err != nil {
			log.Printf("chainCodeのデコードに失敗しました: %v", err)
			http.Error(w, "chainCodeのデコードに失敗しました", http.StatusBadRequest)
			return
		}
		childKey := hd.NewExtendedKey(
			pubKey,
			chainCode,
			childNum,
		)

		exk, err := childKey.DeriveChildKey()
		if err != nil {
			log.Printf("子公開鍵の生成に失敗しました: %v", err)
			http.Error(w, "子公開鍵の生成に失敗しました", http.StatusBadRequest)
			return
		}

		// レスポンスデータに追加
		resData[childNum] = ResponseData{
			PublicKey: cryptoPkg.EncodeBase64(exk.PublicKey),
			ChainCode: cryptoPkg.EncodeBase64(exk.ChainCode),
			ChildNum:  exk.ChildNum,
			Depth:     exk.Depth,
		}
	}

	// レスポンスをJSONにエンコード
	respJSON, err := json.Marshal(resData)
	if err != nil {
		log.Printf("レスポンスデータのエンコードに失敗しました: %v", err)
		http.Error(w, "レスポンスデータのエンコードに失敗しました", http.StatusInternalServerError)
		return
	}

	// レスポンスを返す
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(respJSON)
}

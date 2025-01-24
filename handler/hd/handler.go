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

// 実測の便宜上、チャレンジ値を永続化しないため固定の文字列を使用
var challenge = "challenge"

func VerifyHandle(w http.ResponseWriter, r *http.Request) {
	// リクエストボディを読み取る
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Println("リクエストボディの読み取りに失敗しました")
		http.Error(w, "リクエストボディの読み取りに失敗しました", http.StatusBadRequest)
		return
	}

	// リクエストデータのパース
	var verifyReqData struct {
		PublicKey        string   `json:"publicKey"`
		ChainCode        string   `json:"chainCode"`
		ChildNums        []uint32 `json:"childNums"`
		EncodedSignature string   `json:"signature"`
	}
	err = json.Unmarshal(body, &verifyReqData)
	if err != nil {
		log.Println("リクエストデータのパースに失敗しました")
		http.Error(w, "リクエストデータのパースに失敗しました", http.StatusBadRequest)
		return
	}

	// 保持証明の検証
	pubKey, err := cryptoPkg.DecodeBase64(verifyReqData.PublicKey)
	if err != nil {
		log.Println("Base64形式の公開鍵のデコードに失敗しました")
		http.Error(w, "Base64形式の公開鍵のデコードに失敗しました", http.StatusBadRequest)
		return
	}

	// Base64形式の署名をデコード
	signature, err := cryptoPkg.DecodeBase64(verifyReqData.EncodedSignature)
	if err != nil {
		log.Println("Base64形式の署名のデコードに失敗しました")
		http.Error(w, "Base64形式の署名のデコードに失敗しました", http.StatusBadRequest)
		return
	}

	// 署名の検証
	isValid := cryptoPkg.VerifySignatureForSecp256k1(
		pubKey,
		challenge+verifyReqData.PublicKey+verifyReqData.ChainCode,
		signature,
	)
	if !isValid {
		log.Println("無効な署名です")
		http.Error(w, "無効な署名です", http.StatusBadRequest)
		return
	}

	// レスポンスデータの構造体
	type ResponseData struct {
		DID       string `json:"did"`
		PublicKey string `json:"publicKey"`
		ChainCode string `json:"chainCode"`
		ChildNum  uint32 `json:"childNum"`
		Depth     uint8  `json:"depth"`
	}

	resData := make([]ResponseData, len(verifyReqData.ChildNums))

	for _, childNum := range verifyReqData.ChildNums {
		// 子公開鍵の生成
		chainCode, err := cryptoPkg.DecodeBase64(verifyReqData.ChainCode)
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
			DID:       did.GenerateDIDFromPubKey(exk.PublicKey),
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

func RequestHandle(w http.ResponseWriter, r *http.Request) {
	// リクエストボディを読み取る
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Println("リクエストボディの読み取りに失敗しました")
		http.Error(w, "リクエストボディの読み取りに失敗しました", http.StatusBadRequest)
		return
	}

	// リクエストデータのパース
	var reqData struct {
		PublicKey string   `json:"publicKey"`
		ChainCode string   `json:"chainCode"`
		ChildNums []uint32 `json:"childNums"`
	}

	err = json.Unmarshal(body, &reqData)
	if err != nil {
		log.Println("リクエストデータのパースに失敗しました")
		http.Error(w, "リクエストデータのパースに失敗しました", http.StatusBadRequest)
		return
	}

	resData := struct {
		Challenge string `json:"challenge"`
	}{
		Challenge: challenge + reqData.PublicKey + reqData.ChainCode,
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

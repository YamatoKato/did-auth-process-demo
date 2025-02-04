package repeater

import (
	"encoding/json"
	"io"
	"log"
	"net/http"

	cryptoPkg "github.com/YamatoKato/did-auth-process-demo/pkg/crypto"
	"github.com/YamatoKato/did-auth-process-demo/pkg/did"
)

// 実測の便宜上、チャレンジ値を永続化しないため固定の文字列を使用
var challenge = "challenge"

func VerifyHandle(w http.ResponseWriter, r *http.Request) {
	// リクエストボディを読み取る
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Println("リクエストボディの読み取りに失敗しました")
		http.Error(w, "リクエストボディの読み取りに失敗しました", http.StatusBadRequest)
	}

	// リクエストデータのパース
	var verifyReqData struct {
		DID       string `json:did`
		Signature string `json:signature`
	}
	err = json.Unmarshal(body, &verifyReqData)
	if err != nil {
		log.Println("リクエストデータのパースに失敗しました")
		http.Error(w, "リクエストデータのパースに失敗しました", http.StatusBadRequest)
	}

	// DIDから公開鍵の取得
	pubKey, err := did.ExtractPublicKeyFromDID(verifyReqData.DID)
	if err != nil {
		log.Println("DIDから公開鍵の取得に失敗しました")
		http.Error(w, "DIDから公開鍵の取得に失敗しました", http.StatusBadRequest)
	}

	// Base64形式の署名をデコード
	signature, err := cryptoPkg.DecodeBase64(verifyReqData.Signature)
	if err != nil {
		log.Println("Base64形式の署名のデコードに失敗しました")
		http.Error(w, "Base64形式の署名のデコードに失敗しました", http.StatusBadRequest)
	}

	// 署名の検証
	isValid := cryptoPkg.VerifySignature(
		pubKey,
		[]byte(challenge+verifyReqData.DID),
		signature,
	)
	if !isValid {
		log.Println("無効な署名です")
		http.Error(w, "無効な署名です", http.StatusBadRequest)
	}

	// 有効な署名
	// 今回はVC発行をスキップする

	// status code 200
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func RequestHandle(w http.ResponseWriter, r *http.Request) {
	// リクエストボディの読み取り
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Println("リクエストボディの読み取りに失敗しました")
		http.Error(w, "リクエストボディの読み取りに失敗しました", http.StatusBadRequest)
	}

	// リクエストデータのパース
	var reqData struct {
		DID string `json:did`
	}
	err = json.Unmarshal(body, &reqData)
	if err != nil {
		log.Println("リクエストデータのパースに失敗しました")
		http.Error(w, "リクエストデータのパースに失敗しました", http.StatusBadRequest)
	}

	// レスポンスデータの構造体
	resData := struct {
		Challenge string `json:"challenge"`
	}{
		Challenge: challenge + reqData.DID,
	}

	// レスポンスデータのエンコード
	resBody, err := json.Marshal(resData)
	if err != nil {
		log.Println("レスポンスデータのエンコードに失敗しました")
		http.Error(w, "レスポンスデータのエンコードに失敗しました", http.StatusInternalServerError)
	}

	// レスポンス 200 OK
	w.WriteHeader(http.StatusOK)
	w.Write(resBody)
}

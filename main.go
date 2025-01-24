package main

import (
	"net/http"

	"github.com/YamatoKato/did-auth-process-demo/handler/batch"
	"github.com/YamatoKato/did-auth-process-demo/handler/hd"
	"github.com/YamatoKato/did-auth-process-demo/handler/repeater"
)

func main() {
	// エンドポイントの設定
	mux := http.NewServeMux()
	mux.HandleFunc("/request-did-repeater", repeater.RequestHandle)
	mux.HandleFunc("/verify-did-repeater", repeater.VerifyHandle)
	mux.HandleFunc("/request-did-batch", batch.RequestHandle)
	mux.HandleFunc("/verify-did-batch", batch.VerifyHandle)
	mux.HandleFunc("/request-did-hd", hd.RequestHandle)
	mux.HandleFunc("/verify-did-hd", hd.VerifyHandle)

	// サーバーの起動
	http.ListenAndServe(":8100", mux)
}

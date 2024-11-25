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
	mux.HandleFunc("/verify-did-hd", hd.Handle)
	mux.HandleFunc("/verify-did-repeater", repeater.Handle)
	mux.HandleFunc("/verify-did-batch", batch.Handle)

	// サーバーの起動
	http.ListenAndServe(":8100", mux)
}

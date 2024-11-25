package hd

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"errors"

	"github.com/btcsuite/btcd/btcec/v2"
)

type ExtendedKey struct {
	PrivateKey []byte // 圧縮された秘密鍵
	PublicKey  []byte // 圧縮された公開鍵
	ChainCode  []byte
	Depth      uint8
	ChildNum   uint32
	IsHardened bool
}

func NewExtendedKey(
	publicKey []byte,
	chainCode []byte,
	childNum uint32,
) *ExtendedKey {
	return &ExtendedKey{
		PrivateKey: nil,
		PublicKey:  publicKey,
		ChainCode:  chainCode,
		Depth:      0,
		ChildNum:   childNum,
		IsHardened: false,
	}
}

// 親公開鍵(M)から子公開鍵(M/0),chaincodeを生成
func (pek *ExtendedKey) DeriveChildKey() (*ExtendedKey, error) {
	// HMAC-SHA512で親の公開鍵とインデックスを使ってハッシュ化（強化されていない）
	// HMAC-SHA512(Key=chaincode, Data=parentPublicKey || childNum)
	hmacSha512 := hmac.New(sha512.New, pek.ChainCode)
	data := append(pek.PublicKey, uint32ToBytes(pek.ChildNum)...)
	hmacSha512.Write(data)
	I := hmacSha512.Sum(nil)
	il := I[:32] // 中間公開鍵
	childChainCode := I[32:]

	var ilNum btcec.ModNScalar // これはsecp256k1曲線のNより小さい整数,Nは有限群の位数
	if overflow := ilNum.SetByteSlice(I[:32]); overflow {
		return nil, errors.New("invalid child key: hash値Iが有限群の位数を超えています")
	}

	var (
		ilScalar btcec.ModNScalar    // il用のスカラー値
		ilJ      btcec.JacobianPoint // 中間公開鍵（il * G）を表すJacobian座標の点。
	)
	if overflow := ilScalar.SetByteSlice(il); overflow { // ilをスカラー値に変換
		return nil, errors.New("invalid child key: hash値ilが有限群の位数を超えています")
	}

	btcec.ScalarBaseMultNonConst(&ilScalar, &ilJ) // 中間公開鍵の計算（il*G）
	if (ilJ.X.IsZero() && ilJ.Y.IsZero()) || ilJ.Z.IsZero() {
		// x,y,z座標がゼロの場合は無効な公開鍵
		return nil, errors.New("invalid child key: 中間公開鍵が無効です")
	}

	// 親の公開鍵をパースし、楕円曲線上の点に変換
	pubKey, err := btcec.ParsePubKey(pek.PublicKey)
	if err != nil {
		return nil, err
	}
	// 親公開鍵をjacobian座標に変換
	var pubKeyJ btcec.JacobianPoint // 親公開鍵を表すJacobian座標の点
	pubKey.AsJacobian(&pubKeyJ)

	// 中間公開鍵と親公開鍵に加算
	var childKeyPubJ btcec.JacobianPoint             // 加算結果を格納するためのJacobian座標の点
	btcec.AddNonConst(&ilJ, &pubKeyJ, &childKeyPubJ) // 子公開鍵 = il*G + parentKey
	// 子公開鍵をアフィン座標に変換
	childKeyPubJ.ToAffine()
	childKeyPub := btcec.NewPublicKey(&childKeyPubJ.X, &childKeyPubJ.Y)

	childKey := childKeyPub.SerializeCompressed()

	return &ExtendedKey{
		PrivateKey: nil,
		PublicKey:  childKey,
		ChainCode:  childChainCode,
		Depth:      pek.Depth + 1,
		ChildNum:   pek.ChildNum,
		IsHardened: false,
	}, nil

}

// uint32をバイト配列に変換するヘルパー関数
func uint32ToBytes(i uint32) []byte {
	data := make([]byte, 4) // 32ビット
	binary.BigEndian.PutUint32(data, i)
	return data
}

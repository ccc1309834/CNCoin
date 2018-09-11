package cpk

import (
	"crypto/rand"
	"crypto/sm2"
	"math/big"
	"strconv"
)

const N int = 4

func Init() ([N][N]*sm2.PrivateKey, [N][N]*sm2.PublicKey) {
	SKM := [N][N]*sm2.PrivateKey{}
	PKM := [N][N]*sm2.PublicKey{}
	for i := range SKM {
		for j := range SKM[i] {
			SKM[i][j], _ = sm2.GenerateKey(sm2.P256_sm2(), rand.Reader)
			PKM[i][j] = SKM[i][j].Public().(*sm2.PublicKey)
		}
	}
	return SKM, PKM
}

func GeneratePrivateKey(digest []byte, SKM [N][N]*sm2.PrivateKey) *sm2.PrivateKey {
	d := big.NewInt(0)
	length := len(digest) / N
	for i := 0; i < N; i++ {
		m := new(big.Int).SetBytes(digest[i*length : (i+1)*length])
		m.Mod(m, big.NewInt(int64(N)))
		s, _ := strconv.Atoi(m.String())
		d.Add(d, SKM[s][i].D)
	}
	priv := new(sm2.PrivateKey)
	priv.PublicKey.Curve = sm2.P256_sm2()
	priv.D = d
	priv.PublicKey.X, priv.PublicKey.Y = sm2.P256_sm2().ScalarBaseMult(priv.D.Bytes())
	return priv
}

func GeneratePublicKey(digest []byte, PKM [N][N]*sm2.PublicKey) *sm2.PublicKey {
	x := big.NewInt(0)
	y := big.NewInt(0)
	length := len(digest) / N
	for i := 0; i < N; i++ {
		m := new(big.Int).SetBytes(digest[i*length : (i+1)*length])
		m.Mod(m, big.NewInt(int64(N)))
		s, _ := strconv.Atoi(m.String())
		x, y = sm2.P256_sm2().Add(x, y, PKM[s][i].X, PKM[s][i].Y)
	}
	pubk := new(sm2.PublicKey)
	pubk.Curve = sm2.P256_sm2()
	pubk.X = x
	pubk.Y = y
	return pubk
}

package proxysignature

import (
	"crypto/sm2"
	"fmt"
	"io"
	"math/big"
)

const N int = 4

func Generaterandk(rand io.Reader) (*big.Int, error) {
	k := big.NewInt(0)
	for {
		randK := make([]byte, sm2.P256_sm2().BitSize/8)
		_, err := io.ReadFull(rand, randK)
		if err != nil {
			return nil, err
		}
		k.SetBytes(randK)
		if k.Sign() != 0 && k.Cmp(sm2.P256_sm2().N) < 0 {
			break
		}
	}
	return k, nil
}

func GenerateAuth(rand io.Reader, xGb, yGb *big.Int, SKM [N][N]*sm2.PrivateKey) (*big.Int, *big.Int, *big.Int, *big.Int, [N][N]*big.Int) {
	ka := big.NewInt(0)
	xGa := big.NewInt(0)
	yGa := big.NewInt(0)
	xGab := big.NewInt(0)
	yGab := big.NewInt(0)
	sA := [N][N]*big.Int{}
	for {
	Loop:
		for {
			ka, _ = Generaterandk(rand)
			xGa, yGa = sm2.P256_sm2().ScalarBaseMult(ka.Bytes())
			xGab, yGab = sm2.P256_sm2().ScalarMult(xGb, yGb, ka.Bytes())
			if xGab.Sign() != 0 {
				break
			}
		}
		for i := range sA {
			for j := range sA[i] {
				temp := big.NewInt(0)
				temp.ModInverse(ka, sm2.P256_sm2().N)
				temp1 := big.NewInt(0)
				temp1.Mul(xGab, SKM[i][j].D)
				temp1.Mod(temp1, sm2.P256_sm2().N)
				sA[i][j] = big.NewInt(0)
				sA[i][j].Mul(temp, temp1)
				sA[i][j].Mod(sA[i][j], sm2.P256_sm2().N)
				if sA[i][j].Sign() == 0 {
					goto Loop
				}
			}
		}
		break
	}
	return xGa, yGa, xGab, yGab, sA
}

func VerifyAuth(kb *big.Int, xGa, yGa *big.Int, sA [N][N]*big.Int, PKM [N][N]*sm2.PublicKey) ([N][N]*sm2.PrivateKey, error) {
	SKMb := [N][N]*sm2.PrivateKey{}
	for i := range sA {
		for j := range sA[i] {
			xGab1, _ := sm2.P256_sm2().ScalarMult(xGa, yGa, kb.Bytes())
			r, _ := sm2.P256_sm2().ScalarMult(xGa, yGa, sA[i][j].Bytes())
			R, _ := sm2.P256_sm2().ScalarMult(PKM[i][j].X, PKM[i][j].Y, xGab1.Bytes())
			if R.Cmp(r) != 0 {
				return SKMb, fmt.Errorf("VerifyAuth fail!")
			} else {
				temp := big.NewInt(0)
				temp.ModInverse(kb, sm2.P256_sm2().N)
				d := big.NewInt(0)
				d.Mul(sA[i][j], temp)
				d.Mod(d, sm2.P256_sm2().N)
				SKMb[i][j] = new(sm2.PrivateKey)
				SKMb[i][j].PublicKey.Curve = sm2.P256_sm2()
				SKMb[i][j].D = d
				SKMb[i][j].PublicKey.X, SKMb[i][j].PublicKey.Y = sm2.P256_sm2().ScalarBaseMult(SKMb[i][j].D.Bytes())
			}
		}
	}
	return SKMb, nil
}

func ProxySign(rand io.Reader, priv *sm2.PrivateKey, hash []byte, xGab, yGab *big.Int) (*big.Int, *big.Int, error) {
	e := big.NewInt(0)
	e.SetBytes(hash)
	k := big.NewInt(0)
	r := big.NewInt(0)
	s := big.NewInt(0)
	rAddK := big.NewInt(0)
	for {
		for {
			for {
				randK := make([]byte, sm2.P256_sm2().BitSize/8)
				_, err := io.ReadFull(rand, randK)
				if err != nil {
					return nil, nil, err
				}
				k.SetBytes(randK)
				if k.Sign() != 0 && k.Cmp(sm2.P256_sm2().N) < 0 {
					break
				}
			}
			x3, _ := sm2.P256_sm2().ScalarMult(xGab, yGab, k.Bytes())
			r.Add(e, x3)
			r.Mod(r, sm2.P256_sm2().N)
			if r.Sign() != 0 {
				rAddK.Add(r, k)
				if rAddK.Sign() != 0 {
					break
				}
			}
		}
		//s = ((1 + dB)-1 * (k - r*dB))mod n
		tmp := big.NewInt(0)
		tmp.Add(priv.D, big.NewInt(1))
		tmp.ModInverse(tmp, sm2.P256_sm2().N)

		tmp1 := big.NewInt(0)
		tmp1.Mul(r, priv.D)
		tmp1.Sub(k, tmp1)
		tmp1.Mod(tmp1, sm2.P256_sm2().N)

		s.Mul(tmp, tmp1)
		s.Mod(s, sm2.P256_sm2().N)

		if s.Sign() != 0 {
			break
		}
	}
	retR := big.NewInt(0)
	retS := big.NewInt(0)

	// r and s must between 1 and N - 1
	if r.Sign() < 1 {
		retR.Add(sm2.P256_sm2().P, r)
	} else {
		retR.Set(r)
	}

	if s.Sign() < 1 {
		retS.Add(sm2.P256_sm2().P, s)
	} else {
		retS.Set(s)
	}
	return retR, retS, nil

}

func ProxyVerify(pub *sm2.PublicKey, hash []byte, xGab, yGab, r, s *big.Int) bool {
	if r.Sign() < 1 || s.Sign() < 1 || r.Cmp(sm2.P256_sm2().N) >= 0 || s.Cmp(sm2.P256_sm2().N) >= 0 {
		return false
	}

	t := big.NewInt(0)
	t.Add(r, s)
	t.Mod(t, sm2.P256_sm2().N)

	x1, y1 := sm2.P256_sm2().ScalarMult(xGab, yGab, s.Bytes())

	x2, y2 := sm2.P256_sm2().ScalarMult(pub.X, pub.Y, xGab.Bytes())
	x3, y3 := sm2.P256_sm2().ScalarMult(x2, y2, t.Bytes())
	x, _ := sm2.P256_sm2().Add(x1, y1, x3, y3)

	e := new(big.Int).SetBytes(hash)
	R := big.NewInt(0)
	R.Add(e, x)
	R.Mod(R, sm2.P256_sm2().N)

	return (0 == R.Cmp(r))
}

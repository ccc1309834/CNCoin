package recover

import (
	"crypto/sm2"
	"io"
	"math/big"
)

//same as sm2Sign, but return with v
func Sign(rand io.Reader, priv *sm2.PrivateKey, hash []byte) (*big.Int, *big.Int, *big.Int, error) {
	e := big.NewInt(0)
	e.SetBytes(hash)
	k := big.NewInt(0)
	//k, _ := new(big.Int).SetString("59276e27d506861a16680f3ad9c02dccef3cc1fa3cdbe4ce6d54b80deac1bc21", 16)
	r := big.NewInt(0)
	s := big.NewInt(0)
	v := big.NewInt(0)
	rAddK := big.NewInt(0)
	for {
		for {
			for {
				randK := make([]byte, sm2.P256_sm2().BitSize/8)
				_, err := io.ReadFull(rand, randK)
				if err != nil {
					return nil, nil, nil, err
				}
				k.SetBytes(randK)
				if k.Sign() != 0 && k.Cmp(sm2.P256_sm2().N) < 0 {
					break
				}
			}
			x1, y1 := sm2.P256_sm2().ScalarBaseMult(k.Bytes())
			v = new(big.Int).Mod(y1, big.NewInt(2))
			r.Add(e, x1)
			r.Mod(r, sm2.P256_sm2().N)
			if r.Sign() != 0 {
				rAddK.Add(r, k)
				if rAddK.Sign() != 0 {
					break
				}
			}
		}
		//s = ((1 + dA)-1 * (k - r*dA))mod n
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
	return retR, retS, v, nil
}

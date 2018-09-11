package recover

import (
	"crypto/elliptic"
	"crypto/sm2"
	"errors"
	"math/big"
)

func Recover(e []byte, r, s, v *big.Int, curve *elliptic.CurveParams) (*sm2.PublicKey, error) {
	n := curve.Params().N
	//x to point
	x, y, err := x_to_point(new(big.Int).SetBytes(e), r, v, curve)
	if err != nil {
		return nil, err
	}

	//(r+s)^-1
	r_add_s := new(big.Int).Add(r, s)
	r_add_s_inverse := new(big.Int).ModInverse(r_add_s, n)

	//s*G
	x1, y1 := curve.ScalarBaseMult(s.Bytes())

	//R-sG
	x2, y2 := curve.Add(x, y, x1, y1.Neg(y1))

	//(r+s)^-1*(R-sG)
	pubx, puby := curve.ScalarMult(x2, y2, r_add_s_inverse.Bytes())

	//recover pub
	pub := &sm2.PublicKey{
		Curve: curve,
		X:     pubx,
		Y:     puby,
	}

	//verify
	if sm2.Verify(pub, e[:], r, s) {
		return pub, nil
	}
	return nil, errors.New("recover fail, cannot found pubkey")
}

func x_to_point(e, r, v *big.Int, curve *elliptic.CurveParams) (*big.Int, *big.Int, error) {
	p := curve.Params().P
	b := curve.Params().B
	a, _ := new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16)
	n := curve.Params().N

	//Euler criterion，y^((p+1)/4)=1 mod p
	p_add_1 := new(big.Int).Add(p, big.NewInt(1))
	p_add_1_div_4 := p_add_1.Div(p_add_1, big.NewInt(4))

	//x = r-e mod n
	x := new(big.Int).Sub(r, e)
	x.Mod(x, n)

	//ax = a*x mod p
	ax := new(big.Int).Mul(a, x)
	ax.Mod(ax, p)

	//c=x^3+ax+b mod p
	c := new(big.Int).Exp(x, big.NewInt(3), p)
	c.Add(c, ax)
	c.Add(c, b)
	c.Mod(c, p)

	//R=(x,y)
	y := new(big.Int).Exp(c, p_add_1_div_4, p)

	if v.Cmp(big.NewInt(0)) == 0 && new(big.Int).Mod(y, big.NewInt(2)).Cmp(big.NewInt(1)) == 0 {
		y.Neg(y)
		y.Mod(y, p)
	} else if v.Cmp(big.NewInt(1)) == 0 && new(big.Int).Mod(y, big.NewInt(2)).Cmp(big.NewInt(0)) == 0 {
		y.Neg(y)
		y.Mod(y, p)
	}

	if !curve.IsOnCurve(x, y) {
		return nil, nil, errors.New("R(x,y) is not on Curve!")
	}

	//y^2==c，nR==O
	if new(big.Int).Exp(y, big.NewInt(2), p).Cmp(c) != 0 {
		return nil, nil, errors.New("recover fail, y^2!=c")
	}
	if a, b := curve.ScalarMult(x, y, n.Bytes()); a.Cmp(big.NewInt(0)) != 0 || b.Cmp(big.NewInt(0)) != 0 {
		return nil, nil, errors.New("recover fail, nR!=O")
	}
	return x, y, nil
}

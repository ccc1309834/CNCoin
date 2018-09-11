package member

import (
	"CNCoin/coin"
	"CNCoin/cpk"
	"CNCoin/proxysignature"
	"CNCoin/recover"
	"crypto/rand"
	"crypto/sm2"
	"crypto/sm3"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
)

type Commercialbank struct {
	Name        string
	Certificate *x509.Certificate
	CNCoin      []*coin.Coin
	ProxySKM    [N][N]*sm2.PrivateKey
	xGab        *big.Int
	yGab        *big.Int
}

func (c *Commercialbank) SpendSign(cncoin *coin.Coin) {
	//Use CPK to generate priv
	m, _ := json.Marshal(cncoin.Head)
	digest := sm3.Sum(m)
	priv := cpk.GeneratePrivateKey(digest[:], c.ProxySKM)

	//spendSig is a recoverable sign
	r, s, v, _ := recover.Sign(rand.Reader, priv, digest[:])
	spendSig, _ := asn1.Marshal(sm2RecoverSignature{r, s, v})
	cncoin.SpendSig = spendSig
}

func (c *Commercialbank) Transfer(cncoin *coin.Coin, usr *User) error {
	//recover pubk
	m, _ := json.Marshal(cncoin.Head)
	digest := sm3.Sum(m)
	sig := new(sm2RecoverSignature)
	_, err := asn1.Unmarshal(cncoin.SpendSig, sig)
	if err != nil {
		return errors.New("No SpendSig or Spendsign error")
	}
	_, err = recover.Recover(digest[:], sig.R, sig.S, sig.V, sm2.P256_sm2())
	if err != nil {
		return err
	}

	//set the owner
	cncoin.Head.Owner = c.Certificate.PublicKey.(*sm2.PublicKey)
	if !(c.PrintVerify(*cncoin) && cncoin.Head.Printer == c.Name && !cncoin.Isused) {
		return fmt.Errorf("Invalid Coin!")
	}
	//set owner nil
	cncoin.Head.Owner = nil
	cncoin.Isused = true

	//newcoin
	newcoin := c.PrintMoney(cncoin.Head.Value)
	newcoin.Head.Owner = usr.Certificate.PublicKey.(*sm2.PublicKey)
	newcoin.PrinterSig = c.PrintSign(cncoin.Head)
	newcoin.Head.Owner = nil
	usr.CNCoin = append(usr.CNCoin, newcoin)
	return nil
}

func (c *Commercialbank) PrintMoney(value float32) *coin.Coin {
	cnbank := NewCentralbank()
	head := coin.CoinHead{}
	head.Id = len(cnbank.TotalCNcoin)
	if head.Id > 0 {
		for _, value := range cnbank.CNCoin {
			if value.Head.Id == head.Id-1 {
				h := sm3.New()
				m, _ := json.Marshal(value.Head)
				h.Write(m)
				digest := h.Sum(nil)
				head.Prehash = digest
			}
		}
		for _, value1 := range cnbank.ComBank {
			for _, value2 := range value1.CNCoin {
				if value2.Head.Id == head.Id-1 {
					h := sm3.New()
					m, _ := json.Marshal(value2.Head)
					h.Write(m)
					digest := h.Sum(nil)
					head.Prehash = digest
				}
			}
		}
	}
	head.Value = value
	head.Owner = c.Certificate.PublicKey.(*sm2.PublicKey)
	head.Printer = c.Name
	sig := c.PrintSign(head)
	//set the owner nil
	head.Owner = nil

	cncoin := new(coin.Coin)
	cncoin.Head = head
	cncoin.PrinterSig = sig
	cncoin.Isused = false
	c.CNCoin = append(c.CNCoin, cncoin)
	cnbank.TotalCNcoin = append(cnbank.TotalCNcoin, cncoin)
	return cncoin
}

func (c *Commercialbank) PrintSign(head coin.CoinHead) []byte {
	m, _ := json.Marshal(head)
	h := sm3.New()
	h.Write(m)
	digest := h.Sum(nil)
	priv := cpk.GeneratePrivateKey(digest, c.ProxySKM)
	r, s, _ := proxysignature.ProxySign(rand.Reader, priv, digest, c.xGab, c.yGab)
	sig, _ := asn1.Marshal(sm2Signature{r, s})
	return sig
}

func (c *Commercialbank) PrintVerify(cncoin coin.Coin) bool {
	cnbank := NewCentralbank()
	m, _ := json.Marshal(cncoin.Head)
	h := sm3.New()
	h.Write(m)
	digest := h.Sum(nil)
	pubk := cpk.GeneratePublicKey(digest, cnbank.PKM)
	sm2sig := new(sm2Signature)
	_, err := asn1.Unmarshal(cncoin.PrinterSig, sm2sig)
	if err != nil {
		return false
	}
	return proxysignature.ProxyVerify(pubk, digest, c.xGab, c.yGab, sm2sig.R, sm2sig.S)
}

func (c *Commercialbank) VerifyAuth(kb *big.Int, xGa, yGa *big.Int, sA [N][N]*big.Int, PKM [N][N]*sm2.PublicKey) ([N][N]*sm2.PrivateKey, error) {
	ProxySKM := [N][N]*sm2.PrivateKey{}
	for i := range sA {
		for j := range sA[i] {
			xGab1, _ := sm2.P256_sm2().ScalarMult(xGa, yGa, kb.Bytes())
			r, _ := sm2.P256_sm2().ScalarMult(xGa, yGa, sA[i][j].Bytes())
			R, _ := sm2.P256_sm2().ScalarMult(PKM[i][j].X, PKM[i][j].Y, xGab1.Bytes())
			if R.Cmp(r) != 0 {
				return ProxySKM, fmt.Errorf("VerifyAuth fail!")
			} else {
				temp := big.NewInt(0)
				temp.ModInverse(kb, sm2.P256_sm2().N)
				d := big.NewInt(0)
				d.Mul(sA[i][j], temp)
				d.Mod(d, sm2.P256_sm2().N)
				ProxySKM[i][j] = new(sm2.PrivateKey)
				ProxySKM[i][j].PublicKey.Curve = sm2.P256_sm2()
				ProxySKM[i][j].D = d
				ProxySKM[i][j].PublicKey.X, ProxySKM[i][j].PublicKey.Y = sm2.P256_sm2().ScalarBaseMult(ProxySKM[i][j].D.Bytes())
			}
		}
	}
	return ProxySKM, nil
}

func (c *Commercialbank) Show() {
	fmt.Println(c.Name, "'s Coins:")
	for _, value := range c.CNCoin {
		fmt.Println("Coin", value.Head.Id, ":")
		fmt.Printf("Prehash:%x\n", value.Head.Prehash)
		fmt.Println("value:", value.Head.Value)
		fmt.Println("Owner:", value.Head.Owner)
		fmt.Println("Printer:", value.Head.Printer)
		fmt.Println("Isused:", value.Isused)
		fmt.Printf("PrinterSig:%x\n", value.PrinterSig)
		fmt.Printf("SpendSig:%x\n", value.SpendSig)
		fmt.Println("")
	}
}

func NewCommercialbank1(name string) *Commercialbank {
	cnbank := NewCentralbank()
	commercialbank := new(Commercialbank)
	commercialbank.Name = name
	enpem, _ := ioutil.ReadFile("/Users/luoyifan/go/src/CNCoin/msp/commercialbank/commercialbank1/commercialbank1_cert.pem")
	pemcert, _ := pem.Decode(enpem)
	cert, _ := x509.ParseCertificate(pemcert.Bytes)
	commercialbank.Certificate = cert
	commercialbank.CNCoin = []*coin.Coin{}
	kb, _ := proxysignature.Generaterandk(rand.Reader)
	xGb, yGb := sm2.P256_sm2().ScalarBaseMult(kb.Bytes())
	xGa, yGa, xGab, yGab, sA := cnbank.GenerateAuth(rand.Reader, xGb, yGb)
	commercialbank.xGab = xGab
	commercialbank.yGab = yGab
	commercialbank.ProxySKM, _ = commercialbank.VerifyAuth(kb, xGa, yGa, sA, cnbank.PKM)
	cnbank.ComBank = append(cnbank.ComBank, commercialbank)
	return commercialbank
}

func NewCommercialbank2(name string) *Commercialbank {
	cnbank := NewCentralbank()
	commercialbank := new(Commercialbank)
	commercialbank.Name = name
	enpem, _ := ioutil.ReadFile("/Users/luoyifan/go/src/CNCoin/msp/commercialbank/commercialbank2/commercialbank2_cert.pem")
	pemcert, _ := pem.Decode(enpem)
	cert, _ := x509.ParseCertificate(pemcert.Bytes)
	commercialbank.Certificate = cert
	commercialbank.CNCoin = []*coin.Coin{}
	kb, _ := proxysignature.Generaterandk(rand.Reader)
	xGb, yGb := sm2.P256_sm2().ScalarBaseMult(kb.Bytes())
	xGa, yGa, xGab, yGab, sA := cnbank.GenerateAuth(rand.Reader, xGb, yGb)
	commercialbank.xGab = xGab
	commercialbank.yGab = yGab
	commercialbank.ProxySKM, _ = commercialbank.VerifyAuth(kb, xGa, yGa, sA, cnbank.PKM)
	cnbank.ComBank = append(cnbank.ComBank, commercialbank)
	return commercialbank
}

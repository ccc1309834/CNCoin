package member

import (
	"CNCoin/coin"
	"CNCoin/cpk"
	"CNCoin/proxysignature"
	"CNCoin/recover"
	"CNCoin/transactions"
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

func (c *Commercialbank) PrintMoney(value float32) *coin.Coin {
	cnbank := NewCentralbank()
	head := new(coin.CoinHead)
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

	//add tx to Transactions
	tx := new(transactions.Transaction)
	tx.Inputs = append(tx.Inputs, nil)
	tx.Outputs = append(tx.Outputs, cncoin)
	transactions.Transactions = append(transactions.Transactions, tx)
	return cncoin
}

func (c *Commercialbank) PrintToUser(value float32, usr *User) *coin.Coin {
	cnbank := NewCentralbank()
	head := new(coin.CoinHead)
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
	head.Owner = usr.Certificate.PublicKey.(*sm2.PublicKey)
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
	usr.CNCoin = append(usr.CNCoin, cncoin)
	return cncoin
}

func (c *Commercialbank) PrintSign(head *coin.CoinHead) []byte {
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

func (c *Commercialbank) SpendSign(cncoin *coin.Coin) []byte {
	//Use CPK to generate priv
	m, _ := json.Marshal(cncoin.Head)
	digest := sm3.Sum(m)
	priv := cpk.GeneratePrivateKey(digest[:], c.ProxySKM)

	//spendSig is a recoverable sign
	r, s, v, _ := recover.Sign(rand.Reader, priv, digest[:])
	spendSig, _ := asn1.Marshal(sm2RecoverSignature{r, s, v})
	return spendSig
}

func (c *Commercialbank) Transfer(cncoin *coin.Coin, usr *User, spendSig []byte) error {
	//recover pubk
	m, _ := json.Marshal(cncoin.Head)
	digest := sm3.Sum(m)
	sig := new(sm2RecoverSignature)
	_, err := asn1.Unmarshal(spendSig, sig)
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
		cncoin.Head.Owner = nil
		return fmt.Errorf("Invalid Coin!")
	}
	//set owner nil
	cncoin.SpendSig = spendSig
	cncoin.Head.Owner = c.Certificate.PublicKey.(*sm2.PublicKey)
	cncoin.Isused = true

	//print newcoin
	newcoin := c.PrintToUser(cncoin.Head.Value, usr)

	//add tx to Transactions
	tx := new(transactions.Transaction)
	tx.Inputs = append(tx.Inputs, cncoin)
	tx.Outputs = append(tx.Outputs, newcoin)
	transactions.Transactions = append(transactions.Transactions, tx)
	return nil
}

func (c *Commercialbank) VerifyAuth(kb *big.Int, xGa, yGa *big.Int, sA [N][N]*big.Int, PKM [N][N]*sm2.PublicKey) ([N][N]*sm2.PrivateKey, error) {
	return proxysignature.VerifyAuth(kb, xGa, yGa, sA, PKM)
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

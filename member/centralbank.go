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
	"io"
	"io/ioutil"
	"math/big"
	"sync"
)

//矩阵规模
const N int = 4

var centralbank *Centralbank
var once sync.Once

type Centralbank struct {
	Name        string
	Certificate *x509.Certificate
	CNCoin      []*coin.Coin
	SKM         [N][N]*sm2.PrivateKey
	PKM         [N][N]*sm2.PublicKey
	ComBank     []*Commercialbank
	TotalCNcoin []*coin.Coin
}

type sm2Signature struct {
	R, S *big.Int
}

type sm2RecoverSignature struct {
	R, S, V *big.Int
}

func (c *Centralbank) GetComBank(name string) *Commercialbank {
	combank := new(Commercialbank)
	for _, value := range c.ComBank {
		if value.Name == name {
			combank = value
			break
		}
	}
	return combank
}

func (c *Centralbank) PrintMoney(value float32) *coin.Coin {
	head := new(coin.CoinHead)
	head.Id = len(c.TotalCNcoin)

	if head.Id > 0 {
		for _, value := range c.CNCoin {
			if value.Head.Id == head.Id-1 {
				m, _ := json.Marshal(value.Head)
				digest := sm3.Sum(m)
				head.Prehash = digest[:]
			}
		}
		for i := range c.ComBank {
			for _, value := range c.ComBank[i].CNCoin {
				if value.Head.Id == head.Id-1 {
					m, _ := json.Marshal(value.Head)
					digest := sm3.Sum(m)
					head.Prehash = digest[:]
				}
			}
		}
	}

	//PrinterSig to ensure the validity of the coin
	head.Value = value
	head.Owner = c.Certificate.PublicKey.(*sm2.PublicKey)
	head.Printer = "Centralbank"
	printSig := c.PrintSign(head)

	//remove owner to ensure anonymity
	head.Owner = nil

	cncoin := new(coin.Coin)
	cncoin.Head = head
	cncoin.PrinterSig = printSig
	cncoin.Isused = false
	c.CNCoin = append(c.CNCoin, cncoin)
	c.TotalCNcoin = append(c.TotalCNcoin, cncoin)

	//add tx to Transactions
	tx := new(transactions.Transaction)
	tx.Inputs = append(tx.Inputs, nil)
	tx.Outputs = append(tx.Outputs, cncoin)
	transactions.Transactions = append(transactions.Transactions, tx)

	return cncoin
}

func (c *Centralbank) PrintToUser(value float32, usr *User) *coin.Coin {
	head := new(coin.CoinHead)
	head.Id = len(c.TotalCNcoin)

	if head.Id > 0 {
		for _, value := range c.CNCoin {
			if value.Head.Id == head.Id-1 {
				m, _ := json.Marshal(value.Head)
				digest := sm3.Sum(m)
				head.Prehash = digest[:]
			}
		}
		for i := range c.ComBank {
			for _, value := range c.ComBank[i].CNCoin {
				if value.Head.Id == head.Id-1 {
					m, _ := json.Marshal(value.Head)
					digest := sm3.Sum(m)
					head.Prehash = digest[:]
				}
			}
		}
	}

	//PrinterSig to ensure the validity of the coin
	head.Value = value
	head.Owner = usr.Certificate.PublicKey.(*sm2.PublicKey)
	head.Printer = "Centralbank"
	printSig := c.PrintSign(head)

	//remove owner to ensure anonymity
	head.Owner = nil

	cncoin := new(coin.Coin)
	cncoin.Head = head
	cncoin.PrinterSig = printSig
	cncoin.Isused = false
	c.CNCoin = append(c.CNCoin, cncoin)
	c.TotalCNcoin = append(c.TotalCNcoin, cncoin)
	usr.CNCoin = append(usr.CNCoin, cncoin)

	return cncoin
}

func (c *Centralbank) PrintSign(head *coin.CoinHead) []byte {
	m, _ := json.Marshal(head)
	h := sm3.New()
	h.Write(m)
	digest := h.Sum(nil)
	priv := cpk.GeneratePrivateKey(digest, c.SKM)
	r, s, _ := sm2.Sign(rand.Reader, priv, digest)
	sig, _ := asn1.Marshal(sm2Signature{r, s})
	return sig
}

func (c *Centralbank) PrintVerify(cncoin coin.Coin) bool {
	m, _ := json.Marshal(cncoin.Head)
	h := sm3.New()
	h.Write(m)
	digest := h.Sum(nil)
	pubk := cpk.GeneratePublicKey(digest, c.PKM)
	sm2sig := new(sm2Signature)
	_, err := asn1.Unmarshal(cncoin.PrinterSig, sm2sig)
	if err != nil {
		return false
	}
	return sm2.Verify(pubk, digest, sm2sig.R, sm2sig.S)
}

//before Tranfer,should generate a spendSign
func (c *Centralbank) SpendSign(cncoin *coin.Coin) []byte {
	//Use CPK to generate priv
	m, _ := json.Marshal(cncoin.Head)
	digest := sm3.Sum(m)
	priv := cpk.GeneratePrivateKey(digest[:], c.SKM)

	//spendSig is a recoverable sign
	r, s, v, _ := recover.Sign(rand.Reader, priv, digest[:])
	spendSig, _ := asn1.Marshal(sm2RecoverSignature{r, s, v})
	return spendSig
}

func (c *Centralbank) Transfer(cncoin *coin.Coin, usr *User, spendSig []byte) error {
	//spendSig
	m, _ := json.Marshal(cncoin.Head)
	digest := sm3.Sum(m)
	sig := new(sm2RecoverSignature)
	_, err := asn1.Unmarshal(spendSig, sig)
	if err != nil {
		return errors.New("No SpendSig or SpendSig error")
	}
	_, err = recover.Recover(digest[:], sig.R, sig.S, sig.V, sm2.P256_sm2())
	if err != nil {
		return err
	}
	//set the owner,verify printSig
	cncoin.Head.Owner = c.Certificate.PublicKey.(*sm2.PublicKey)
	if !(c.PrintVerify(*cncoin) && cncoin.Head.Printer == "Centralbank" && !cncoin.Isused) {
		cncoin.Head.Owner = nil
		return fmt.Errorf("Invalid Coin!")
	}
	cncoin.SpendSig = spendSig
	cncoin.Isused = true
	cncoin.Head.Owner = c.Certificate.PublicKey.(*sm2.PublicKey)

	//print newcoin to usr
	newcoin := c.PrintToUser(cncoin.Head.Value, usr)

	//add tx to Transactions
	tx := new(transactions.Transaction)
	tx.Inputs = append(tx.Inputs, cncoin)
	tx.Outputs = append(tx.Outputs, newcoin)
	transactions.Transactions = append(transactions.Transactions, tx)
	return nil
}

func (c *Centralbank) GenerateAuth(rand io.Reader, xGb, yGb *big.Int) (*big.Int, *big.Int, *big.Int, *big.Int, [N][N]*big.Int) {
	return proxysignature.GenerateAuth(rand, xGb, yGb, c.SKM)
}

func (c *Centralbank) Show() {
	fmt.Println("Centralbank's Coins:")
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

func (c *Centralbank) ShowTotalCoins() {
	fmt.Println("TotalCoins:")
	for _, value := range c.TotalCNcoin {
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

func NewCentralbank() *Centralbank {
	once.Do(
		func() {
			centralbank = new(Centralbank)
			centralbank.Name = "CNBank"
			enpem, _ := ioutil.ReadFile("/Users/luoyifan/go/src/CNCoin/msp/centralbank/centralbank_cert.pem")
			pemcert, _ := pem.Decode(enpem)
			cert, _ := x509.ParseCertificate(pemcert.Bytes)
			centralbank.Certificate = cert
			centralbank.CNCoin = []*coin.Coin{}
			centralbank.ComBank = []*Commercialbank{}
			centralbank.SKM, centralbank.PKM = cpk.Init()
			centralbank.TotalCNcoin = []*coin.Coin{}
		})
	return centralbank
}

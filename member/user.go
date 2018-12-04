package member

import (
	"CNCoin/coin"
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
)

type User struct {
	Name        string
	Certificate *x509.Certificate
	Priv        *sm2.PrivateKey
	CNCoin      []*coin.Coin
}

func (u *User) SpendSign(cncoin *coin.Coin) []byte {
	m, _ := json.Marshal(cncoin.Head)
	digest := sm3.Sum(m)
	r, s, v, _ := recover.Sign(rand.Reader, u.Priv, digest[:])
	spendSig, _ := asn1.Marshal(sm2RecoverSignature{r, s, v})
	return spendSig
}

func (u *User) SpendCoin(cncoin *coin.Coin, spendSig []byte, value float32, usr *User) error {
	cnbank := NewCentralbank()
	//recover pubk
	m, _ := json.Marshal(cncoin.Head)
	digest := sm3.Sum(m)
	sig := new(sm2RecoverSignature)
	_, err := asn1.Unmarshal(spendSig, sig)
	if err != nil {
		return errors.New("No SpendSig or SpendSign error")
	}
	pubk, err := recover.Recover(digest[:], sig.R, sig.S, sig.V, sm2.P256_sm2())
	if err != nil {
		return err
	}
	//set the owner
	cncoin.Head.Owner = pubk
	if cncoin.Head.Printer == "Centralbank" {
		if !(cncoin.Isused == false && cnbank.PrintVerify(*cncoin)) {
			cncoin.Head.Owner = nil
			return fmt.Errorf("Invalid Coin!")
		}
		if cncoin.Head.Value < value {
			cncoin.Head.Owner = nil
			return fmt.Errorf("No Enough Value!")
		}
		cncoin.SpendSig = spendSig
		cncoin.Isused = true
		cncoin.Head.Owner = u.Certificate.PublicKey.(*sm2.PublicKey)
		//newcoin
		newcoin := cnbank.PrintToUser(value, usr)

		//add tx to Transactions
		tx := new(transactions.Transaction)
		tx.Inputs = append(tx.Inputs, cncoin)
		tx.Outputs = append(tx.Outputs, newcoin)
		if cncoin.Head.Value > value {
			//changecoin
			changecoin := cnbank.PrintToUser(cncoin.Head.Value-value, usr)
			tx.Outputs = append(tx.Outputs, changecoin)
		}
		transactions.Transactions = append(transactions.Transactions, tx)
	} else {
		commercialbank := cnbank.GetComBank(cncoin.Head.Printer)
		if !(cncoin.Isused == false && commercialbank.PrintVerify(*cncoin)) {
			cncoin.Head.Owner = nil
			return fmt.Errorf("Invalid Coin!")
		}
		if cncoin.Head.Value < value {
			cncoin.Head.Owner = nil
			return fmt.Errorf("No Enough Value!")
		}
		cncoin.SpendSig = spendSig
		cncoin.Isused = true
		cncoin.Head.Owner = u.Certificate.PublicKey.(*sm2.PublicKey)
		//newcoin
		newcoin := commercialbank.PrintToUser(value, usr)

		//add tx to Transactions
		tx := new(transactions.Transaction)
		tx.Inputs = append(tx.Inputs, cncoin)
		tx.Outputs = append(tx.Outputs, newcoin)
		if cncoin.Head.Value > value {
			//changecoin
			changecoin := commercialbank.PrintToUser(cncoin.Head.Value-value, usr)
			tx.Outputs = append(tx.Outputs, changecoin)
		}
		transactions.Transactions = append(transactions.Transactions, tx)
	}

	return nil
}

func (u *User) Show() {
	fmt.Println(u.Name, "'s Coins:")
	for _, value := range u.CNCoin {
		fmt.Println("Coin", value.Head.Id, ":")
		fmt.Printf("Prehash:%x\n", value.Head.Prehash)
		fmt.Println("value:", value.Head.Value)
		fmt.Println("Owner:", value.Head.Owner)
		fmt.Println("Printer:", value.Head.Printer)
		fmt.Println("isused:", value.Isused)
		fmt.Printf("PrinterSig:%x\n", value.PrinterSig)
		fmt.Printf("SpendSig:%x\n", value.SpendSig)
		fmt.Println("")
	}
}

func NewUser1(name string) *User {
	usr := new(User)
	usr.Name = name
	enpem, _ := ioutil.ReadFile("/Users/luoyifan/go/src/CNCoin/msp/user/user1/user1_cert.pem")
	pemcert, _ := pem.Decode(enpem)
	cert, _ := x509.ParseCertificate(pemcert.Bytes)
	usr.Certificate = cert
	raw, _ := ioutil.ReadFile("/Users/luoyifan/go/src/CNCoin/msp/user/user1/user1_sk")
	block, _ := pem.Decode(raw)
	priv, _ := x509.ParsePKCS8PrivateKey(block.Bytes)
	usr.Priv = priv.(*sm2.PrivateKey)
	usr.CNCoin = []*coin.Coin{}
	return usr
}

func NewUser2(name string) *User {
	usr := new(User)
	usr.Name = name
	enpem, _ := ioutil.ReadFile("/Users/luoyifan/go/src/CNCoin/msp/user/user2/user2_cert.pem")
	pemcert, _ := pem.Decode(enpem)
	cert, _ := x509.ParseCertificate(pemcert.Bytes)
	usr.Certificate = cert
	raw, _ := ioutil.ReadFile("/Users/luoyifan/go/src/CNCoin/msp/user/user2/user2_sk")
	block, _ := pem.Decode(raw)
	priv, _ := x509.ParsePKCS8PrivateKey(block.Bytes)
	usr.Priv = priv.(*sm2.PrivateKey)
	usr.CNCoin = []*coin.Coin{}
	return usr
}

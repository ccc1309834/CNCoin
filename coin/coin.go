package coin

import (
	"crypto/sm2"
)

//coin's head
type CoinHead struct {
	Prehash []byte         //pre-coin's hash
	Id      int            //coin's id
	Value   float32        //amount of the coin
	Owner   *sm2.PublicKey //when printed,this should be nil
	Printer string         //coin's printer
}

type Coin struct {
	Head       CoinHead //coin's head
	Isused     bool     //whether the coin is used
	PrinterSig []byte   //standard sig，ensure the validity of the coin
	SpendSig   []byte   //recoverable sig, represent the spending purpose of the coin's user
}

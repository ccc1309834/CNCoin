package main

import (
	"CNCoin/member"
	"fmt"
)

func main() {
	//创建中央银行
	cnbank := member.NewCentralbank()

	//创建商业银行
	boc := member.NewCommercialbank1("BoC")
	icbc := member.NewCommercialbank2("ICBC")

	//中央银行造币
	coin0 := cnbank.PrintMoney(0.01)

	//商业银行造币
	coin1 := boc.PrintMoney(1)
	coin2 := icbc.PrintMoney(0.2)

	//创建用户
	user1 := member.NewUser1("u1")
	user2 := member.NewUser2("u2")

	//中央银行给用户发币
	cnbank.SpendSign(coin0)
	err1 := cnbank.Transfer(coin0, user1)
	if err1 != nil {
		fmt.Println("cnbank transfer coin0 to user2 err:", err1)
	}

	//商业银行给用户发币
	boc.SpendSign(coin1)
	err2 := boc.Transfer(coin1, user2)
	if err2 != nil {
		fmt.Println("boc transfer coin1 to user2", err2)
	}

	icbc.SpendSign(coin2)
	err3 := icbc.Transfer(coin2, user1)
	if err3 != nil {
		fmt.Println("icbc transfer coin2 to user2", err3)
	}

	//用户指定使用某个币消费
	user1.SpendSign(user1.CNCoin[0])
	err4 := user1.SpendCoin(user1.CNCoin[0], 0.005, user2)
	if err4 != nil {
		fmt.Println("user1 spend coin[0] to user2", err4)
	}

	//show
	//cnbank.Show()
	//boc.Show()
	//icbc.Show()
	//user2.Show()
	//user2.Show()
	cnbank.ShowTotalCoins()
}

package main

import (
	"CNCoin/member"
	"fmt"
)

func main() {
	//创建中央银行
	cnbank := member.NewCentralbank()

	//创建商业银行
	cb1 := member.NewCommercialbank1("cb1")
	cb2 := member.NewCommercialbank2("cb2")

	//创建用户
	user1 := member.NewUser1("u1")
	user2 := member.NewUser2("u2")

	//中央银行造币
	coin0 := cnbank.PrintMoney(0.01)
	fmt.Println("central bank print coin0,value:0.01")

	//商业银行造币
	coin1 := cb1.PrintMoney(1)
	fmt.Println("commercialbank cb1 print coin1,value:1")
	coin2 := cb2.PrintMoney(0.2)
	fmt.Println("commercialbank cb2 print coin2,value:0.2")

	//中央银行给用户发币
	err1 := cnbank.Transfer(coin0, user1, cnbank.SpendSign(coin0))
	if err1 != nil {
		fmt.Println("cnbank transfer coin1 to user2 err:", err1)
	} else {
		fmt.Println("cnbank transfer coin1 to user2")
	}

	//商业银行给用户发币
	err2 := cb1.Transfer(coin1, user2, cb1.SpendSign(coin1))
	if err2 != nil {
		fmt.Println("cb1 transfer coin0 to user2", err2)
	} else {
		fmt.Println("cb1 transfer coin0 to user2")
	}

	err3 := cb2.Transfer(coin2, user1, cb2.SpendSign(coin2))
	if err3 != nil {
		fmt.Println("cb2 transfer coin2 to user1", err3)
	} else {
		fmt.Println("cb2 transfer coin2 to user1")
	}

	//用户指定使用某个币消费
	err4 := user1.SpendCoin(user1.CNCoin[1], user1.SpendSign(user1.CNCoin[1]), 0.005, user2)
	if err4 != nil {
		fmt.Println("user1 spend coin[1] to user2", err4)
	} else {
		fmt.Println("user1 send 0.005 to user2");
	}

	//show
	//cnbank.Show()
	//cb1.Show()
	//cb2.Show()
	//user2.Show()
	//user2.Show()
	cnbank.ShowTotalCoins()

}

package main

import (
	"CNCoin/member"
	"CNCoin/transactions"
	"fmt"
)

func main() {
	//创建中央银行
	cnbank := member.NewCentralbank()

	//创建商业银行
	cb := member.NewCommercialbank1("cb")

	//创建用户
	user1 := member.NewUser1("u1")
	user2 := member.NewUser2("u2")

	//中央银行造币
	fmt.Println("====================Init====================")

	coin0 := cnbank.PrintMoney(100)
	fmt.Println("central bank print coin0,value:100;")

	//商业银行造币
	coin1 := cb.PrintMoney(50)
	fmt.Println("commercialbank cb print coin1,value:50;")

	//中央银行给用户发币
	err1 := cnbank.Transfer(coin0, user1, cnbank.SpendSign(coin0))
	if err1 != nil {
		fmt.Println("cnbank transfer coin0 to user2 err:", err1)
	} else {
		fmt.Println("cnbank transfer coin0 to user2;")
	}

	//商业银行给用户发币
	err2 := cb.Transfer(coin1, user2, cb.SpendSign(coin1))
	if err2 != nil {
		fmt.Println("cb transfer coin", coin1.Head.Id, " to user2 err", err2)
	} else {
		fmt.Println("cb transfer coin", coin1.Head.Id, " to user2;")
	}

	//用户指定使用某个币消费
	err4 := user1.SpendCoin(user1.CNCoin[0], user1.SpendSign(user1.CNCoin[0]), 30, user2)
	if err4 != nil {
		fmt.Println("user1 spend coin[0] to user2 err", err4)
	} else {
		fmt.Println("user1 send 30 to user2;");
	}

	//show
	//cnbank.Show()
	//cb1.Show()
	//cb2.Show()
	//user2.Show()
	//user2.Show()
	fmt.Println()
	fmt.Println("====================Current Total Coins====================")
	cnbank.ShowTotalCoins()
	transactions.ShowAllTransactions()

	//fmt.Println("---------------CNCoin System--------------")
	//fmt.Println("1.Create Central Bank")
	//fmt.Println("2.Create Commercial Bank")
	//fmt.Println("3.Print Coin")

}

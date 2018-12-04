package transactions

import (
	"CNCoin/coin"
	"fmt"
)

type Transaction struct {
	Inputs  []*coin.Coin
	Outputs []*coin.Coin
}

var Transactions []*Transaction

func ShowAllTransactions() {
	for i := 0; i < len(Transactions); i++ {
		fmt.Print("transaction", i, ":","\n")
		fmt.Println("inputs:")
		for _, input := range Transactions[i].Inputs {
			if input == nil {
				fmt.Print(input)
			} else {
				fmt.Print("coin", input.Head.Id, " ")
			}

		}
		fmt.Println()
		fmt.Println("outputs:")
		for _, output := range Transactions[i].Outputs {
			fmt.Print("coin", output.Head.Id, " ")
		}
		fmt.Println()
	}
}

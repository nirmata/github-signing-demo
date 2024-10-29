package main

import (
	"fmt"
	"time"
)

func main() {
	fmt.Println("Hello World, this is a Nirmata demo app!")
	for {
		time.Sleep(10 * time.Second)
		fmt.Print(".")
	}
}

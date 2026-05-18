package main

import "fmt"

func helper(x int) int {
    return x + 1
}

func main() {
    if helper(3) > 0 {
        fmt.Println("ok")
        return
    }
    fmt.Println("nope")
}

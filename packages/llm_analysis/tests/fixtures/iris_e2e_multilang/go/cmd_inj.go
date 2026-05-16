package main

import (
	"os"
	"os/exec"
)

func main() {
	target := os.Args[1]
	exec.Command("sh", "-c", "ping -c1 "+target).Run()
}

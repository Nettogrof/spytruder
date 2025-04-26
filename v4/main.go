package main

import (
	"fmt"
	"os"

	"github.com/ALW1EZ/spytruder/v4/pkg/cli"
)

func main() {
	opts := cli.ParseOptions()
	if err := cli.Run(opts); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

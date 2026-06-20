package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/consensys/gnark/logger"
)

func main() {
	if len(os.Args) < 2 {
		fatalf("expected subcommand: setup or prove")
	}

	switch os.Args[1] {
	case "setup":
		runSetup(os.Args[2:])
	case "prove":
		runProve(os.Args[2:])
	default:
		fatalf("unknown subcommand %q", os.Args[1])
	}
}

func init() {
	logger.Disable()
}

func runSetup(args []string) {
	flags := flag.NewFlagSet("setup", flag.ExitOnError)
	buildDir := flags.String("build-dir", "", "artifact output directory")
	leafCount := flags.Int("leaf-count", -1, "number of enabled leaves in the circuit")
	flags.Parse(args)

	if *buildDir == "" {
		fatalf("setup requires --build-dir")
	}
	if *leafCount < 0 {
		fatalf("setup requires --leaf-count")
	}

	layout, err := ensureArtifacts(*buildDir, *leafCount)
	if err != nil {
		fatalf("%v", err)
	}

	writeJSON(layout)
}

func runProve(args []string) {
	flags := flag.NewFlagSet("prove", flag.ExitOnError)
	buildDir := flags.String("build-dir", "", "artifact directory")
	inputPath := flags.String("input", "", "json witness input path")
	flags.Parse(args)

	if *buildDir == "" {
		fatalf("prove requires --build-dir")
	}
	if *inputPath == "" {
		fatalf("prove requires --input")
	}

	output, err := proveOperation(*buildDir, *inputPath)
	if err != nil {
		fatalf("%v", err)
	}

	writeJSON(output)
}

func writeJSON(value any) {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		fatalf("encode json: %v", err)
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

// Command wafctl manages the nginx AWS-WAF simulator.
package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
)

var commands = map[string]func([]string) int{
	"version":  cmdVersion,
	"catalog":  cmdCatalog,
	"validate": cmdValidate,
	"render":   cmdRender,
}

func usage() {
	names := make([]string, 0, len(commands))
	for n := range commands {
		names = append(names, n)
	}
	sort.Strings(names)
	fmt.Fprintf(os.Stderr, "usage: wafctl <command> [args]\ncommands: %s\n", strings.Join(names, ", "))
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	fn, ok := commands[os.Args[1]]
	if !ok {
		fmt.Fprintf(os.Stderr, "wafctl: unknown command %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	os.Exit(fn(os.Args[2:]))
}

func fail(format string, a ...any) int {
	fmt.Fprintf(os.Stderr, "wafctl: "+format+"\n", a...)
	return 1
}

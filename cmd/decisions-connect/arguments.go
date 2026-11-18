package main

import (
	"fmt"
	"io"
)

const usage = `Usage: decisions-connect [--help]

Run without arguments on Windows to set up an OpenAI Decisions connection.
The setup reads OPENAI_API_KEY from the process environment, or prompts for
hidden console input when no usable process credential is available.
It encrypts the key for the current Windows user, saves a shadow configuration,
and runs decisions-check.exe for a live API smoke check.

  -h, --help  Show this help and exit without reading credentials, writing files,
              or running the live check.

No other arguments are supported. Never pass an API key on the command line.
`

// Validate every argument before the platform-specific setup can read a key,
// write configuration, or launch the live check. Do not echo unknown arguments:
// a user may have mistakenly supplied a credential on the command line.
func runCLI(args []string, stdout, stderr io.Writer, setup func() int) int {
	if len(args) == 0 {
		return setup()
	}
	if len(args) == 1 && (args[0] == "-h" || args[0] == "--help") {
		fmt.Fprint(stdout, usage)
		return 0
	}
	fmt.Fprintln(stderr, "Unsupported arguments. Run decisions-connect --help for usage. Do not pass an API key on the command line.")
	return 2
}

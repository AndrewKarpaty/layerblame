// Command layerblame maps container image vulnerabilities back to the
// Dockerfile instructions that introduced them, and suggests Dockerfile
// improvements.
package main

import (
	"os"

	"github.com/AndrewKarpaty/layerblame/cmd"
)

func main() {
	os.Exit(cmd.Execute())
}

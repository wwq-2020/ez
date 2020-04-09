package cmd

import "github.com/spf13/cobra"

var root = &cobra.Command{}

// Execute Execute
func Execute() {
	root.Execute()
}

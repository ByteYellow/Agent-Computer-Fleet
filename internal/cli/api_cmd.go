package cli

import (
	"fmt"
	"github.com/byteyellow/agent-computer-fleet/internal/computerapi"
	"github.com/byteyellow/agent-computer-fleet/internal/store"
	"github.com/spf13/cobra"
)

func apiCmd(dataDir *string) *cobra.Command {
	var toolCallID string
	fileReadPath := ""
	fileRead := &cobra.Command{
		Use:   "read-file <session_id>",
		Short: "read a file from the sandbox workspace",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			paths, err := store.Init(*dataDir)
			if err != nil {
				return err
			}
			db, err := store.Open(paths)
			if err != nil {
				return err
			}
			defer db.Close()
			body, decision, err := (computerapi.Service{DB: db, Paths: paths}).ReadFile(args[0], fileReadPath, toolCallID)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "decision=%s reason=%s\n%s\n", decision.Decision, decision.Reason, body)
			return nil
		},
	}
	fileRead.Flags().StringVar(&fileReadPath, "path", "", "workspace-relative path")
	fileRead.Flags().StringVar(&toolCallID, "tool-call-id", "", "tool call id")
	_ = fileRead.MarkFlagRequired("path")

	fileWritePath := ""
	fileWriteContent := ""
	fileWrite := &cobra.Command{
		Use:   "write-file <session_id>",
		Short: "write a file into the sandbox workspace",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			paths, err := store.Init(*dataDir)
			if err != nil {
				return err
			}
			db, err := store.Open(paths)
			if err != nil {
				return err
			}
			defer db.Close()
			decision, err := (computerapi.Service{DB: db, Paths: paths}).WriteFile(args[0], fileWritePath, fileWriteContent, toolCallID)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "decision=%s reason=%s\n", decision.Decision, decision.Reason)
			return nil
		},
	}
	fileWrite.Flags().StringVar(&fileWritePath, "path", "", "workspace-relative path")
	fileWrite.Flags().StringVar(&fileWriteContent, "content", "", "file content")
	fileWrite.Flags().StringVar(&toolCallID, "tool-call-id", "", "tool call id")
	_ = fileWrite.MarkFlagRequired("path")
	_ = fileWrite.MarkFlagRequired("content")

	searchPattern := ""
	search := &cobra.Command{
		Use:   "search <session_id>",
		Short: "search inside the sandbox workspace",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			paths, err := store.Init(*dataDir)
			if err != nil {
				return err
			}
			db, err := store.Open(paths)
			if err != nil {
				return err
			}
			defer db.Close()
			matches, decision, err := (computerapi.Service{DB: db, Paths: paths}).Search(args[0], searchPattern, toolCallID)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "decision=%s reason=%s\n", decision.Decision, decision.Reason)
			for _, match := range matches {
				fmt.Fprintf(cmd.OutOrStdout(), "%s:%d:%s\n", match.Path, match.Line, match.Text)
			}
			return nil
		},
	}
	search.Flags().StringVar(&searchPattern, "pattern", "", "search pattern")
	search.Flags().StringVar(&toolCallID, "tool-call-id", "", "tool call id")
	_ = search.MarkFlagRequired("pattern")

	artifactPath := ""
	artifactName := ""
	artifact := &cobra.Command{
		Use:   "export-artifact <session_id>",
		Short: "export a workspace file into the local artifacts directory",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			paths, err := store.Init(*dataDir)
			if err != nil {
				return err
			}
			db, err := store.Open(paths)
			if err != nil {
				return err
			}
			defer db.Close()
			artifactRef, decision, err := (computerapi.Service{DB: db, Paths: paths}).ExportArtifact(args[0], artifactPath, artifactName, toolCallID)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "decision=%s reason=%s artifact=%s\n", decision.Decision, decision.Reason, artifactRef)
			return nil
		},
	}
	artifact.Flags().StringVar(&artifactPath, "path", "", "workspace-relative path")
	artifact.Flags().StringVar(&artifactName, "name", "", "artifact output name")
	artifact.Flags().StringVar(&toolCallID, "tool-call-id", "", "tool call id")
	_ = artifact.MarkFlagRequired("path")

	callModule := ""
	callFunction := ""
	callCommand := ""
	var callStream bool
	call := &cobra.Command{
		Use:   "call <session_id>",
		Short: "invoke a structured sandbox capability",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			paths, err := store.Init(*dataDir)
			if err != nil {
				return err
			}
			db, err := store.Open(paths)
			if err != nil {
				return err
			}
			defer db.Close()
			processID, decision, err := (computerapi.Service{DB: db, Paths: paths}).Call(args[0], callModule, callFunction, map[string]string{"command": callCommand}, toolCallID, callStream)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "decision=%s reason=%s process_id=%s\n", decision.Decision, decision.Reason, processID)
			return nil
		},
	}
	call.Flags().StringVar(&callModule, "module", "shell", "call module")
	call.Flags().StringVar(&callFunction, "function", "exec", "call function")
	call.Flags().StringVar(&callCommand, "command", "", "shell command for shell/exec")
	call.Flags().StringVar(&toolCallID, "tool-call-id", "", "tool call id")
	call.Flags().BoolVar(&callStream, "stream", false, "stream command output")
	_ = call.MarkFlagRequired("command")

	cmd := &cobra.Command{Use: "api", Short: "structured sandbox API commands"}
	cmd.AddCommand(fileRead)
	cmd.AddCommand(fileWrite)
	cmd.AddCommand(search)
	cmd.AddCommand(artifact)
	cmd.AddCommand(call)
	return cmd
}

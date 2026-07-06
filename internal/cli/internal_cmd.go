package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"
)

// internalCmd is the hidden home for plumbing subcommands that porcelain
// commands (launch) invoke but users rarely call directly -- the git
// porcelain/plumbing split. Kept hidden so `agentprov --help` stays focused on
// the handful of top-level verbs. More plumbing will migrate here over time.
func internalCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:    "internal",
		Short:  "plumbing subcommands used by porcelain commands",
		Hidden: true,
	}
	cmd.AddCommand(internalHookLogCmd())
	return cmd
}

// internalHookLogCmd appends the hook event's raw JSON stdin to a run's hook log
// as one line. This is the command every entry in launch's per-run Claude Code
// settings overlay points at; the resulting JSONL is folded into the graph by
// `hooks bridge` at seal time.
//
// It reads all of stdin, then appends it plus a newline in a single O_APPEND
// write so concurrent hook processes do not interleave typical (single-line)
// events. Very large multi-line payloads can still split under load; the bridge
// tolerates partial lines, and the essential events (tool calls, delegation,
// SendMessage) are single-line.
func internalHookLogCmd() *cobra.Command {
	var file string
	cmd := &cobra.Command{
		Use:    "hook-log",
		Short:  "append a hook event (stdin JSON) to a run hook log",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if file == "" {
				return fmt.Errorf("--file is required")
			}
			data, err := io.ReadAll(cmd.InOrStdin())
			if err != nil {
				return err
			}
			// Stamp a real wall-clock timestamp. Hook stdin carries no time field,
			// so without this the bridge falls back to a synthetic epoch and the
			// resulting tool_call windows cannot be time-joined to kernel effects.
			// Injected as `_ts` so a real `ts` (if a future hook adds one) still
			// wins in the bridge's firstStr("ts","_ts","timestamp") order.
			data = stampHookTS(data)
			// A hook must never break the agent: swallow write errors to stderr
			// rather than returning nonzero (a nonzero PreToolUse hook can abort
			// the agent's tool call). Missing evidence is acceptable; a broken
			// agent run is not.
			f, err := os.OpenFile(file, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
			if err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "hook-log: open: %v\n", err)
				return nil
			}
			defer f.Close()
			if len(data) > 0 && data[len(data)-1] != '\n' {
				data = append(data, '\n')
			}
			if _, err := f.Write(data); err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "hook-log: write: %v\n", err)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&file, "file", "", "hook log file to append to")
	return cmd
}

// stampHookTS injects a real-time `_ts` into a hook event JSON object. If the
// payload is not a JSON object it is returned unchanged (the bridge tolerates
// unstamped lines).
func stampHookTS(data []byte) []byte {
	var obj map[string]any
	if err := json.Unmarshal(data, &obj); err != nil {
		return data
	}
	if _, ok := obj["_ts"]; !ok {
		obj["_ts"] = time.Now().UTC().Format(time.RFC3339Nano)
	}
	stamped, err := json.Marshal(obj)
	if err != nil {
		return data
	}
	return stamped
}

package signals

import (
	"database/sql"
	"fmt"
)

// Projection bridges the legacy per-dimension silos into the unified signal
// model. It reads existing rows and records them as unified signals, keyed
// idempotently on (source_table, source_id) so it can run repeatedly (e.g. as a
// backfill or a periodic sync) without creating duplicates. Hot write paths are
// left untouched; new producers should call Record directly.
//
// Each projector fully drains its read cursor before writing - read first, then
// write. This is correct regardless of pool size and keeps the projector safe
// if the store ever moves to a single-connection write-serialization model.

// ProjectRiskSignals projects the security silo (risk_signals) into the unified
// model under the Security dimension.
func ProjectRiskSignals(db *sql.DB) (int, error) {
	rows, err := db.Query(`SELECT id, run_id, session_id, tool_call_id, process_id, event_id,
		signal_type, severity, reason, recommended_action, payload, created_at FROM risk_signals`)
	if err != nil {
		return 0, fmt.Errorf("signals: read risk_signals: %w", err)
	}
	var pending []Signal
	for rows.Next() {
		var id, runID, sessionID, toolCallID, processID, eventID, sigType, severity, reason, action, payload, createdAt string
		if err := rows.Scan(&id, &runID, &sessionID, &toolCallID, &processID, &eventID,
			&sigType, &severity, &reason, &action, &payload, &createdAt); err != nil {
			rows.Close()
			return 0, fmt.Errorf("signals: scan risk_signal: %w", err)
		}
		pending = append(pending, Signal{
			Dimension: Security, Type: sigType,
			GraphRefKind: graphKind(processID, toolCallID), GraphRefID: graphID(processID, toolCallID, runID),
			RunID: runID, SessionID: sessionID, ToolCallID: toolCallID, ProcessID: processID, EventID: eventID,
			Severity: severity, Reference: reason, RecommendedAction: action,
			ProducedBy: "security.policy", Payload: payload, CreatedAt: createdAt,
			SourceTable: "risk_signals", SourceID: id,
		})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, fmt.Errorf("signals: iterate risk_signals: %w", err)
	}
	rows.Close()
	return recordAll(db, pending)
}

// ProjectBaselineDeviations projects the baseline silo into the unified model.
// Deviations are security signals (deviation-from-expected-norm).
func ProjectBaselineDeviations(db *sql.DB) (int, error) {
	rows, err := db.Query(`SELECT id, run_id, deviation_type, status, expected_value, observed_value,
		recommended_action, payload, created_at FROM baseline_deviations`)
	if err != nil {
		return 0, fmt.Errorf("signals: read baseline_deviations: %w", err)
	}
	var pending []Signal
	for rows.Next() {
		var id, runID, devType, status, action, payload, createdAt string
		var expected, observed float64
		if err := rows.Scan(&id, &runID, &devType, &status, &expected, &observed, &action, &payload, &createdAt); err != nil {
			rows.Close()
			return 0, fmt.Errorf("signals: scan baseline_deviation: %w", err)
		}
		pending = append(pending, Signal{
			Dimension: Security, Type: "baseline_deviation:" + devType,
			GraphRefKind: "run", GraphRefID: runID, RunID: runID,
			Severity: status, Value: observed, Reference: fmt.Sprintf("expected=%g", expected),
			RecommendedAction: action, ProducedBy: "baseline", Payload: payload, CreatedAt: createdAt,
			SourceTable: "baseline_deviations", SourceID: id,
		})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, fmt.Errorf("signals: iterate baseline_deviations: %w", err)
	}
	rows.Close()
	return recordAll(db, pending)
}

// ProjectCostSamples projects the system-side resource-attribution rows
// (cost_samples) into the unified model under the Cost dimension. This is the
// only cost that rides the correlation graph; app-side token/$ cost is
// deliberately out of scope.
func ProjectCostSamples(db *sql.DB) (int, error) {
	rows, err := db.Query(`SELECT id, run_id, session_id, active_cpu_seconds, wall_seconds, created_at FROM cost_samples`)
	if err != nil {
		return 0, fmt.Errorf("signals: read cost_samples: %w", err)
	}
	var pending []Signal
	for rows.Next() {
		var id, runID, sessionID, createdAt string
		var activeCPU, wall float64
		if err := rows.Scan(&id, &runID, &sessionID, &activeCPU, &wall, &createdAt); err != nil {
			rows.Close()
			return 0, fmt.Errorf("signals: scan cost_sample: %w", err)
		}
		kind, refID := "run", runID
		if sessionID != "" {
			kind, refID = "session", sessionID
		}
		pending = append(pending, Signal{
			Dimension: Cost, Type: "resource_sample",
			GraphRefKind: kind, GraphRefID: refID, RunID: runID, SessionID: sessionID,
			Value: activeCPU, Reference: "active_cpu_seconds",
			ProducedBy: "cost", CreatedAt: createdAt,
			SourceTable: "cost_samples", SourceID: id,
		})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, fmt.Errorf("signals: iterate cost_samples: %w", err)
	}
	rows.Close()
	return recordAll(db, pending)
}

// Backfill projects every legacy silo into the unified model and returns the
// total number of rows projected. Safe to run repeatedly (idempotent).
func Backfill(db *sql.DB) (int, error) {
	total := 0
	for _, p := range []func(*sql.DB) (int, error){ProjectRiskSignals, ProjectBaselineDeviations, ProjectCostSamples} {
		n, err := p(db)
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

// recordAll writes a fully-read batch of signals and returns how many were
// newly inserted (idempotent source rows that already exist do not count).
func recordAll(db *sql.DB, batch []Signal) (int, error) {
	n := 0
	for _, s := range batch {
		inserted, err := RecordCounting(db, s)
		if err != nil {
			return n, err
		}
		if inserted {
			n++
		}
	}
	return n, nil
}

// graphKind/graphID pick the most specific graph node available to anchor a
// signal: process > tool_call > run.
func graphKind(processID, toolCallID string) string {
	switch {
	case processID != "":
		return "process"
	case toolCallID != "":
		return "tool_call"
	default:
		return "run"
	}
}

func graphID(processID, toolCallID, runID string) string {
	switch {
	case processID != "":
		return processID
	case toolCallID != "":
		return toolCallID
	default:
		return runID
	}
}

package compliance

const disclaimer = "Evidence-backed self-assessment only. This is not certification, legal advice, or a substitute for a qualified third-party audit."

func owaspASI() Framework {
	return Framework{
		ID:          "owasp-asi",
		Title:       "OWASP Agentic Security Mapping",
		Description: "AgentProvenance evidence mapping profile for OWASP Agentic Security style risks.",
		Disclaimer:  disclaimer,
		Controls: []Control{
			{
				ID:       "ASI01",
				Title:    "Agent Goal Hijack",
				Evidence: []string{"policy_decision", "risk_signal"},
				Partial:  []string{"tool_call", "timeline"},
				Gap:      "no policy/risk evidence showing prompt, goal, or instruction guardrail enforcement",
				NextStep: "connect agent-level prompt/tool policy decisions to ToolCallScope evidence",
			},
			{
				ID:       "ASI02",
				Title:    "Tool Misuse and Exploitation",
				Evidence: []string{"tool_call", "policy_decision", "response_action"},
				Partial:  []string{"tool_call", "runtime_event"},
				Gap:      "tool call, policy decision, or response action evidence is incomplete",
				NextStep: "add tool allow/deny policy evidence and response records",
			},
			{
				ID:       "ASI03",
				Title:    "Identity and Privilege Abuse",
				Evidence: []string{"binding", "session", "credential_event"},
				Partial:  []string{"binding", "session"},
				Gap:      "runtime identity exists but credential or privilege evidence is missing",
				NextStep: "record credential access, identity, or privilege boundary evidence",
			},
			{
				ID:       "ASI04",
				Title:    "Agentic Supply Chain",
				Evidence: []string{"provenance_object", "snapshot", "artifact"},
				Partial:  []string{"provenance_object", "artifact"},
				Gap:      "artifact lineage exists but template/SBOM/dependency evidence is incomplete",
				NextStep: "attach template bundle, dependency manifest, or SBOM refs",
			},
			{
				ID:       "ASI05",
				Title:    "Unexpected Code Execution",
				Evidence: []string{"exec_event", "process", "runtime_event"},
				Partial:  []string{"process", "runtime_event"},
				Gap:      "exec event, process, or runtime evidence is incomplete",
				NextStep: "ingest Falco/Tetragon/zero-SDK process events for the run",
			},
			{
				ID:       "ASI06",
				Title:    "Memory and Context Poisoning",
				Evidence: []string{"snapshot", "diff_blame", "taint"},
				Partial:  []string{"snapshot", "provenance_object"},
				Gap:      "snapshot/provenance evidence exists but taint or state-diff evidence is missing",
				NextStep: "materialize graph objects and record taint/diff evidence for modified state",
			},
			{
				ID:         "ASI07",
				Title:      "Insecure Inter-Agent Communication",
				Evidence:   []string{"inter_agent_event", "trust_decision"},
				NotApplies: []string{"single_agent_run"},
				Gap:        "no inter-agent communication or trust-decision evidence found",
				NextStep:   "record A2A/MCP handoff identity and trust gate events when multi-agent flows exist",
			},
			{
				ID:       "ASI08",
				Title:    "Cascading Agent Failures",
				Evidence: []string{"response_action", "baseline_deviation", "resource_evidence"},
				Partial:  []string{"response_action", "policy_decision"},
				Gap:      "response or resource evidence is incomplete for cascade control",
				NextStep: "record circuit breaker, resource pressure, or response gate evidence",
			},
			{
				ID:       "ASI09",
				Title:    "Human-Agent Trust Exploitation",
				Evidence: []string{"timeline", "forensics_bundle", "explainable_graph"},
				Partial:  []string{"timeline", "provenance_object"},
				Gap:      "audit/explain evidence exists but forensics or review bundle evidence is missing",
				NextStep: "export a forensics bundle and attach review/approval evidence for high-risk runs",
			},
			{
				ID:       "ASI10",
				Title:    "Rogue Agents",
				Evidence: []string{"baseline_deviation", "risk_signal", "response_action"},
				Partial:  []string{"baseline_deviation", "risk_signal"},
				Gap:      "rogue behavior evidence exists without recorded response action",
				NextStep: "link baseline deviations to response action or quarantine evidence",
			},
			{
				ID:       "TRACE",
				Title:    "Agent Traceability Extension",
				Evidence: []string{"timeline", "provenance_object", "graph_edge"},
				Partial:  []string{"timeline", "runtime_event"},
				Gap:      "runtime evidence exists but content-addressed provenance objects or graph edges are missing",
				NextStep: "run graph materialize/verify and attach object refs",
			},
		},
	}
}

func nistRFI() Framework {
	return Framework{
		ID:          "nist-rfi-2026-00206",
		Title:       "NIST AI Agent Security RFI Evidence Mapping",
		Description: "AgentProvenance evidence mapping profile for NIST AI agent security assessment questions.",
		Disclaimer:  disclaimer,
		Controls: []Control{
			{
				ID:       "Q1",
				Title:    "Security Threats, Risks, and Vulnerabilities",
				Evidence: []string{"risk_signal", "baseline_deviation", "policy_decision"},
				Partial:  []string{"runtime_event", "timeline"},
				Gap:      "runtime activity exists but risk or deviation evidence is missing",
				NextStep: "run policy evaluation and baseline check for this run",
			},
			{
				ID:       "Q2",
				Title:    "Security Practices and Technical Controls",
				Evidence: []string{"policy_decision", "response_action", "binding"},
				Partial:  []string{"binding", "session"},
				Gap:      "identity/session evidence exists but control decisions or responses are missing",
				NextStep: "record policy decisions, adapter capability, and response action evidence",
			},
			{
				ID:       "Q3",
				Title:    "Detection and Assessment Methods",
				Evidence: []string{"telemetry_batch", "timeline", "baseline_deviation"},
				Partial:  []string{"runtime_event", "timeline"},
				Gap:      "runtime telemetry exists but batch/deviation evidence is incomplete",
				NextStep: "ingest telemetry batches and run baseline check",
			},
			{
				ID:       "Q4",
				Title:    "Constraining and Monitoring Deployment Environments",
				Evidence: []string{"session", "binding", "response_action", "runtime_event"},
				Partial:  []string{"session", "binding"},
				Gap:      "sandbox identity exists but monitoring or response evidence is incomplete",
				NextStep: "attach runtime telemetry and policy response evidence",
			},
			{
				ID:       "Q5",
				Title:    "Adoption, Research, and Cross-Discipline Considerations",
				Evidence: []string{"forensics_bundle", "provenance_object"},
				Partial:  []string{"timeline", "provenance_object"},
				Gap:      "operational artifacts for broader assessment are incomplete",
				NextStep: "export forensics bundle and include signed/object-hash evidence in review material",
			},
		},
	}
}

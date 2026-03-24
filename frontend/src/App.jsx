import { useState, useEffect, useRef } from "react";

const API = "http://localhost:8000";
const WS  = "ws://localhost:8000";

function useSession(sessionId) {
  const [agents,    setAgents]    = useState({});
  const [findings,  setFindings]  = useState([]);
  const [questions, setQuestions] = useState({});
  const [connected, setConnected] = useState(false);
  const [done,      setDone]      = useState(false);

  useEffect(() => {
    if (!sessionId) return;
    const ws = new WebSocket(`${WS}/ws/${sessionId}`);
    ws.onopen  = () => setConnected(true);
    ws.onclose = () => setConnected(false);
    ws.onmessage = (e) => {
      try {
        const ev = JSON.parse(e.data);
        if (ev.type === "snapshot" && ev.data) {
          if (ev.data.agent_states) setAgents(ev.data.agent_states);
          if (ev.data.findings)     setFindings(ev.data.findings);
          if (ev.data.hitl) setQuestions(Object.fromEntries(ev.data.hitl.map(q => [q.question_id, q])));
        }
        if (ev.namespace === "agent_state") setAgents(p => ({ ...p, [ev.key]: ev.data }));
        if (ev.namespace === "finding") setFindings(p => p.find(f => f.finding_id === ev.data.finding_id) ? p : [...p, ev.data]);
        if (ev.namespace === "hitl_question" || ev.namespace === "hitl_answer") setQuestions(p => ({ ...p, [ev.key]: ev.data }));
        if (ev.type === "analysis_complete") setDone(true);
      } catch {}
    };
    return () => ws.close();
  }, [sessionId]);

  return { agents, findings, questions, connected, done };
}

const AGENT_ORDER = ["orchestrator", "recon", "analysis", "report"];
const AGENT_META = {
  orchestrator: { icon: "⚙️", name: "Coordinator",   desc: "Plans the full analysis and coordinates all agents" },
  recon:        { icon: "🗂️", name: "File Scanner",   desc: "Maps every file in the repository" },
  analysis:     { icon: "🔍", name: "Security Analyst", desc: "Scans each file for vulnerabilities" },
  report:       { icon: "📄", name: "Report Writer",  desc: "Synthesises all findings into a final report" },
};

const SEV_COLOR = {
  critical: "#ff4444",
  high:     "#ff8800",
  medium:   "#f5c400",
  low:      "#44bb77",
  info:     "#4488ff",
};

function humanize(key) {
  if (!key) return "";
  return key.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase());
}

function cleanObservation(raw) {
  if (!raw) return "";
  if (typeof raw !== "string") return String(raw);
  // Strip Python dict syntax for non-technical users
  if (raw.startsWith("{") || raw.startsWith("[")) {
    try {
      const parsed = JSON.parse(raw.replace(/'/g, '"').replace(/True/g, 'true').replace(/False/g, 'false').replace(/None/g, 'null'));
      if (parsed.status) return `Status: ${parsed.status}`;
      if (parsed.total_files) return `Found ${parsed.total_files} files (${(parsed.languages_detected || []).join(", ")})`;
      if (parsed.match_count !== undefined) return `Scanned file — ${parsed.match_count} pattern matches found`;
      if (parsed.file_path) return `Analysed: ${parsed.file_path}`;
    } catch {}
    if (raw.length > 120) return raw.slice(0, 120) + "…";
  }
  return raw.length > 200 ? raw.slice(0, 200) + "…" : raw;
}

// ── Step component — one reasoning step inside an agent ───────────────────────
function StepRow({ step }) {
  const icons = { "Observed": "👁", "Planned": "🧠", "Acting": "⚡", "Evaluated": "✅", "Decided": "🎯" };
  return (
    <div className="step-row">
      <div className="step-left">
        <div className="step-icon">{icons[step.type] || "•"}</div>
        <div className="step-line" />
      </div>
      <div className="step-content">
        <div className="step-type">{step.type}</div>
        <div className="step-text">{step.text}</div>
      </div>
    </div>
  );
}

// ── Agent card — full reasoning trail ─────────────────────────────────────────
function AgentCard({ state, questions, onAnswer, isLatest }) {
  const [expanded, setExpanded] = useState(true);
  const meta = AGENT_META[state.agent_type] || { icon: "🤖", name: state.agent_type, desc: "" };
  const isRunning = state.status === "running";
  const isWaiting = state.status === "waiting_for_human";
  const isDone    = state.status === "done";
  const isFailed  = state.status === "failed";

  // Auto-collapse completed agents (except the latest)
  useEffect(() => {
    if (isDone && !isLatest) {
      const t = setTimeout(() => setExpanded(false), 1500);
      return () => clearTimeout(t);
    }
    if (isRunning || isWaiting) setExpanded(true);
  }, [state.status, isLatest]);

  const myQuestions = Object.values(questions).filter(q => q.agent_id === state.agent_id);
  const pendingQ    = myQuestions.filter(q => q.status === "pending");

  // Build human-readable step trail from agent state
  const steps = [];
  if (state.last_observation && state.last_observation !== "{}" && !state.last_observation.startsWith("Observed")) {
    steps.push({ type: "Observed", text: cleanObservation(state.last_observation) });
  }
  if (state.thought && state.thought !== state.last_observation) {
    steps.push({ type: "Planned", text: state.thought });
  }
  if (state.last_action) {
    steps.push({ type: "Acting", text: humanize(state.last_action) });
  }
  if (state.decision && state.decision !== "continue") {
    steps.push({ type: "Decided", text: humanize(state.decision) });
  }

  const statusDot = isRunning ? "running" : isWaiting ? "waiting" : isDone ? "done" : isFailed ? "failed" : "idle";
  const statusLabel = isRunning ? "Working…" : isWaiting ? "Waiting for you" : isDone ? "Done" : isFailed ? "Failed" : "Idle";

  const pct = Math.min(100, (state.iterations / (state.max_iterations || 50)) * 100);

  return (
    <div className={`agent-card ${statusDot}`}>
      {/* Card header */}
      <div className="agent-card-header" onClick={() => setExpanded(e => !e)}>
        <div className="agent-card-left">
          <span className="agent-emoji">{meta.icon}</span>
          <div>
            <div className="agent-card-name">
              {meta.name}
              {isRunning && (
                <span className="typing-indicator">
                  <span/><span/><span/>
                </span>
              )}
            </div>
            {!expanded && isDone && state.thought && (
              <div className="agent-card-summary">{state.thought}</div>
            )}
          </div>
        </div>
        <div className="agent-card-right">
          <span className={`status-dot ${statusDot}`} />
          <span className="status-label">{statusLabel}</span>
          <span className="expand-btn">{expanded ? "▲" : "▼"}</span>
        </div>
      </div>

      {/* Progress bar */}
      {(isRunning || isDone) && (
        <div className="progress-bar">
          <div className="progress-fill" style={{ width: `${pct}%` }} />
        </div>
      )}

      {/* Expanded body */}
      {expanded && (
        <div className="agent-card-body">
          <div className="agent-desc">{meta.desc}</div>

          {steps.length > 0 && (
            <div className="steps-trail">
              {steps.map((s, i) => <StepRow key={i} step={s} />)}
            </div>
          )}

          {/* HITL question */}
          {pendingQ.map(q => (
            <HITLCard key={q.question_id} question={q} onAnswer={onAnswer} />
          ))}

          {/* Answered questions */}
          {myQuestions.filter(q => q.status === "answered").map(q => (
            <div key={q.question_id} className="hitl-answered">
              <span className="hitl-answered-icon">✓</span>
              <div>
                <div className="hitl-answered-q">{q.question}</div>
                <div className="hitl-answered-a">Your answer: {q.answer}</div>
              </div>
            </div>
          ))}

          {isRunning && (
            <div className="agent-thinking-bar">
              <div className="thinking-shimmer" />
            </div>
          )}

          {isDone && (
            <div className="agent-done-bar">
              <span>✓</span> Completed in {state.iterations} steps
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── HITL card ──────────────────────────────────────────────────────────────────
function HITLCard({ question, onAnswer }) {
  const [answer, setAnswer] = useState("");
  const [loading, setLoading] = useState(false);

  async function submit(ans) {
    setLoading(true);
    await onAnswer(question.question_id, ans || answer);
    setLoading(false);
  }

  return (
    <div className="hitl-card">
      <div className="hitl-header">
        <span className="hitl-icon">💬</span>
        <span className="hitl-title">The agent needs your input to continue</span>
      </div>
      <p className="hitl-question">{question.question}</p>
      {question.context && (
        <div className="hitl-context">
          <strong>Context:</strong> {question.context.slice(0, 300)}
        </div>
      )}
      {question.options?.length > 0 ? (
        <div className="hitl-options">
          {question.options.map((opt, i) => (
            <button key={i} className="hitl-option" onClick={() => submit(opt)} disabled={loading}>
              {opt}
            </button>
          ))}
        </div>
      ) : (
        <div className="hitl-input-row">
          <input
            className="hitl-input"
            placeholder="Type your answer and press Enter…"
            value={answer}
            onChange={e => setAnswer(e.target.value)}
            onKeyDown={e => e.key === "Enter" && submit()}
            autoFocus
          />
          <button className="hitl-send" onClick={() => submit()} disabled={loading || !answer}>
            {loading ? "…" : "Send →"}
          </button>
        </div>
      )}
    </div>
  );
}

// ── Finding card ───────────────────────────────────────────────────────────────
function FindingCard({ f }) {
  const [open, setOpen] = useState(false);
  const color = SEV_COLOR[f.severity] || "#888";

  return (
    <div className="finding-card" onClick={() => setOpen(o => !o)}>
      <div className="finding-header">
        <div className="finding-sev-bar" style={{ background: color }} />
        <div className="finding-main">
          <span className="finding-title">{f.title || f.rule_id}</span>
          <div className="finding-meta-row">
            <span className="finding-badge" style={{ background: color + "22", color }}>
              {f.severity}
            </span>
            <span className="finding-file">📄 {f.file_path?.split("/").pop() || f.file_path}</span>
            <span className="finding-conf">{f.confidence ? `${(f.confidence * 100).toFixed(0)}% confident` : ""}</span>
          </div>
        </div>
        <span className="finding-toggle">{open ? "▲" : "▼"}</span>
      </div>

      {open && (
        <div className="finding-detail">
          {f.description && (
            <div className="finding-section">
              <div className="finding-section-label">What's the issue?</div>
              <div className="finding-section-text">{f.description}</div>
            </div>
          )}
          {f.evidence && (
            <div className="finding-section">
              <div className="finding-section-label">Where is it?</div>
              <pre className="finding-code">{f.evidence}</pre>
            </div>
          )}
          {f.recommendation && (
            <div className="finding-section">
              <div className="finding-section-label">How to fix it</div>
              <div className="finding-section-text">{f.recommendation}</div>
            </div>
          )}
          {f.false_positive_risk && (
            <div className="finding-section">
              <div className="finding-section-label">Could this be a false alarm?</div>
              <div className="finding-section-text" style={{ color: "#aaa" }}>{f.false_positive_risk}</div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── Report ─────────────────────────────────────────────────────────────────────
function ReportCard({ sessionId, visible }) {
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(false);
  const tried = useRef(false);

  useEffect(() => {
    if (visible && !tried.current) {
      tried.current = true;
      setLoading(true);
      fetch(`${API}/session/${sessionId}/report`)
        .then(r => r.json())
        .then(d => { if (d.executive_summary) setReport(d); })
        .finally(() => setLoading(false));
    }
  }, [visible, sessionId]);

  if (!visible) return null;
  if (loading) return <div className="report-loading">Generating report…</div>;
  if (!report) return (
    <button className="btn-load-report" onClick={() => { tried.current = false; setLoading(true); fetch(`${API}/session/${sessionId}/report`).then(r=>r.json()).then(d=>{if(d.executive_summary)setReport(d)}).finally(()=>setLoading(false)); }}>
      Load Report
    </button>
  );

  const riskColor = SEV_COLOR[report.risk_rating] || "#888";
  return (
    <div className="report-card">
      <div className="report-risk" style={{ borderColor: riskColor, color: riskColor }}>
        {report.risk_rating?.toUpperCase()} RISK
      </div>
      <p className="report-summary">{report.executive_summary}</p>
      {report.top_recommendations?.length > 0 && (
        <div className="report-recs">
          <div className="report-recs-title">What to do next</div>
          {report.top_recommendations.map((r, i) => (
            <div key={i} className="report-rec-item">
              <span className="rec-num">{r.priority}</span>
              <div>
                <div className="rec-action">{r.action}</div>
                {r.rationale && <div className="rec-rationale">{r.rationale}</div>}
              </div>
            </div>
          ))}
        </div>
      )}
      {report.conclusion && <p className="report-conclusion">{report.conclusion}</p>}
    </div>
  );
}

// ── Start screen ───────────────────────────────────────────────────────────────
function StartScreen({ onStart }) {
  const [mode,    setMode]    = useState("github");
  const [ghUrl,   setGhUrl]   = useState("");
  const [path,    setPath]    = useState("");
  const [file,    setFile]    = useState(null);
  const [loading, setLoading] = useState(false);
  const [error,   setError]   = useState("");

  async function launch() {
    setError(""); setLoading(true);
    try {
      let res;
      if (mode === "github") {
        if (!ghUrl.trim()) { setError("Please enter a GitHub URL."); setLoading(false); return; }
        res = await fetch(`${API}/analyse/github`, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ github_url: ghUrl.trim() }),
        });
      } else if (mode === "upload") {
        if (!file) { setError("Please select a .zip file."); setLoading(false); return; }
        const fd = new FormData(); fd.append("file", file);
        res = await fetch(`${API}/analyse/upload`, { method: "POST", body: fd });
      } else {
        if (!path.trim()) { setError("Please enter a path."); setLoading(false); return; }
        res = await fetch(`${API}/analyse/repo`, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ repo_path: path.trim() }),
        });
      }
      const data = await res.json();
      if (!res.ok) { setError(data.detail || "Something went wrong. Is the server running?"); setLoading(false); return; }
      onStart(data.session_id);
    } catch {
      setError("Cannot connect to the server. Make sure uvicorn is running on port 8000.");
      setLoading(false);
    }
  }

  return (
    <div className="start-page">
      <div className="start-card">
        <div className="start-logo">
          <div className="logo-hex">⬡</div>
          <div>
            <div className="logo-title">HoneySentinel</div>
            <div className="logo-sub">Agentic Security Intelligence</div>
          </div>
        </div>

        <p className="start-description">
          Drop a GitHub link or upload your code as a zip. Our AI agents will
          scan every file, reason about security risks, and give you a plain-English report.
        </p>

        <div className="mode-tabs">
          {[["github", "🔗 GitHub URL"], ["upload", "📦 Upload Zip"], ["path", "📁 Local Path"]].map(([id, label]) => (
            <button key={id} className={`mode-tab ${mode === id ? "active" : ""}`} onClick={() => setMode(id)}>
              {label}
            </button>
          ))}
        </div>

        {mode === "github" && (
          <div className="input-group">
            <input className="main-input" placeholder="https://github.com/owner/repository"
              value={ghUrl} onChange={e => setGhUrl(e.target.value)}
              onKeyDown={e => e.key === "Enter" && launch()} autoFocus />
            <p className="input-hint">Works with public repos. Private repos need a token.</p>
          </div>
        )}
        {mode === "upload" && (
          <div className="input-group">
            <div className="file-zone" onClick={() => document.getElementById("zipfile").click()}>
              <div className="file-zone-inner">
                {file ? <><span style={{fontSize:24}}>📦</span><span>{file.name}</span></>
                      : <><span style={{fontSize:24}}>⬆️</span><span>Click to select a .zip file</span></>}
              </div>
              <input id="zipfile" type="file" accept=".zip" style={{ display: "none" }}
                onChange={e => setFile(e.target.files[0])} />
            </div>
          </div>
        )}
        {mode === "path" && (
          <div className="input-group">
            <input className="main-input" placeholder="C:\projects\my-app"
              value={path} onChange={e => setPath(e.target.value)}
              onKeyDown={e => e.key === "Enter" && launch()} />
          </div>
        )}

        {error && <div className="error-banner">{error}</div>}

        <button className="launch-button" onClick={launch} disabled={loading}>
          {loading
            ? <><div className="btn-spinner" /> {mode === "github" ? "Cloning repository…" : "Starting analysis…"}</>
            : "🚀  Start Security Analysis"}
        </button>
      </div>
    </div>
  );
}

// ── Main App ───────────────────────────────────────────────────────────────────
export default function App() {
  const [sessionId, setSessionId] = useState(null);
  const { agents, findings, questions, connected, done } = useSession(sessionId);
  const bottomRef = useRef(null);

  const agentList = AGENT_ORDER.map(type => {
    const entry = Object.values(agents).find(a => a.agent_type === type);
    return entry;
  }).filter(Boolean);

  // Only show agents that have started
  const visibleAgents = agentList.filter(a => a.status !== "idle");
  const latestAgentId = visibleAgents.length > 0 ? visibleAgents[visibleAgents.length - 1].agent_id : null;

  const pendingHITL  = Object.values(questions).filter(q => q.status === "pending");
  const critCount    = findings.filter(f => f.severity === "critical").length;
  const highCount    = findings.filter(f => f.severity === "high").length;
  const reportDone   = agentList.find(a => a.agent_type === "report")?.status === "done";

  // Auto-scroll to bottom as new content appears
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [visibleAgents.length, findings.length]);

  async function handleAnswer(qid, answer) {
    await fetch(`${API}/session/${sessionId}/hitl/${qid}/answer`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ answer }),
    });
  }

  if (!sessionId) return <StartScreen onStart={setSessionId} />;

  const sessionShort = sessionId.slice(0, 8);

  return (
    <div className="app-page">
      {/* Sticky header */}
      <div className="app-header">
        <div className="app-header-left">
          <span className="header-hex">⬡</span>
          <span className="header-title">HoneySentinel</span>
        </div>
        <div className="app-header-center">
          <div className={`conn-dot ${connected ? "green" : "gray"}`} />
          <span className="conn-label">
            {done ? "Analysis complete" : pendingHITL.length > 0 ? "⚠ Waiting for your input" : connected ? "Agents working…" : "Connecting…"}
          </span>
        </div>
        <button className="header-new" onClick={() => setSessionId(null)}>New Analysis</button>
      </div>

      {/* Stats strip */}
      <div className="stats-strip">
        <div className="stat-item"><span className="stat-num">{findings.length}</span><span className="stat-lbl">Findings</span></div>
        <div className="stat-sep" />
        <div className="stat-item"><span className="stat-num" style={critCount > 0 ? {color:"#ff4444"}:{}}>{critCount}</span><span className="stat-lbl">Critical</span></div>
        <div className="stat-sep" />
        <div className="stat-item"><span className="stat-num" style={highCount > 0 ? {color:"#ff8800"}:{}}>{highCount}</span><span className="stat-lbl">High</span></div>
        <div className="stat-sep" />
        <div className="stat-item"><span className="stat-num" style={pendingHITL.length > 0 ? {color:"#f5c400"}:{}}>{pendingHITL.length}</span><span className="stat-lbl">Awaiting input</span></div>
        <div className="stat-sep" />
        <div className="stat-item"><span className="stat-num stat-session">{sessionShort}</span><span className="stat-lbl">Session</span></div>
      </div>

      {/* Main scroll area */}
      <div className="main-scroll">
        <div className="content-col">

          {/* Agent flow */}
          {visibleAgents.length === 0 && (
            <div className="waiting-start">
              <div className="waiting-spinner" />
              <span>Starting agents…</span>
            </div>
          )}

          {visibleAgents.map((a, i) => (
            <AgentCard
              key={a.agent_id}
              state={a}
              questions={questions}
              onAnswer={handleAnswer}
              isLatest={a.agent_id === latestAgentId}
            />
          ))}

          {/* Findings section — appears inline after analysis */}
          {findings.length > 0 && (
            <div className="inline-section">
              <div className="inline-section-title">
                <span className="section-icon">🛡</span>
                Security Findings
                <span className="section-count">{findings.length}</span>
              </div>
              {["critical","high","medium","low","info"].map(sev => {
                const group = findings.filter(f => f.severity === sev);
                if (!group.length) return null;
                return (
                  <div key={sev} className="sev-group">
                    <div className="sev-group-label" style={{ color: SEV_COLOR[sev] }}>
                      <span className="sev-group-dot" style={{ background: SEV_COLOR[sev] }} />
                      {sev.charAt(0).toUpperCase() + sev.slice(1)} severity
                      <span className="sev-group-count">{group.length}</span>
                    </div>
                    {group.map(f => <FindingCard key={f.finding_id} f={f} />)}
                  </div>
                );
              })}
            </div>
          )}

          {/* Report section */}
          {reportDone && (
            <div className="inline-section">
              <div className="inline-section-title">
                <span className="section-icon">📋</span>
                Final Report
              </div>
              <ReportCard sessionId={sessionId} visible={reportDone} />
            </div>
          )}

          <div ref={bottomRef} style={{ height: 40 }} />
        </div>
      </div>
    </div>
  );
}
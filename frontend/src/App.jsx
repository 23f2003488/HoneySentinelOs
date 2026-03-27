import { useState, useEffect, useRef } from "react";

const API = "http://localhost:8000";

function useSession(sessionId) {
  const [agents, setAgents] = useState({});
  const [findings, setFindings] = useState([]);
  const [questions, setQuestions] = useState({});
  const [repoMap, setRepoMap] = useState(null);
  const [connected, setConnected] = useState(false);
  const [done, setDone] = useState(false);

  useEffect(() => {
    if (!sessionId) return;
    let interval;
    const pollData = async () => {
      try {
        const res = await fetch(`${API}/session/${sessionId}`);
        if (!res.ok) throw new Error("Session not found");
        const data = await res.json();
        
        if (data.agent_states) setAgents(data.agent_states);
        if (data.findings) setFindings(data.findings);
        if (data.repo_map) setRepoMap(data.repo_map);
        if (data.hitl) {
          const qMap = {};
          data.hitl.forEach(q => (qMap[q.question_id] = q));
          setQuestions(qMap);
        }

        const orch = data.agent_states?.["orchestrator"];
        if (orch && orch.status === "done") setDone(true);
        setConnected(true);
      } catch (err) {
        console.error("Polling error:", err);
        setConnected(false);
      }
    };

    pollData();
    interval = setInterval(pollData, 2000);
    if (done) clearInterval(interval);
    return () => clearInterval(interval);
  }, [sessionId, done]);

  return { agents, findings, questions, repoMap, connected, done };
}

const AGENT_META = {
  orchestrator: { icon: "⚙️", name: "Orchestrator Agent", tools: ["SessionManager", "AgentDelegator"], memory: "Cosmos DB (Session Root)" },
  recon:        { icon: "🗂️", name: "Recon Agent", tools: ["FileScannerTool", "AzureSearchIndexer"], memory: "Cosmos DB (RepoMap)" },
  analysis:     { icon: "🔍", name: "Analysis Agent", tools: ["PatternDetector", "Semgrep", "Pip-Audit", "AzureSearchTool"], memory: "Cosmos DB (Findings)" },
  report:       { icon: "📄", name: "Report Agent", tools: ["RiskSynthesizer"], memory: "Cosmos DB (Read-Only All)" },
};

const SEV_COLOR = { critical: "#ff4444", high: "#ff8800", medium: "#f5c400", low: "#44bb77", info: "#4488ff" };

function cleanObservation(raw) {
  if (!raw) return "";
  if (typeof raw !== "string") return String(raw);
  if (raw.startsWith("{") || raw.startsWith("[")) {
    try {
      const p = JSON.parse(raw.replace(/'/g, '"').replace(/True/g, 'true').replace(/False/g, 'false').replace(/None/g, 'null'));
      if (p.status) return `Status: ${p.status}`;
      if (p.total_files) return `Found ${p.total_files} files (${(p.languages_detected || []).join(", ")})`;
      if (p.file_path) return `Analysed: ${p.file_path}`;
    } catch {}
    if (raw.length > 80) return raw.slice(0, 80) + "…";
  }
  return raw.length > 150 ? raw.slice(0, 150) + "…" : raw;
}

function buildFileTree(files) {
  const root = {};
  files.forEach(f => {
    const parts = f.path.replace(/\\/g, "/").split("/");
    let current = root;
    parts.forEach((part, i) => {
      if (i === parts.length - 1) {
        current[part] = null;
      } else {
        current[part] = current[part] || {};
        current = current[part];
      }
    });
  });
  return root;
}

function FileTreeNode({ node, name, depth = 0 }) {
  const isFile = node === null;
  const padding = depth * 16;
  return (
    <div>
      <div style={{ paddingLeft: `${padding}px`, color: isFile ? "var(--text2)" : "var(--accent)", fontSize: "13px", fontFamily: "monospace", marginBottom: "6px" }}>
        {isFile ? "📄 " : "📁 "} {name}
      </div>
      {!isFile && Object.entries(node).map(([childName, childNode]) => (
        <FileTreeNode key={childName} name={childName} node={childNode} depth={depth + 1} />
      ))}
    </div>
  );
}

function AgentTransparency({ state, meta }) {
  return (
    <div className="agent-transparency-panel">
      <div className="transparency-grid">
        <div className="t-col">
          <span className="t-label">Initial State:</span> <span className="t-val">IDLE</span>
        </div>
        <div className="t-col">
          <span className="t-label">Current State:</span> <span className={`t-val state-${state.status}`}>{state.status.toUpperCase()}</span>
        </div>
        <div className="t-col">
          <span className="t-label">Memory:</span> <span className="t-val">{meta.memory}</span>
        </div>
      </div>
      <div className="t-row mt-2">
        <span className="t-label">Tools Used:</span> 
        <div className="tools-list">{meta.tools.map(t => <span key={t} className="tool-badge">{t}</span>)}</div>
      </div>
      <div className="t-row mt-2">
        <span className="t-label">Goal:</span> <span className="t-val goal-text">{state.goal}</span>
      </div>
    </div>
  );
}

function AgentCard({ state, questions, repoMap, onAnswer }) {
  const meta = AGENT_META[state.agent_type] || { icon: "🤖", name: state.agent_type, tools: [], memory: "" };
  const isRunning = state.status === "running";
  const isWaiting = state.status === "waiting_for_human";
  const isDone    = state.status === "done";
  const isFailed  = state.status === "failed";
  const [showFullTree, setShowFullTree] = useState(false);

  const myQuestions = Object.values(questions).filter(q => q.agent_id === state.agent_id);
  const pendingQ    = myQuestions.filter(q => q.status === "pending" || q.status === "HITLStatus.PENDING");
  const statusDot = isRunning ? "running" : isWaiting ? "waiting" : isDone ? "done" : isFailed ? "failed" : "idle";
  const hasTrace = state.last_action || state.last_observation || state.thought;

  return (
    <div className={`agent-card ${statusDot}`} id={`agent-${state.agent_type}`}>
      <div className="agent-card-header">
        <div className="agent-card-left">
          <span className="agent-emoji">{meta.icon}</span>
          <div className="agent-card-name">
            {meta.name}
            {isRunning && <span className="typing-indicator"><span/><span/><span/></span>}
          </div>
        </div>
        <div className="agent-card-right">
          <span className={`status-dot ${statusDot}`} />
          <span className="status-label">{state.status.toUpperCase()}</span>
        </div>
      </div>

      <div className="agent-card-body">
        <AgentTransparency state={state} meta={meta} />

        <div className="process-title">Live Execution Trace:</div>
        <div className="live-trace-box">
          {hasTrace ? (
            <>
              {state.last_action && <div className="trace-line"><strong>Action:</strong> {state.last_action}</div>}
              {state.last_observation && <div className="trace-line"><strong>Observation:</strong> {cleanObservation(state.last_observation)}</div>}
              {state.thought && <div className="trace-line highlight-thought"><strong>Thought:</strong> {state.thought}</div>}
            </>
          ) : (
            <div className="terminal-loader">
              <span className="prompt">{">"}</span> Awaiting execution trace<span className="cursor">_</span>
            </div>
          )}
        </div>

        {/* PURE FILE TREE OUTPUT */}
        {isDone && state.agent_type === "recon" && repoMap && (
          <div className="recon-output-box">
            <div className="recon-title">
              <span>📁 Architecture Mapped ({repoMap.total_files} files)</span>
            </div>
            <div className="recon-files">
              {Object.entries(buildFileTree(repoMap.files)).map(([name, node]) => (
                <FileTreeNode key={name} name={name} node={node} />
              ))}
            </div>
          </div>
        )}

        {pendingQ.map(q => <HITLCard key={q.question_id} question={q} onAnswer={onAnswer} />)}

        {myQuestions.filter(q => q.status === "answered" || q.status === "HITLStatus.ANSWERED").map(q => (
          <div key={q.question_id} className="hitl-answered">
            <span className="hitl-answered-icon">✓</span>
            <div>
              <div className="hitl-answered-q">{q.question}</div>
              <div className="hitl-answered-a">Human Override: {q.answer}</div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

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
        <span className="hitl-title">Confidence below policy threshold. Awaiting human input.</span>
      </div>
      <p className="hitl-question">{question.question}</p>
      
      {question.context && !question.context.startsWith("{") && (
        <pre className="hitl-code-snippet">{question.context}</pre>
      )}

      {question.options?.length > 0 ? (
        <div className="hitl-options">
          {question.options.map((opt, i) => (
            <button key={i} className="hitl-option" onClick={() => submit(opt)} disabled={loading}>{opt}</button>
          ))}
        </div>
      ) : (
        <div className="hitl-input-row">
          <input className="hitl-input" placeholder="Type your context..." value={answer} onChange={e => setAnswer(e.target.value)} onKeyDown={e => e.key === "Enter" && submit()} autoFocus />
          <button className="hitl-send" onClick={() => submit()} disabled={loading || !answer}>{loading ? "…" : "Confirm"}</button>
        </div>
      )}
    </div>
  );
}

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
            <span className="finding-badge" style={{ background: color + "22", color }}>{f.severity}</span>
            <span className="finding-file">📄 {f.file_path?.split("/").pop() || f.file_path}</span>
            {f.cwe_id && <span className="finding-cwe">{f.cwe_id}</span>}
            {f.owasp && <span className="finding-owasp">{f.owasp}</span>}
          </div>
        </div>
        <span className="finding-toggle">{open ? "▲" : "▼"}</span>
      </div>
      {open && (
        <div className="finding-detail">
          <div className="finding-section"><div className="finding-section-label">Vulnerability Details</div><div className="finding-section-text">{f.description}</div></div>
          {f.evidence && <div className="finding-section"><div className="finding-section-label">Evidence Found</div><pre className="finding-code">{f.evidence}</pre></div>}
          {f.recommendation && <div className="finding-section"><div className="finding-section-label">Remediation</div><div className="finding-section-text">{f.recommendation}</div></div>}
        </div>
      )}
    </div>
  );
}

function ReportCard({ sessionId, visible }) {
  const [report, setReport] = useState(null);
  
  useEffect(() => {
    if (visible) {
      fetch(`${API}/session/${sessionId}/report`).then(r => r.json()).then(d => { if (d.executive_summary) setReport(d); });
    }
  }, [visible, sessionId]);

  if (!visible || !report) return null;
  const riskColor = SEV_COLOR[report.risk_rating] || "#888";

  return (
    <div className="report-card">
      <div className="report-risk" style={{ borderColor: riskColor, color: riskColor }}>OVERALL RISK: {report.risk_rating?.toUpperCase()}</div>
      <p className="report-summary">{report.executive_summary}</p>
      {report.top_recommendations?.length > 0 && (
        <div className="report-recs">
          <div className="report-recs-title">Strategic Remediation Plan</div>
          {report.top_recommendations.map((r, i) => (
            <div key={i} className="report-rec-item">
              <span className="rec-num">{r.priority}</span>
              <div>
                <div className="rec-action">{r.action}</div>
                {r.rationale && <div className="rec-rationale"><strong>Business Impact:</strong> {r.rationale}</div>}
              </div>
            </div>
          ))}
        </div>
      )}
      {report.conclusion && <div className="report-conclusion"><strong>Conclusion:</strong> {report.conclusion}</div>}
    </div>
  );
}

function StartScreen({ onStart }) {
  const [mode, setMode] = useState("upload");
  const [ghUrl, setGhUrl] = useState("");
  const [file, setFile] = useState(null);
  const [policyFile, setPolicyFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function launch() {
    setError(""); setLoading(true);
    try {
      let res;
      const fd = new FormData();
      if (policyFile) fd.append("policy_file", policyFile); // Attach policy to ALL modes

      if (mode === "github") {
        if (!ghUrl.trim()) { setError("Please enter a GitHub URL."); setLoading(false); return; }
        fd.append("github_url", ghUrl.trim());
        res = await fetch(`${API}/analyse/github`, { method: "POST", body: fd });
      } else if (mode === "upload") {
        if (!file) { setError("Please select a codebase .zip file."); setLoading(false); return; }
        fd.append("file", file);
        res = await fetch(`${API}/analyse/upload`, { method: "POST", body: fd });
      }
      
      const data = await res.json();
      if (!res.ok) { setError(data.detail || "Connection failed."); setLoading(false); return; }
      onStart(data.session_id);
    } catch {
      setError("Cannot connect to backend."); setLoading(false);
    }
  }

  return (
    <div className="start-page">
      <div className="start-card">
        <div className="start-logo">
          <div className="logo-hex">⬡</div>
          <div>
            <div className="logo-title">HoneySentinel-OS</div>
            <div className="logo-sub">Multi-Agent Security Intelligence</div>
          </div>
        </div>
        <p className="start-description">
          Provide your codebase. Our AI Agents will map the architecture, semantically search for vulnerabilities, and ask for business context before generating an executive report.
        </p>

        {/* ALWAYS SHOW POLICY UPLOAD AT TOP */}
        <div className="input-group" style={{ marginBottom: '12px' }}>
          <label className="input-label">Custom Security Policy (Optional)</label>
          <div className="file-zone policy-zone" style={{ padding: '12px' }} onClick={() => document.getElementById("policyfile").click()}>
            <div className="file-zone-inner" style={{ flexDirection: 'row', justifyContent: 'center' }}>
              {policyFile ? <><span style={{fontSize:18}}>🛡️</span><span>{policyFile.name}</span></> : <><span style={{fontSize:18}}>📄</span><span>Upload policy.yaml (Uses Universal Default if empty)</span></>}
            </div>
            <input id="policyfile" type="file" accept=".yaml,.yml" style={{ display: "none" }} onChange={e => setPolicyFile(e.target.files[0])} />
          </div>
        </div>

        <label className="input-label">Select Code Source</label>
        <div className="mode-tabs" style={{ marginTop: '4px' }}>
          <button className={`mode-tab ${mode === "upload" ? "active" : ""}`} onClick={() => setMode("upload")}>📦 Upload Code (Zip)</button>
          <button className={`mode-tab ${mode === "github" ? "active" : ""}`} onClick={() => setMode("github")}>🔗 GitHub URL</button>
        </div>

        {mode === "github" && (
          <div className="input-group" style={{ marginTop: '8px' }}>
            <input className="main-input" placeholder="https://github.com/owner/repo" value={ghUrl} onChange={e => setGhUrl(e.target.value)} onKeyDown={e => e.key === "Enter" && launch()} autoFocus />
          </div>
        )}
        
        {mode === "upload" && (
          <div className="input-group" style={{ marginTop: '8px' }}>
            <div className="file-zone" onClick={() => document.getElementById("zipfile").click()}>
              <div className="file-zone-inner">
                {file ? <><span style={{fontSize:24}}>📦</span><span>{file.name}</span></> : <><span style={{fontSize:24}}>⬆️</span><span>Select .zip codebase</span></>}
              </div>
              <input id="zipfile" type="file" accept=".zip" style={{ display: "none" }} onChange={e => setFile(e.target.files[0])} />
            </div>
          </div>
        )}

        {error && <div className="error-banner">{error}</div>}
        <button className="launch-button" onClick={launch} disabled={loading} style={{ marginTop: '8px' }}>
          {loading ? <><div className="btn-spinner" /> Booting Agents...</> : "🚀 Initialize Agentic Analysis"}
        </button>
      </div>
    </div>
  );
}

export default function App() {
  const [sessionId, setSessionId] = useState(null);
  const { agents, findings, questions, repoMap, connected, done } = useSession(sessionId);

  async function handleAnswer(qid, answer) {
    await fetch(`${API}/session/${sessionId}/hitl/${qid}/answer`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ answer }) });
  }

  if (!sessionId) return <StartScreen onStart={setSessionId} />;

  const orchestrator = agents["orchestrator"];
  const subAgents = ["recon", "analysis", "report"].map(type => Object.values(agents).find(a => a.agent_type === type)).filter(Boolean);

  return (
    <div className="app-page">
      <div className="app-header">
        <div className="app-header-left">
          <span className="header-hex">⬡</span>
          <span className="header-title">HoneySentinel-OS</span>
        </div>
        <div className="app-header-center">
          <div className={`conn-dot ${connected ? "green" : "gray"}`} />
          <span className="conn-label">
            {done ? "Analysis Complete" : connected ? "Agents Active" : "Connecting..."}
          </span>
        </div>
        <button className="header-new" onClick={() => setSessionId(null)}>New Session</button>
      </div>

      <div className="main-scroll" style={{ position: 'relative' }}>
        <div className="command-center" style={{ position: 'relative', zIndex: 1 }}>
          
          {/* TOP HUB */}
          {orchestrator ? (
            <div className="orchestrator-hub">
              <AgentCard state={orchestrator} questions={questions} onAnswer={handleAnswer} repoMap={null} />
            </div>
          ) : (
             <div className="waiting-start"><div className="waiting-spinner" /><span>Booting Orchestrator...</span></div>
          )}

          {/* THE NEW SHARED MEMORY VISUAL */}
          {orchestrator && (
            <div className="shared-memory-hub">
              <div className="flow-arrow">⬇ Orchestrator delegates tasks & updates memory</div>
              <div className="memory-database-icon">
                <div className="memory-glow" />
                <span style={{fontSize: '32px', position: 'relative', zIndex: 2}}>🗄️</span>
                <div className="memory-text">
                  <div className="memory-title">Shared Agent Memory</div>
                  <div className="memory-sub">Powered by Azure Cosmos DB</div>
                </div>
              </div>
              <div className="flow-arrow">⬇ Agents read/write to memory asynchronously</div>
            </div>
          )}

          {/* MIDDLE GRID */}
          <div className="agents-grid">
            {subAgents.map((a) => (
              <AgentCard key={a.agent_id} state={a} questions={questions} repoMap={repoMap} onAnswer={handleAnswer} />
            ))}
          </div>

          {/* BOTTOM RESULTS */}
          <div className="results-container">
            {findings.length > 0 && (
              <div className="inline-section flex-1">
                <div className="inline-section-title"><span className="section-icon">🛡</span> Validated Findings</div>
                {findings.map(f => <FindingCard key={f.finding_id} f={f} />)}
              </div>
            )}
            {Object.values(agents).find(a => a.agent_type === "report")?.status === "done" && (
              <div className="inline-section flex-1">
                <div className="inline-section-title"><span className="section-icon">📋</span> Executive Report</div>
                <ReportCard sessionId={sessionId} visible={true} />
              </div>
            )}
          </div>

        </div>
      </div>
    </div>
  );
}
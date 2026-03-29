import { useState, useEffect, useRef } from "react";

const API = "https://honeysentinel-api.redglacier-631cc2e6.centralindia.azurecontainerapps.io"; // Ensure this points to your backend (local or Azure)

function useSession(sessionId) {
  const [agents, setAgents] = useState({});
  const [findings, setFindings] = useState([]);
  const [questions, setQuestions] = useState({});
  const [repoMap, setRepoMap] = useState(null);
  const [connected, setConnected] = useState(false);
  const [done, setDone] = useState(false);

  useEffect(() => {
    if (!sessionId) return;
    
    // Poll every 1 second instead of 2 for better responsiveness during demo
    const interval = setInterval(async () => {
      try {
        const res = await fetch(`${API}/session/${sessionId}`);
        if (!res.ok) return;
        const data = await res.json();
        
        if (data.agent_states) setAgents(data.agent_states);
        if (data.findings) setFindings(data.findings);
        if (data.repo_map) setRepoMap(data.repo_map);
        if (data.hitl) {
          const qMap = {};
          data.hitl.forEach(q => (qMap[q.question_id] = q));
          setQuestions(qMap);
        }
        
        // Don't set 'done' to true to stop polling. 
        // Let it poll forever so the final trace is captured.
        setConnected(true);
      } catch (err) {
        setConnected(false);
      }
    }, 1000);

    return () => clearInterval(interval);
  }, [sessionId]);

  return { agents, findings, questions, repoMap, connected, done };
}


const AGENT_META = {
  orchestrator: { icon: "⚙️", name: "Orchestrator", tools: ["SessionManager", "AgentDelegator"], memory: "Cosmos DB (Session Root)" },
  recon:        { icon: "🗂️", name: "Recon Agent", tools: ["FileScannerTool", "AzureSearchIndexer"], memory: "Cosmos DB (RepoMap)" },
  analysis:     { icon: "🔍", name: "Analysis Agent", tools: ["PatternDetector", "Semgrep", "Pip-Audit", "AzureSearchTool"], memory: "Cosmos DB (Findings)" },
  report:       { icon: "📄", name: "Report Agent", tools: ["RiskSynthesizer"], memory: "Cosmos DB (Read-Only All)" },
};

const SEV_COLOR = { critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#22c55e", info: "#3b82f6" };

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
      <div className="file-tree-item" style={{ paddingLeft: `${padding}px` }}>
        <span className="file-tree-icon">{isFile ? "📄" : "📁"}</span> {name}
      </div>
      {!isFile && Object.entries(node).map(([childName, childNode]) => (
        <FileTreeNode key={childName} name={childName} node={childNode} depth={depth + 1} />
      ))}
    </div>
  );
}

function AgentCard({ state, questions, repoMap, onAnswer }) {
  useEffect(() => {}, [state]); 
  const meta = AGENT_META[state.agent_type] || { icon: "🤖", name: state.agent_type, tools: [], memory: "" };
  const isRunning = state.status === "running";
  const isWaiting = state.status === "waiting_for_human";
  const isDone    = state.status === "done";
  const isFailed  = state.status === "failed";
  
  const [showFullTree, setShowFullTree] = useState(false);
  const [showInternals, setShowInternals] = useState(false);

  const myQuestions = Object.values(questions).filter(q => q.agent_id === state.agent_id);
  const pendingQ    = myQuestions.filter(q => q.status === "pending" || q.status === "HITLStatus.PENDING");
  const statusClass = isRunning ? "running" : isWaiting ? "waiting" : isDone ? "done" : isFailed ? "failed" : "idle";
  const hasTrace = state.last_action || state.last_observation || state.thought;

  return (
    <div className={`agent-card ${statusClass}`} id={`agent-${state.agent_type}`}>
      <div className="agent-card-header">
        <div className="agent-card-left">
          <span className="agent-emoji">{meta.icon}</span>
          <div className="agent-card-name">
            {meta.name}
            {isRunning && <span className="typing-indicator"><span/><span/><span/></span>}
          </div>
        </div>
        <div className={`agent-status-badge ${statusClass}`}>
          <span className="status-dot"></span>
          {state.status.toUpperCase()}
        </div>
      </div>

      <div className="agent-card-body">
        <div className="internals-toggle" onClick={() => setShowInternals(!showInternals)}>
          {showInternals ? "▼ Hide Agent Internals" : "▶ View Agent Internals (Tools & Memory)"}
        </div>
        
        {showInternals && (
          <div className="agent-transparency-panel">
            <div className="t-row"><span className="t-label">Goal:</span> <span className="t-val goal-text">{state.goal}</span></div>
            <div className="t-row mt-2"><span className="t-label">Memory:</span> <span className="t-val">{meta.memory}</span></div>
            <div className="t-row mt-2">
              <span className="t-label">Tools:</span> 
              <div className="tools-list">{meta.tools.map(t => <span key={t} className="tool-badge">{t}</span>)}</div>
            </div>
          </div>
        )}

        <div className="process-title">Live Execution Trace</div>
        <div className="live-trace-box">
          {hasTrace ? (
            <>
              {state.last_action && <div className="trace-line"><span className="trace-label">Action:</span> {state.last_action}</div>}
              {state.last_observation && <div className="trace-line"><span className="trace-label">Observation:</span> {cleanObservation(state.last_observation)}</div>}
              {state.thought && <div className="trace-line highlight-thought"><span className="trace-label">Thought:</span> {state.thought}</div>}
              {/* FIX: Removed the hardcoded [Process Terminated Successfully] line! */}
            </>
          ) : (
            <div className="terminal-loader"><span className="prompt">{">"}</span> Awaiting execution trace<span className="cursor">_</span></div>
          )}
        </div>

        {isDone && state.agent_type === "recon" && repoMap && (
          <div className="recon-output-box">
            <div className="recon-title-row">
              <span className="recon-title-text">📁 Architecture Mapped ({repoMap.total_files} files)</span>
              {repoMap.files.length > 6 && (
                <span className="recon-expand-btn" onClick={() => setShowFullTree(!showFullTree)}>
                  {showFullTree ? "Collapse ▲" : "Expand All ▼"}
                </span>
              )}
            </div>
            <div className="recon-files">
              {Object.entries(buildFileTree(showFullTree ? repoMap.files : repoMap.files.slice(0, 6))).map(([name, node]) => (
                <FileTreeNode key={name} name={name} node={node} />
              ))}
              {!showFullTree && repoMap.files.length > 6 && (
                <div className="recon-hidden-text">...and {repoMap.files.length - 6} more files hidden.</div>
              )}
            </div>
          </div>
        )}

        {pendingQ.map(q => <HITLCard key={q.question_id} question={q} onAnswer={onAnswer} />)}

        {myQuestions.filter(q => q.status === "answered" || q.status === "HITLStatus.ANSWERED").map(q => (
          <div key={q.question_id} className="hitl-answered">
            <span className="hitl-answered-icon">✓</span>
            <div className="hitl-answered-content">
              <div className="hitl-answered-q">{q.question}</div>
              <div className="hitl-answered-a">Human Override: <span className="text-main">{q.answer}</span></div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function HITLCard({ question, onAnswer }) {
  const [answer, setAnswer] = useState("");
  const [submitted, setSubmitted] = useState(false); // Optimistic UI state

  async function submit(ans) {
    setSubmitted(true); // Instantly hide the buttons and show success
    await onAnswer(question.question_id, ans || answer);
  }

  if (submitted) {
    return (
      <div className="hitl-card" style={{borderColor: "var(--low)", background: "rgba(34, 197, 94, 0.05)"}}>
        <div className="hitl-header" style={{color: "var(--low)"}}>
          <span className="hitl-icon">✓</span>
          <span className="hitl-title">Response accepted. Resuming...</span>
        </div>
      </div>
    );
  }

  return (
    <div className="hitl-card">
      <div className="hitl-header">
        <span className="hitl-icon">⚠️</span>
        <span className="hitl-title">Human Input Required</span>
      </div>
      <p className="hitl-question">{question.question}</p>
      
      {question.context && !question.context.startsWith("{") && (
        <div className="hitl-code-wrapper">
          <div className="hitl-code-header">Suspicious Code Snippet</div>
          <pre className="hitl-code-snippet">{question.context}</pre>
        </div>
      )}

      {question.options?.length > 0 ? (
        <div className="hitl-options">
          {question.options.map((opt, i) => (
            <button key={i} className="hitl-option" onClick={() => submit(opt)}>{opt}</button>
          ))}
        </div>
      ) : (
        <div className="hitl-input-row">
          <input className="hitl-input" placeholder="Provide business context..." value={answer} onChange={e => setAnswer(e.target.value)} onKeyDown={e => e.key === "Enter" && submit()} autoFocus />
          <button className="hitl-send" onClick={() => submit()} disabled={!answer}>Confirm</button>
        </div>
      )}
    </div>
  );
}


function FindingCard({ f }) {
  const [open, setOpen] = useState(false);
  const color = SEV_COLOR[f.severity] || "#888";

  return (
    <div className="finding-card" onClick={() => setOpen(!open)}>
      <div className="finding-header">
        <div className="finding-sev-bar" style={{ background: color }} />
        
        <div className="finding-main">
          {/* Top Row: Title + Expand Button */}
          <div className="finding-title-row">
            <span className="finding-title">{f.title || f.rule_id}</span>
            <div className={`chevron-btn ${open ? 'open' : ''}`}>▼</div>
          </div>
          
          {/* Bottom Row: Tags flowing cleanly */}
          <div className="finding-meta-row">
            <span className="finding-badge" style={{ background: `${color}1A`, color: color, border: `1px solid ${color}4D` }}>
              {f.severity.toUpperCase()}
            </span>
            <span className="finding-file">📄 {f.file_path?.split("/").pop() || f.file_path}</span>
            {f.cwe_id && <span className="finding-cwe">{f.cwe_id}</span>}
            {f.owasp && <span className="finding-owasp">{f.owasp}</span>}
          </div>
        </div>
      </div>
      
      {open && (
        <div className="finding-detail">
          <div className="finding-section"><div className="finding-section-label">Details</div><div className="finding-section-text">{f.description}</div></div>
          {f.evidence && <div className="finding-section"><div className="finding-section-label">Evidence Location</div><div className="ide-code-block"><pre className="finding-code">{f.evidence}</pre></div></div>}
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
      <div className="report-header">
        <h3 className="report-title">Executive Security Summary</h3>
        <div className="report-risk-badge" style={{ background: `${riskColor}1A`, color: riskColor, border: `1px solid ${riskColor}4D` }}>
          OVERALL RISK: {report.risk_rating?.toUpperCase()}
        </div>
      </div>
      <p className="report-summary">{report.executive_summary}</p>
      
      {report.top_recommendations?.length > 0 && (
        <div className="report-recs">
          <div className="report-recs-title">Strategic Remediation Plan</div>
          {report.top_recommendations.map((r, i) => (
            <div key={i} className="report-rec-item">
              <div className="rec-num">{r.priority}</div>
              <div>
                <div className="rec-action">{r.action}</div>
                {r.rationale && <div className="rec-rationale"><strong>Impact:</strong> {r.rationale}</div>}
              </div>
            </div>
          ))}
        </div>
      )}
      {report.conclusion && <div className="report-conclusion">{report.conclusion}</div>}
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
  const [hoveredSection, setHoveredSection] = useState(null);

  async function launch() {
    setError(""); setLoading(true);
    try {
      let res;
      if (mode === "github") {
        if (!ghUrl.trim()) { setError("Please enter a GitHub URL."); setLoading(false); return; }
        const fd = new FormData();
        fd.append("github_url", ghUrl.trim());
        if (policyFile) fd.append("policy_file", policyFile);
        res = await fetch(`${API}/analyse/github`, { method: "POST", body: fd });
      } else if (mode === "upload") {
        if (!file) { setError("Please select a codebase .zip file."); setLoading(false); return; }
        const fd = new FormData(); 
        fd.append("file", file);
        if (policyFile) fd.append("policy_file", policyFile);
        res = await fetch(`${API}/analyse/upload`, { method: "POST", body: fd });
      }
      const data = await res.json();
      if (!res.ok) { setError(data.detail || "Connection failed."); setLoading(false); return; }
      onStart(data.session_id);
    } catch {
      setError("Cannot connect to backend server."); setLoading(false);
    }
  }

  return (
    <div className="start-page">
      <div className="clean-navbar">
        <div className="clean-nav-left">
          <div className="clean-shield-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg></div>
          <span className="clean-nav-title">Honey <span className="text-blue">Sentinel</span></span>
        </div>
        <div className="clean-nav-right"><span className="clean-nav-badge">MULTI-AGENT SECURITY</span></div>
      </div>

      <div className="clean-hero">
        <div className="hero-shield"><svg viewBox="0 0 24 24" fill="#38bdf8" stroke="currentColor" strokeWidth="1"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg></div>
        <h1 className="hero-title">Scan Your Codebase</h1>
        <p className="hero-subtitle">AI agents that map your architecture, detect vulnerabilities, <br/>and generate an executive security report — in seconds.</p>

        <div className="clean-input-card">
          <div className="pill-toggle">
            <button className={`pill-btn ${mode === "github" ? "active" : ""}`} onClick={() => setMode("github")}>🔗 GitHub URL</button>
            <button className={`pill-btn ${mode === "upload" ? "active" : ""}`} onClick={() => setMode("upload")}>📦 Upload Zip</button>
          </div>

          <div className="input-group-wrapper" onMouseEnter={() => setHoveredSection('code')} onMouseLeave={() => setHoveredSection(null)}>
            {mode === "github" && (
              <div className="clean-input-wrapper">
                <span className="input-icon">🔗</span>
                <input className="clean-text-input" placeholder="https://github.com/owner/repo" value={ghUrl} onChange={e => setGhUrl(e.target.value)} onKeyDown={e => e.key === "Enter" && launch()} autoFocus />
              </div>
            )}
            {mode === "upload" && (
              <div className="clean-dropzone" onClick={() => document.getElementById("zipfile").click()}>
                {file ? (
                  <div className="dropzone-content active"><span className="drop-icon">📦</span> <span className="drop-text">{file.name}</span></div>
                ) : (
                  <div className="dropzone-content">Drop your <span className="text-blue">.zip</span> here, or <span className="text-blue">browse</span><div className="drop-subtext">Python, JavaScript, TypeScript — up to 50 MB</div></div>
                )}
                <input id="zipfile" type="file" accept=".zip" style={{ display: "none" }} onChange={e => setFile(e.target.files[0])} />
              </div>
            )}
          </div>

          {/* VISIBLE POLICY DROPZONE (No more hidden toggle) */}
          <div className="input-group-wrapper" onMouseEnter={() => setHoveredSection('policy')} onMouseLeave={() => setHoveredSection(null)}>
            <div className="clean-dropzone policy-dropzone" onClick={() => document.getElementById("policyfile").click()}>
              <div className="dropzone-content">
                {policyFile ? <><span className="text-blue">🛡️ {policyFile.name}</span></> : <><strong>Optional:</strong> Attach custom <span className="text-blue">policy.yaml</span><div className="drop-subtext">Uses Universal Default if left empty</div></>}
              </div>
              <input id="policyfile" type="file" accept=".yaml,.yml" style={{ display: "none" }} onChange={e => setPolicyFile(e.target.files[0])} />
            </div>
          </div>

          <button className="clean-submit-btn" onClick={launch} disabled={loading}>{loading ? <span className="btn-spinner"></span> : "🔍 Initialize Agentic Analysis"}</button>
          {error && <div className="clean-error">{error}</div>}
        </div>
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
  const hasActiveHITL = Object.values(questions).some(q => q.status === "pending" || q.status === "HITLStatus.PENDING");

  return (
    <div className={`app-page ${hasActiveHITL ? 'has-hitl' : ''}`}>
      <div className="clean-navbar">
        <div className="clean-nav-left" onClick={() => setSessionId(null)} style={{cursor:'pointer'}}>
          <div className="clean-shield-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg></div>
          <span className="clean-nav-title">Honey <span className="text-blue">Sentinel</span></span>
        </div>
        <div className="clean-nav-right">
          <div className={`conn-indicator ${connected ? "online" : "offline"}`}></div>
          <span className="conn-text">{done ? "Analysis Complete" : hasActiveHITL ? "Human Input Required" : connected ? "Agents Active" : "Connecting..."}</span>
        </div>
      </div>

      <div className="main-dashboard-scroll">
        <div className="command-center">
          
          {/* ORCHESTRATOR HUB */}
          {orchestrator ? (
            <div className="orchestrator-hub">
              <AgentCard state={orchestrator} questions={questions} onAnswer={handleAnswer} repoMap={null} />
            </div>
          ) : (
             <div className="waiting-state"><div className="btn-spinner blue"></div> Booting Orchestrator...</div>
          )}

          {/* SHARED MEMORY HUB */}
          {orchestrator && (
            <div className="shared-memory-hub">
              <div className="flow-line"></div>
              <div className="memory-badge">🗄️ Azure Cosmos DB (Shared Agent Memory)</div>
              <div className="flow-line"></div>
            </div>
          )}

          {/* SUB-AGENTS GRID */}
          <div className="agents-grid">
            {subAgents.map((a) => {
              const agentHasHitl = Object.values(questions).some(q => q.agent_id === a.agent_id && (q.status === "pending" || q.status === "HITLStatus.PENDING"));
              return (
                <div key={a.agent_id} className={`agent-wrapper ${agentHasHitl ? 'hitl-focus' : ''}`}>
                  <AgentCard state={a} questions={questions} repoMap={repoMap} onAnswer={handleAnswer} />
                </div>
              );
            })}
          </div>

          {/* RESULTS SECTION */}
          <div className="results-container">
            {findings.length > 0 && (
              <div className="results-col">
                <h3 className="results-heading">Validated Findings</h3>
                <div className="findings-list">
                  {findings.map(f => <FindingCard key={f.finding_id} f={f} />)}
                </div>
              </div>
            )}
            {Object.values(agents).find(a => a.agent_type === "report")?.status === "done" && (
              <div className="results-col">
                <h3 className="results-heading">Final Report</h3>
                <ReportCard sessionId={sessionId} visible={true} />
              </div>
            )}
          </div>

        </div>
      </div>
    </div>
  );
}
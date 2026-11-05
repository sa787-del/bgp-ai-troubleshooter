import { useCallback, useEffect, useMemo, useState } from 'react';
import './App.css';

const API = (import.meta.env.VITE_API_BASE || 'http://localhost:8000').replace(/\/$/, '');
const NAV = [
  { id: 'investigate', label: 'Investigate', icon: 'pulse' },
  { id: 'sessions', label: 'Sessions', icon: 'network' },
  { id: 'tests', label: 'Test results', icon: 'table' },
  { id: 'rules', label: 'Rule book', icon: 'book' },
  { id: 'settings', label: 'Settings', icon: 'settings' },
];
const TITLES = { investigate: 'BGP investigation', sessions: 'BGP sessions', tests: 'Test results', rules: 'Rule book', settings: 'Router inventory' };

async function request(path, options = {}) {
  const response = await fetch(API + path, options);
  const text = await response.text();
  let data;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  if (!response.ok) {
    const detail = data && typeof data === 'object' && 'detail' in data ? data.detail : undefined;
    const message = typeof detail === 'string' ? detail : detail !== undefined ? JSON.stringify(detail) : (typeof data === 'string' && data) || response.statusText || String(response.status);
    throw new Error(message);
  }
  return data;
}
function isPresent(value) {
  if (value === null || value === undefined) return false;
  if (typeof value === 'string') return value.trim().length > 0;
  if (Array.isArray(value)) return value.length > 0;
  if (typeof value === 'object') return Object.keys(value).length > 0;
  return true;
}
function valueText(value) {
  if (typeof value === 'string') return value;
  if (typeof value === 'object' && value !== null) return JSON.stringify(value, null, 2);
  return String(value);
}
function iconPath(name) {
  const paths = {
    pulse: <path d="M3 12h4l2.2-6 4.2 12 2.1-6H21" />,
    network: <><circle cx="12" cy="5" r="2.2" /><circle cx="5" cy="18" r="2.2" /><circle cx="19" cy="18" r="2.2" /><path d="M10.8 7 6.2 16M13.2 7l4.6 9M7.3 18h9.4" /></>,
    table: <><rect x="3.5" y="4" width="17" height="16" rx="2" /><path d="M3.5 9.5h17M9 9.5V20M15 9.5V20" /></>,
    book: <><path d="M5 4.5h10.5A3.5 3.5 0 0 1 19 8v11.5H8A3 3 0 0 1 5 16.5z" /><path d="M5 16.5A3 3 0 0 1 8 13.5h11M9 8h6" /></>,
    settings: <><circle cx="12" cy="12" r="3" /><path d="m19.4 15 .1.1a1.8 1.8 0 1 1-2.5 2.5l-.1-.1a1.8 1.8 0 0 0-3.1 1.3v.2a1.8 1.8 0 1 1-3.6 0v-.2a1.8 1.8 0 0 0-3.1-1.3l-.1.1a1.8 1.8 0 1 1-2.5-2.5l.1-.1a1.8 1.8 0 0 0-1.3-3.1h-.2a1.8 1.8 0 1 1 0-3.6h.2a1.8 1.8 0 0 0 1.3-3.1l-.1-.1a1.8 1.8 0 1 1 2.5-2.5l.1.1a1.8 1.8 0 0 0 3.1-1.3v-.2a1.8 1.8 0 1 1 3.6 0v.2a1.8 1.8 0 0 0 3.1 1.3l.1-.1a1.8 1.8 0 1 1 2.5 2.5l-.1.1a1.8 1.8 0 0 0 1.3 3.1h.2a1.8 1.8 0 1 1 0 3.6h-.2a1.8 1.8 0 0 0-1.3 3.1z" /></>,
  };
  return paths[name] || null;
}
function Icon({ name, className = '' }) {
  return <svg className={className} viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">{iconPath(name)}</svg>;
}
function StatusDot({ tone = 'neutral' }) { return <span className={'status-dot ' + tone} aria-hidden="true" />; }
function Section({ title, eyebrow, action, className = '', children }) {
  return <section className={'panel ' + className}>{(title || eyebrow || action) && <header className="panel-head"><div>{eyebrow && <p className="eyebrow">{eyebrow}</p>}{title && <h2>{title}</h2>}</div>{action && <div className="panel-action">{action}</div>}</header>}<div className="panel-body">{children}</div></section>;
}
function EmptyState({ children }) { return <div className="empty-state">{children}</div>; }
function ErrorMessage({ children }) { return isPresent(children) ? <div className="error-message" role="alert">{children}</div> : null; }
function Field({ label, value, onChange, type = 'text', required = false, multiline = false, rows = 4 }) {
  const common = { value, onChange: event => onChange(event.target.value), required, autoComplete: 'off' };
  return <label className={'field ' + (multiline ? 'field-wide' : '')}><span>{label}</span>{multiline ? <textarea {...common} rows={rows} /> : <input {...common} type={type} />}</label>;
}
function DataList({ entries, className = '' }) {
  const visible = entries.filter(([, value]) => isPresent(value));
  return visible.length ? <dl className={'data-list ' + className}>{visible.map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{valueText(value)}</dd></div>)}</dl> : null;
}
function OutputDetails({ title, value }) {
  if (!isPresent(value)) return null;
  return <details className="output-details"><summary>{title}</summary><pre>{valueText(value)}</pre></details>;
}
function normaliseHeader(value) { return String(value ?? '').trim().toLowerCase(); }
function parseWorkbookSheet(name, worksheet, XLSX) {
  const rows = XLSX.utils.sheet_to_json(worksheet, { header: 1, raw: false, defval: '', blankrows: false });
  const headerRowIndex = rows.findIndex(row => row.some(cell => normaliseHeader(cell) === 'result'));
  if (headerRowIndex < 0) return null;
  const headers = rows[headerRowIndex].map(cell => String(cell ?? '').trim());
  const resultIndex = headers.findIndex(header => normaliseHeader(header) === 'result');
  const categoryIndex = headers.findIndex(header => normaliseHeader(header) === 'category');
  const runIdIndex = headers.findIndex(header => ['run id', 'run_id', 'run_log_id', 'session id', 'session_id'].includes(normaliseHeader(header)));
  const cases = rows.slice(headerRowIndex + 1).map((values, offset) => ({ id: headerRowIndex + offset + 1, values })).filter(item => item.values.some(isPresent));
  return { name, headers, resultIndex, categoryIndex, runIdIndex, cases };
}
function uniqueColumnValues(sheet, index) {
  if (index < 0) return [];
  return [...new Set(sheet.cases.map(item => item.values[index]).filter(isPresent).map(valueText))];
}

function ToolTrace({ mode, verdict }) {
  const evidence = Array.isArray(verdict.evidence) ? verdict.evidence : [];
  let steps;
  if (mode === 'agent') {
    let evidenceIndex = 0;
    steps = (Array.isArray(verdict.steps) ? verdict.steps : []).map(step => {
      if (step && Object.prototype.hasOwnProperty.call(step, 'rejected')) return { step, evidence: null };
      const item = evidence[evidenceIndex] || null;
      evidenceIndex += 1;
      return { step, evidence: item };
    });
  } else {
    steps = (Array.isArray(verdict.checked) ? verdict.checked : []).map((tool, index) => ({ step: { tool }, evidence: evidence[index] || null }));
  }
  if (!steps.length) return <EmptyState>No investigation steps were returned.</EmptyState>;
  return <ol className="trace-list">{steps.map(({ step, evidence: item }, index) => {
    const rejected = step && Object.prototype.hasOwnProperty.call(step, 'rejected');
    const tool = isPresent(step?.tool) ? step.tool : item?.tool;
    const marker = isPresent(step?.n) ? step.n : <Icon name={rejected ? 'settings' : 'pulse'} />;
    return <li className={'trace-step ' + (rejected ? 'rejected' : '')} key={String(step?.n ?? index) + '-' + String(tool ?? 'step')}>
      <div className="trace-marker">{marker}</div>
      <div className="trace-card">
        <div className="trace-title">{isPresent(tool) && <strong className="mono">{tool}</strong>}{isPresent(step?.summary) && <span>{step.summary}</span>}{rejected && isPresent(step.rejected) && <span className="rejection">{step.rejected}</span>}</div>
        {isPresent(step?.thought) && <p className="trace-thought">{step.thought}</p>}
        {isPresent(item?.error) && <ErrorMessage>{item.error}</ErrorMessage>}
        <OutputDetails title="Parsed data" value={step?.parsed ?? item?.parsed} />
        <OutputDetails title="Raw output" value={step?.raw_output ?? item?.raw_output} />
      </div>
    </li>;
  })}</ol>;
}

function VerdictPanel({ result, onCopyFix, onCopyReport, onRerun, onOpenRun }) {
  const verdict = result.data;
  const triage = verdict.triage;
  const hypotheses = Array.isArray(triage?.hypotheses) ? triage.hypotheses.map(item => item?.fault_class).filter(isPresent) : [];
  const ml = verdict.ml_prediction;
  const mlEntries = [['Label', ml?.label], ['Confidence', ml?.confidence]];
  const usage = verdict.llm_usage;
  return <div className="result-stack">
    {triage && (isPresent(triage.symptom) || hypotheses.length > 0) && <Section eyebrow="Initial read" title="Triage" className="triage-panel"><DataList entries={[['Symptom', triage.symptom], ['Suspects', hypotheses.length ? hypotheses.join(', ') : undefined]]} /></Section>}
    <Section eyebrow="Investigation" title="Tool sequence"><ToolTrace mode={result.mode} verdict={verdict} /></Section>
    {ml && mlEntries.some(([, value]) => isPresent(value)) && <Section eyebrow="Second opinion" title="ML prediction" className="ml-panel"><DataList entries={mlEntries} /></Section>}
    {usage && <Section eyebrow="LLM usage · this analysis" title="Token usage" className="ml-panel">
      {usage.call_count > 0 ? <><DataList entries={[
        ['Model', usage.model], ['LLM calls', usage.call_count], ['Input tokens', usage.input_tokens],
        ['Output tokens', usage.output_tokens], ['Total tokens', usage.total_tokens],
      ]} />{usage.reported_call_count < usage.call_count && <p className="helper-copy">Some provider responses did not report token counts; totals include only reported usage.</p>}</>
        : <p className="helper-copy">No LLM calls were made for this analysis, so token use is 0.</p>}
    </Section>}
    <Section eyebrow="Outcome" title="Verdict" className={verdict.resolved === false ? 'verdict-panel unresolved' : 'verdict-panel'}>
      {verdict.resolved === false && <p className="unresolved-banner">Not resolved</p>}
      <DataList entries={[
        ['Root cause', verdict.root_cause], ['Suggested fix', verdict.suggested_fix], ['Source', verdict.source],
        ['Confidence', verdict.confidence], ['Fault class', verdict.fault_class],
        ['Rules agree', typeof verdict.rules_agree === 'boolean' ? String(verdict.rules_agree) : verdict.rules_agree],
      ]} />
      {Array.isArray(verdict.next_checks) && verdict.next_checks.filter(isPresent).length > 0 && <div className="verdict-list"><h3>Next checks</h3><ul>{verdict.next_checks.filter(isPresent).map((value, index) => <li key={String(index) + valueText(value)}>{valueText(value)}</li>)}</ul></div>}
      {Array.isArray(verdict.notes) && verdict.notes.filter(isPresent).length > 0 && <div className="verdict-list notes-list"><h3>Notes</h3><ul>{verdict.notes.filter(isPresent).map((value, index) => <li key={String(index) + valueText(value)}>{valueText(value)}</li>)}</ul></div>}
    </Section>
    <div className="result-actions">
      {isPresent(verdict.suggested_fix) && <button type="button" className="button button-primary" onClick={() => onCopyFix(verdict.suggested_fix)}>Copy fix</button>}
      <button type="button" className="button button-secondary" onClick={() => onCopyReport(verdict)}>Copy report</button>
      <button type="button" className="button button-secondary" onClick={() => onRerun(result.mode, result.inputs)}>Re-run</button>
      <button type="button" className="button button-secondary" onClick={() => onRerun(result.mode === 'agent' ? 'rules' : 'agent', result.inputs)}>Re-run in {result.mode === 'agent' ? 'Rules' : 'Agent'} mode</button>
      {isPresent(verdict.run_id) && <button type="button" className="button button-quiet" onClick={() => onOpenRun(verdict.run_id)}>Open run log</button>}
    </div>
  </div>;
}

function autoResolveSupport(verdict) {
  if (!verdict?.resolved) return 'The diagnosis is unresolved, so no automatic change is available.';
  if (!isPresent(verdict.run_id)) return 'A real diagnosis run ID is required before preparing a change.';
  if (verdict.fault_class === 'neighbor_passive') {
    const evidence = (verdict.evidence || []).find(item => item.tool === 'config')?.parsed?.peer_passive_check;
    return evidence?.local_passive === true && evidence?.passive === true
      ? '' : 'Both live router configs must confirm passive neighbor statements.';
  }
  if (verdict.fault_class === 'neighbor_shutdown') {
    const evidence = (verdict.evidence || []).find(item => item.tool === 'bgp_neighbor')?.parsed;
    return evidence?.admin_shutdown === true ? '' : 'Live neighbor evidence must confirm an administrative shutdown.';
  }
  if (verdict.fault_class === 'route_filtered') {
    const state = (verdict.evidence || []).find(item => item.tool === 'bgp_state')?.parsed;
    return state?.queried_peer_state === 'Established' && state?.queried_peer_state_reason === 'Policy'
      ? '' : 'Live BGP evidence must confirm this peer is Established with the Policy reason before route-policy resolution is offered.';
  }
  return `No approved automatic remediation is available for ${verdict.fault_class || 'this diagnosis'}.`;
}

function RemediationPanel({ result, state, onStart, onPrepare, onApply, onVerify, onRollback, onConfirm }) {
  const verdict = result.data;
  const unavailable = autoResolveSupport(verdict);
  const plan = state.plan;
  return <Section eyebrow="Optional, allow-listed change" title="Resolve issue" className="remediation-panel">
    {unavailable && <p className="helper-copy">Automatic resolution unavailable: {unavailable}</p>}
    {!unavailable && state.status === 'idle' && <button type="button" className="button button-primary" onClick={() => onStart(verdict)}>Resolve issue</button>}
    {state.status === 'input_required' && <form className="remediation-inputs" onSubmit={event => {
      event.preventDefault();
      const prefixes = state.prefixText.split(/[\s,;]+/).map(value => value.trim()).filter(Boolean);
      onPrepare(verdict.run_id, { prefix_list_name: state.prefixListName, prefixes });
    }}>
      <p>Enter only the IPv4 prefixes you expect to receive from this peer. The plan will create an exact-match inbound allow-list. Nothing changes until you review and confirm the plan.</p>
      <label className="field"><span>Prefix-list name</span><input value={state.prefixListName} onChange={event => onConfirm({ ...state, prefixListName: event.target.value })} required maxLength={32} /></label>
      <label className="field"><span>Approved prefixes, one per line</span><textarea value={state.prefixText} onChange={event => onConfirm({ ...state, prefixText: event.target.value })} rows={4} required /></label>
      <button type="submit" className="button button-primary" disabled={!state.prefixListName.trim() || !state.prefixText.trim()}>Prepare plan</button>
    </form>}
    {state.status === 'preparing' && <div className="loading-inline"><span className="button-spinner" /> Preparing from this run's real evidence</div>}
    {state.error && <ErrorMessage>{state.error}</ErrorMessage>}
    {plan && <div className="remediation-plan">
      <p><strong>{plan.title}</strong></p><p>{plan.expected_effect}</p>
      <DataList entries={[
        ['Run', plan.run_id], ['Fault', plan.fault_class],
        ['Expires in seconds', plan.expires_in_seconds],
        ['Operator inputs', plan.parameters],
        ['Pre-checks', plan.pre_checks], ['Post-checks', plan.post_checks],
      ]} />
      <h3>Affected routers and commands</h3>
      {plan.routers.map((router, index) => <div className="remediation-command" key={router.id}>
        <strong>{router.name} · {router.ip}</strong><pre>{(plan.changes[index] || []).join('\n')}</pre>
        <span>Rollback</span><pre>{(plan.rollback[index] || []).join('\n')}</pre>
      </div>)}
      {state.status === 'prepared' && <>
        <label className="remediation-confirm"><input type="checkbox" checked={state.confirmed} onChange={event => onConfirm(event.target.checked)} /> I reviewed these exact changes and want to apply them.</label>
        <button type="button" className="button button-primary" disabled={!state.confirmed} onClick={() => onApply(plan)}>Apply and verify</button>
      </>}
      {state.status === 'failed' && !state.result && state.confirmed && <button type="button" className="button button-secondary" onClick={() => onApply(plan)}>Retry or check apply status</button>}
      {['applying', 'verifying', 'rolling_back'].includes(state.status) && <div className="loading-inline"><span className="button-spinner" /> {state.status === 'applying' ? 'Applying approved changes' : state.status === 'verifying' ? 'Verifying live BGP state' : 'Rolling back approved changes'}</div>}
      {state.result && <><DataList entries={[
        ['Status', state.result.status], ['Verified', state.result.verified],
        ['Apply results', state.result.results], ['Live checks', state.result.checks],
      ]} />{state.result.error && <ErrorMessage>{state.result.error}</ErrorMessage>}</>}
      {state.status === 'failed' && state.result?.status === 'applied' && <>
        <button type="button" className="button button-secondary" onClick={() => onVerify(plan)}>Retry verification</button>
        <button type="button" className="button button-secondary" onClick={() => onRollback(plan)}>Rollback changes</button>
      </>}
      {['verification_failed', 'partially_applied'].includes(state.status) && <button type="button" className="button button-secondary" onClick={() => onRollback(plan)}>Rollback changes</button>}
      {state.status === 'rollback_failed' && <button type="button" className="button button-secondary" onClick={() => onRollback(plan)}>Retry rollback</button>}
    </div>}
  </Section>;
}

function RuleDetail({ rule, chainIndex }) {
  const tools = Array.isArray(rule.tools) ? rule.tools.filter(tool =>
    isPresent(tool?.display_name) || isPresent(tool?.tool_id) || isPresent(tool?.description) ||
    isPresent(tool?.endpoint) || isPresent(tool?.base_command)
  ) : [];
  return <Section eyebrow={isPresent(chainIndex) ? 'Chain link ' + String(chainIndex + 1) : undefined} title={rule.intent}>
    {tools.length > 0 && <div className="rule-tools"><h3>Tools</h3>{tools.map((tool, index) =>
      <div className="rule-tool" key={String(tool?.tool_id ?? index)}>
        {(isPresent(tool?.display_name) || isPresent(tool?.tool_id)) && <strong>{tool?.display_name || tool?.tool_id}</strong>}
        {isPresent(tool?.description) && <p>{tool.description}</p>}
        <DataList entries={[['Endpoint', tool?.endpoint], ['Base command', tool?.base_command]]} />
      </div>
    )}</div>}
    <DataList entries={[
      ['Symptoms', rule.symptoms],
      ['Likely causes', rule.likely_causes],
      ['Verification', rule.verification],
      ['Next rule on fail', rule.next_intent_on_fail],
    ]} />
  </Section>;
}

function App() {
  const [health, setHealth] = useState({ status: 'checking' });
  const [page, setPage] = useState('investigate');
  const [routers, setRouters] = useState([]);
  const [inventory, setInventory] = useState({ status: 'idle' });
  const [form, setForm] = useState({ question: '', deviceId: '', peer: '', mode: 'agent' });
  const [investigation, setInvestigation] = useState(null);
  const [remediation, setRemediation] = useState({ status: 'idle', confirmed: false });
  const [sessionResults, setSessionResults] = useState({});
  const [ruleCatalog, setRuleCatalog] = useState({ status: 'idle' });
  const [selectedIntent, setSelectedIntent] = useState('');
  const [ruleChain, setRuleChain] = useState({ status: 'idle', rules: [] });
  const [sheets, setSheets] = useState([]);
  const [selectedSheetName, setSelectedSheetName] = useState('');
  const [selectedCase, setSelectedCase] = useState(null);
  const [fileName, setFileName] = useState('');
  const [workbookError, setWorkbookError] = useState('');
  const [workbookLoading, setWorkbookLoading] = useState(false);
  const [categoryFilter, setCategoryFilter] = useState('');
  const [resultFilter, setResultFilter] = useState('');
  const [runsState, setRunsState] = useState({ status: 'idle' });
  const [llmUsage, setLlmUsage] = useState({ status: 'idle' });
  const [runLog, setRunLog] = useState(null);
  const [copyError, setCopyError] = useState('');

  const checkHealth = useCallback(async () => {
    setHealth({ status: 'checking' });
    try {
      const data = await request('/health');
      if (!data || data.status !== 'ok') throw new Error(valueText(data));
      setHealth({ status: 'ready' });
    } catch (error) { setHealth({ status: 'error', error: error.message }); }
  }, []);
  useEffect(() => { checkHealth(); }, [checkHealth]);

  const loadRouters = useCallback(async () => {
    setInventory({ status: 'loading' });
    try {
      const data = await request('/devices');
      const devices = Array.isArray(data?.devices) ? data.devices : [];
      setRouters(devices);
      setInventory({ status: 'ready' });
      setForm(current => {
        const selected = devices.find(device => device.id === current.deviceId) || devices[0];
        if (!selected) return { ...current, deviceId: '', peer: '' };
        const peers = Array.isArray(selected.peers) ? selected.peers : [];
        return { ...current, deviceId: selected.id, peer: current.peer || selected.peer || peers[0] || '' };
      });
    } catch (error) {
      setRouters([]);
      setInventory({ status: 'error', error: error.message });
    }
  }, []);
  useEffect(() => { if (health.status === 'ready') loadRouters(); }, [health.status, loadRouters]);

  const loadSessions = useCallback(async currentRouters => {
    if (!currentRouters.length) { setSessionResults({}); return; }
    setSessionResults(Object.fromEntries(currentRouters.map(router => [router.id, { status: 'loading' }])));
    await Promise.all(currentRouters.map(async router => {
      try {
        const data = await request('/tools/bgp/state', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ host: router.ip || router.host, device_port: router.port }) });
        setSessionResults(current => ({ ...current, [router.id]: { status: 'ready', data } }));
      } catch (error) { setSessionResults(current => ({ ...current, [router.id]: { status: 'error', error: error.message } })); }
    }));
  }, []);
  useEffect(() => { if (health.status === 'ready' && inventory.status === 'ready' && page === 'sessions') loadSessions(routers); }, [health.status, inventory.status, page, routers, loadSessions]);

  const loadRuns = useCallback(async () => {
    setRunsState({ status: 'loading' });
    try {
      const data = await request('/runs');
      setRunsState({ status: 'ready', runs: Array.isArray(data?.runs) ? data.runs : undefined });
    } catch (error) { setRunsState({ status: 'error', error: error.message }); }
  }, []);
  useEffect(() => { if (health.status === 'ready' && page === 'tests') loadRuns(); }, [health.status, page, loadRuns]);

  const loadLlmUsage = useCallback(async () => {
    setLlmUsage({ status: 'loading' });
    try {
      const data = await request('/usage/llm');
      setLlmUsage({ status: 'ready', data });
    } catch (error) { setLlmUsage({ status: 'error', error: error.message }); }
  }, []);
  useEffect(() => { if (health.status === 'ready' && page === 'settings') loadLlmUsage(); }, [health.status, page, loadLlmUsage]);

  useEffect(() => {
    if (health.status !== 'ready' || page !== 'rules') return undefined;
    let alive = true;
    setRuleCatalog({ status: 'loading' });
    request('/rules/catalog').then(data => alive && setRuleCatalog({ status: 'ready', data })).catch(error => alive && setRuleCatalog({ status: 'error', error: error.message }));
    return () => { alive = false; };
  }, [health.status, page]);

  const selectedSheet = sheets.find(sheet => sheet.name === selectedSheetName);
  const categories = useMemo(() => selectedSheet ? uniqueColumnValues(selectedSheet, selectedSheet.categoryIndex) : [], [selectedSheet]);
  const resultOptions = useMemo(() => selectedSheet ? uniqueColumnValues(selectedSheet, selectedSheet.resultIndex) : [], [selectedSheet]);
  const visibleCases = useMemo(() => {
    if (!selectedSheet) return [];
    return selectedSheet.cases.filter(item => {
      const category = selectedSheet.categoryIndex >= 0 ? valueText(item.values[selectedSheet.categoryIndex] ?? '') : '';
      const result = valueText(item.values[selectedSheet.resultIndex] ?? '');
      return (!categoryFilter || category === categoryFilter) && (!resultFilter || result === resultFilter);
    });
  }, [selectedSheet, categoryFilter, resultFilter]);

  const openInvestigation = (router, peer) => {
    setForm(current => ({ ...current, deviceId: router.id, peer }));
    setInvestigation(null);
    setCopyError('');
    setPage('investigate');
  };

  const runDiagnosis = async (mode = form.mode, inputs = form) => {
    const device = routers.find(item => item.id === inputs.deviceId);
    if (!device) { setInvestigation({ status: 'error', mode, error: 'Select a router returned by the backend inventory.' }); return; }
    const submitted = { question: inputs.question, deviceId: device.id, peer: inputs.peer, mode };
    const payload = { question: inputs.question, host: device.ip || device.host, device_port: device.port, peer: inputs.peer, mode };
    setForm(current => ({ ...current, mode }));
    setInvestigation({ status: 'loading', mode });
    setRemediation({ status: 'idle', confirmed: false });
    setCopyError('');
    try {
      const data = await request('/diagnose', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
      setInvestigation({ status: 'ready', mode, inputs: submitted, data });
    } catch (error) { setInvestigation({ status: 'error', mode, error: error.message }); }
  };

  const startRemediation = verdict => {
    if (verdict.fault_class === 'route_filtered') {
      setRemediation({ status: 'input_required', confirmed: false, prefixListName: '', prefixText: '' });
      return;
    }
    prepareRemediation(verdict.run_id);
  };
  const prepareRemediation = async (runId, inputs) => {
    setRemediation({ status: 'preparing', confirmed: false });
    try {
      const plan = await request('/remediation/plans', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ run_id: runId, ...inputs }) });
      setRemediation({ status: 'prepared', plan, confirmed: false });
    } catch (error) { setRemediation({ status: 'idle', error: error.message, confirmed: false }); }
  };
  const verifyRemediation = async plan => {
    setRemediation(current => ({ ...current, status: 'verifying', error: '' }));
    try {
      const body = JSON.stringify({ digest: plan.digest, confirm: true });
      const verified = await request(`/remediation/plans/${encodeURIComponent(plan.plan_id)}/verify`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body });
      setRemediation(current => ({ ...current, status: verified.status, result: verified, error: verified.checks?.find(item => !item.success)?.error || '' }));
    } catch (error) { setRemediation(current => ({ ...current, status: 'failed', error: error.message })); }
  };
  const applyRemediation = async plan => {
    setRemediation(current => ({ ...current, status: 'applying', result: null, error: '' }));
    try {
      const body = JSON.stringify({ digest: plan.digest, confirm: true });
      const applied = await request(`/remediation/plans/${encodeURIComponent(plan.plan_id)}/apply`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body });
      if (applied.status !== 'applied') {
        setRemediation(current => ({ ...current, status: applied.status, result: applied, error: applied.results?.find(item => !item.success)?.error || '' }));
        return;
      }
      setRemediation(current => ({ ...current, status: 'applied', result: applied, error: '' }));
      await verifyRemediation(plan);
    } catch (error) { setRemediation(current => ({ ...current, status: 'failed', error: error.message })); }
  };
  const rollbackRemediation = async plan => {
    setRemediation(current => ({ ...current, status: 'rolling_back', error: '' }));
    try {
      const result = await request(`/remediation/plans/${encodeURIComponent(plan.plan_id)}/rollback`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ digest: plan.digest, confirm: true }) });
      setRemediation(current => ({ ...current, status: result.status, result, error: result.results?.find(item => !item.success)?.error || '' }));
    } catch (error) { setRemediation(current => ({ ...current, status: 'rollback_failed', error: error.message })); }
  };

  const copyText = async value => {
    setCopyError('');
    try { await navigator.clipboard.writeText(value); } catch (error) { setCopyError(error.message); }
  };
  const openRunLog = async id => {
    setRunLog({ id, status: 'loading' });
    try {
      const text = await request('/runs/' + encodeURIComponent(id));
      setRunLog({ id, status: 'ready', text });
    } catch (error) { setRunLog({ id, status: 'error', error: error.message }); }
  };
  const handleWorkbook = async event => {
    const file = event.target.files?.[0];
    if (!file) return;
    setWorkbookLoading(true);
    setWorkbookError('');
    setSheets([]);
    setSelectedSheetName('');
    setSelectedCase(null);
    setFileName('');
    setCategoryFilter('');
    setResultFilter('');
    try {
      if (!file.name.toLowerCase().endsWith('.xlsx')) throw new Error('The selected file is not an .xlsx workbook.');
      const XLSX = await import('xlsx');
      const workbook = XLSX.read(await file.arrayBuffer(), { raw: false });
      const parsed = workbook.SheetNames.map(name => parseWorkbookSheet(name, workbook.Sheets[name], XLSX)).filter(Boolean);
      if (!parsed.length) throw new Error('No worksheet contains a Result column.');
      setSheets(parsed);
      setSelectedSheetName(parsed[0].name);
      setFileName(file.name);
    } catch (error) { setWorkbookError(error.message); }
    finally { setWorkbookLoading(false); event.target.value = ''; }
  };

  const loadRuleChain = async intent => {
    setSelectedIntent(intent);
    setRuleChain({ status: 'loading', rules: [] });
    const chain = [];
    const seen = new Set();
    let current = intent;
    try {
      while (current && !seen.has(current)) {
        seen.add(current);
        const detail = await request('/rules/' + encodeURIComponent(current));
        chain.push(detail);
        current = isPresent(detail?.next_intent_on_fail) ? detail.next_intent_on_fail : '';
      }
      setRuleChain({ status: 'ready', rules: chain });
    } catch (error) { setRuleChain({ status: 'error', error: error.message, rules: chain }); }
  };

  const setCurrentPage = next => {
    setPage(next);
    setCopyError('');
    setSelectedCase(null);
    if (next !== 'tests') { setCategoryFilter(''); setResultFilter(''); }
  };

  if (health.status !== 'ready') return <div className="health-gate">
    <div className="gate-mark"><Icon name="network" /></div>
    {health.status === 'checking'
      ? <><div className="spinner" /><h1>Connecting to the BGP API</h1></>
      : <><StatusDot tone="bad" /><h1>API unavailable</h1><ErrorMessage>{health.error}</ErrorMessage><button type="button" className="button button-primary" onClick={checkHealth}>Retry health check</button></>}
  </div>;

  return <div className="app-shell">
    <aside className="sidebar">
      <div className="brand"><div className="brand-mark"><Icon name="network" /></div><div><strong>NetworkOps</strong><span>BGP troubleshooter</span></div></div>
      <nav className="primary-nav" aria-label="Main navigation">
        {NAV.map(item => <button key={item.id} type="button" className={'nav-item ' + (page === item.id ? 'active' : '')} aria-current={page === item.id ? 'page' : undefined} onClick={() => setCurrentPage(item.id)}><Icon name={item.icon} /><span>{item.label}</span></button>)}
      </nav>
      <div className="sidebar-foot"><div className="api-pill"><StatusDot tone="good" /><span>API connected</span></div><span className="sidebar-foot-note">Local network workspace</span></div>
    </aside>

    <main className="main-area">
      <header className="topbar">
        <div className="breadcrumbs"><span>NetworkOps</span><span className="crumb-separator">/</span><strong>{TITLES[page]}</strong></div>
        <div className="topbar-right"><span className="api-label"><StatusDot tone="good" /> API connected</span><button type="button" className="icon-button" aria-label="Recheck API health" onClick={checkHealth}><span className="refresh-icon">↻</span></button></div>
      </header>
      <div className="page-content">
        <div className="page-heading"><div><p className="eyebrow">Network operations</p><h1>{TITLES[page]}</h1><p className="page-description">
          {page === 'investigate' && 'Describe the BGP issue and inspect evidence returned by the backend.'}
          {page === 'sessions' && 'Live peer state, reason and uptime from each configured router.'}
          {page === 'tests' && 'Review results from the workbook filled during testing.'}
          {page === 'rules' && 'Inspect the rule catalog and follow its escalation chain.'}
          {page === 'settings' && 'Routers and published SSH ports returned by the backend inventory.'}
        </p></div></div>

        {page === 'investigate' && <section className="investigate-layout">
          <Section eyebrow="Start with the incident" title="What went wrong?" className="investigation-form-panel">
            {inventory.status === 'loading' && <div className="loading-inline"><span className="button-spinner" /> Loading router inventory from the backend</div>}
            {inventory.status === 'error' && <ErrorMessage>{inventory.error}</ErrorMessage>}
            {inventory.status === 'ready' && !routers.length && <EmptyState>No routers were returned by GET /devices. Check the backend inventory and Docker Desktop SSH port mappings.</EmptyState>}
            <form className="investigation-form" onSubmit={event => { event.preventDefault(); runDiagnosis(); }}>
              <Field label="Problem" value={form.question} onChange={value => setForm(current => ({ ...current, question: value }))} multiline rows={5} required />
              <div className="field-row">
                <label className="field"><span>Router from Docker inventory</span><select value={form.deviceId} onChange={event => { const selected = routers.find(device => device.id === event.target.value); const peers = Array.isArray(selected?.peers) ? selected.peers : []; setForm(current => ({ ...current, deviceId: event.target.value, peer: selected?.peer || peers[0] || '' })); }} required disabled={!routers.length}><option value="">Select router</option>{routers.map(device => <option key={device.id} value={device.id}>{device.name}{isPresent(device.ip) ? ' · ' + device.ip : ''}</option>)}</select></label>
                <Field label="BGP peer IP" value={form.peer} onChange={value => setForm(current => ({ ...current, peer: value }))} required />
              </div>
              <label className="field mode-field"><span>Investigation mode</span><select value={form.mode} onChange={event => setForm(current => ({ ...current, mode: event.target.value }))}><option value="agent">Agent</option><option value="rules">Rules</option></select></label>
              <div className="form-footer"><span className="form-note"><StatusDot tone="good" /> Ready to investigate</span><button className="button button-primary run-button" type="submit" disabled={investigation?.status === 'loading'}>{investigation?.status === 'loading' ? <><span className="button-spinner" /> Running investigation</> : <>Run investigation <span aria-hidden="true">→</span></>}</button></div>
            </form>
          </Section>
          {investigation?.status === 'error' && <ErrorMessage>{investigation.error}</ErrorMessage>}
          {copyError && <ErrorMessage>{copyError}</ErrorMessage>}
          {investigation?.status === 'loading' && <div className="loading-panel" role="status"><div className="spinner" /><div><strong>Investigation in progress</strong><span>Waiting for the real tool and diagnosis results.</span></div></div>}
          {investigation?.status === 'ready' && <>
            <VerdictPanel result={investigation} onCopyFix={copyText} onCopyReport={verdict => copyText(JSON.stringify(verdict, null, 2))} onRerun={runDiagnosis} onOpenRun={openRunLog} />
            <RemediationPanel result={investigation} state={remediation} onStart={startRemediation} onPrepare={prepareRemediation} onApply={applyRemediation} onVerify={verifyRemediation} onRollback={rollbackRemediation} onConfirm={value => setRemediation(current => typeof value === 'boolean' ? { ...current, confirmed: value } : { ...current, ...value })} />
          </>}
        </section>}

        {page === 'sessions' && <div className="screen-stack">
          <Section eyebrow="Live device checks" title="Docker Desktop routers" action={<button type="button" className="button button-secondary" onClick={() => loadSessions(routers)} disabled={!routers.length || inventory.status === 'loading'}>Refresh sessions</button>}>
            {inventory.status === 'loading' && <div className="loading-inline"><span className="button-spinner" /> Loading router inventory</div>}
            {inventory.status === 'error' && <ErrorMessage>{inventory.error}</ErrorMessage>}
            {inventory.status === 'ready' && !routers.length && <EmptyState>No devices were returned by GET /devices. Check the backend inventory and Docker Desktop SSH port mappings.</EmptyState>}
            {routers.length > 0 && <div className="session-list">{routers.map(router => {
                const state = sessionResults[router.id];
                const data = state?.data;
                const parsed = data?.parsed || {};
                const peers = parsed.peers && typeof parsed.peers === 'object' && !Array.isArray(parsed.peers) ? Object.entries(parsed.peers) : [];
                return <article className="session-card" key={router.id}>
                  <header className="session-head"><div className="router-avatar"><Icon name="network" /></div><div className="session-router"><h3>{router.name}</h3><span className="mono">{router.ip || router.host}</span></div>
                    {state?.status === 'loading' && <span className="session-state"><span className="button-spinner" /> Checking</span>}
                    {state?.status === 'error' && <span className="session-state state-error"><StatusDot tone="bad" /> Error</span>}
                  </header>
                  {state?.status === 'loading' && <div className="session-loading">Reading BGP state from the backend.</div>}
                  {state?.status === 'error' && <ErrorMessage>{state.error}</ErrorMessage>}
                  {state?.status === 'ready' && data?.success === false && <ErrorMessage>{data.error}</ErrorMessage>}
                  {state?.status === 'ready' && data?.success !== false && <>{peers.length ? <div className="peer-list">{peers.map(([peer, peerState]) => {
                    const flagged = isPresent(peerState) && String(peerState).toLowerCase() !== 'established';
                    const reason = parsed.state_reasons?.[peer];
                    const uptime = parsed.uptimes?.[peer];
                    return <div className={'peer-row ' + (flagged ? 'peer-down' : '')} key={peer}>
                      <div className="peer-main">{isPresent(peerState) && <StatusDot tone={flagged ? 'bad' : 'good'} />}{flagged ? <button type="button" className="peer-link mono" onClick={() => openInvestigation(router, peer)}>{peer}</button> : <span className="mono">{peer}</span>}</div>
                      {isPresent(peerState) && <div className="peer-field"><span>State</span><strong className={flagged ? 'text-bad' : 'text-good'}>{valueText(peerState)}</strong></div>}
                      {isPresent(reason) && <div className="peer-field"><span>Reason</span><strong>{valueText(reason)}</strong></div>}
                      {isPresent(uptime) && <div className="peer-field"><span>Uptime</span><strong className="mono">{valueText(uptime)}</strong></div>}
                      {flagged && <button className="button button-quiet investigate-peer" type="button" onClick={() => openInvestigation(router, peer)}>Investigate <span aria-hidden="true">→</span></button>}
                    </div>;
                  })}</div> : <EmptyState>No peer rows were returned.</EmptyState>}<OutputDetails title="Raw output" value={data.raw_output} /></>}
                  {!state && <EmptyState>No BGP state has been loaded.</EmptyState>}
                </article>;
              })}</div>}
          </Section>
        </div>}

        {page === 'tests' && <div className="screen-stack">
          <Section eyebrow="Real recorded outcomes" title="Test workbook">
            <div className="upload-area"><div className="upload-icon"><Icon name="table" /></div><div className="upload-copy"><strong>Upload the completed testbed workbook</strong><span>Choose the .xlsx file filled during testing. It is read in this browser.</span></div><label className="button button-primary upload-button">{workbookLoading ? 'Reading workbook' : 'Choose workbook'}<input type="file" accept=".xlsx" onChange={handleWorkbook} disabled={workbookLoading} /></label></div>
            {fileName && <p className="file-name">{fileName}</p>}
            {workbookError && <ErrorMessage>{workbookError}</ErrorMessage>}
            {workbookLoading && <div className="loading-inline"><span className="button-spinner" /> Reading uploaded workbook</div>}
          </Section>

          {selectedSheet && <>
            <div className="workbook-toolbar">
              <div className="workbook-heading"><span className="eyebrow">Workbook sheet</span>{sheets.length > 1 ? <select className="select-control" value={selectedSheetName} onChange={event => { setSelectedSheetName(event.target.value); setSelectedCase(null); setCategoryFilter(''); setResultFilter(''); }}>{sheets.map(sheet => <option key={sheet.name} value={sheet.name}>{sheet.name}</option>)}</select> : <strong>{selectedSheet.name}</strong>}</div>
              <div className="filter-controls">
                {selectedSheet.categoryIndex >= 0 && <label className="filter-field"><span>Category</span><select className="select-control" value={categoryFilter} onChange={event => setCategoryFilter(event.target.value)}><option value="">All categories</option>{categories.map(value => <option key={value} value={value}>{value}</option>)}</select></label>}
                <label className="filter-field"><span>Result</span><select className="select-control" value={resultFilter} onChange={event => setResultFilter(event.target.value)}><option value="">All results</option>{resultOptions.map(value => <option key={value} value={value}>{value}</option>)}</select></label>
              </div>
            </div>
            <div className="result-summary" aria-label="Workbook result summary">{['Pass', 'Fail', 'Partial', 'Not run'].map(label => {
              const count = selectedSheet.cases.filter(item => valueText(item.values[selectedSheet.resultIndex] ?? '').trim().toLowerCase() === label.toLowerCase()).length;
              return <div className={'summary-item summary-' + label.toLowerCase().replace(' ', '-')} key={label}><span>{label}</span><strong>{count}</strong></div>;
            })}</div>
            <Section eyebrow="Workbook cases" title="Case list">
              {visibleCases.length ? <div className="table-scroll"><table className="case-table"><thead><tr>{selectedSheet.headers.map((header, index) => header ? <th key={header + '-' + index}>{header}</th> : null)}</tr></thead><tbody>{visibleCases.map(item => <tr key={item.id} className={selectedCase?.id === item.id ? 'selected' : ''} onClick={() => setSelectedCase(item)} tabIndex="0" onKeyDown={event => { if (event.key === 'Enter' || event.key === ' ') setSelectedCase(item); }}>{selectedSheet.headers.map((header, index) => header ? <td key={header + '-' + index}>{valueText(item.values[index] ?? '')}</td> : null)}</tr>)}</tbody></table></div> : <EmptyState>No cases match the selected filters.</EmptyState>}
            </Section>
            {selectedCase && <Section eyebrow="Selected workbook row" title="Case details">
              <div className="case-detail-grid">{selectedSheet.headers.map((header, index) => header ? <div className="case-detail-field" key={header + '-' + index}><dt>{header}</dt><dd>{valueText(selectedCase.values[index] ?? '')}</dd></div> : null)}</div>
              {selectedSheet.runIdIndex >= 0 && isPresent(selectedCase.values[selectedSheet.runIdIndex]) && <div className="case-run-action"><button type="button" className="button button-secondary" onClick={() => openRunLog(valueText(selectedCase.values[selectedSheet.runIdIndex]))}>View run</button></div>}
            </Section>}
          </>}

          <Section eyebrow="Backend logs" title="Available run logs" action={<button type="button" className="button button-secondary" onClick={loadRuns} disabled={runsState.status === 'loading'}>{runsState.status === 'loading' ? 'Loading' : 'Refresh logs'}</button>}>
            {runsState.status === 'loading' && <div className="loading-inline"><span className="button-spinner" /> Loading run logs</div>}
            {runsState.status === 'error' && <ErrorMessage>{runsState.error}</ErrorMessage>}
            {runsState.status === 'ready' && Array.isArray(runsState.runs) && runsState.runs.length > 0 && <div className="run-list">{runsState.runs.map(id => <button type="button" className="run-chip mono" key={id} onClick={() => openRunLog(id)}>{id}<span aria-hidden="true">↗</span></button>)}</div>}
            {runsState.status === 'ready' && Array.isArray(runsState.runs) && !runsState.runs.length && <EmptyState>No run logs were returned.</EmptyState>}
            {runsState.status === 'ready' && !Array.isArray(runsState.runs) && <EmptyState>The response did not include a run list.</EmptyState>}
            {runsState.status === 'idle' && <EmptyState>Run logs have not been loaded.</EmptyState>}
          </Section>
        </div>}

        {page === 'rules' && <div className="rules-layout">
          <Section eyebrow="Rules database" title="All rules" className="rule-list-panel">
            {ruleCatalog.status === 'loading' && <div className="loading-inline"><span className="button-spinner" /> Loading rule catalog</div>}
            {ruleCatalog.status === 'error' && <ErrorMessage>{ruleCatalog.error}</ErrorMessage>}
            {ruleCatalog.status === 'ready' && Array.isArray(ruleCatalog.data?.rules) && ruleCatalog.data.rules.length > 0 && <div className="rule-list">{ruleCatalog.data.rules.map((rule, index) => {
              const intent = isPresent(rule?.intent) ? String(rule.intent) : '';
              return <button type="button" key={intent + '-' + String(rule.rule_id ?? index)} className={'rule-row ' + (selectedIntent === intent ? 'selected' : '')} onClick={() => loadRuleChain(intent)}><span className="rule-row-icon"><Icon name="book" /></span><span className="rule-row-copy">{isPresent(intent) && <strong className="mono">{intent}</strong>}{isPresent(rule.symptoms) && <small>{rule.symptoms}</small>}</span><span className="rule-chevron" aria-hidden="true">›</span></button>;
            })}</div>}
            {ruleCatalog.status === 'ready' && (!Array.isArray(ruleCatalog.data?.rules) || !ruleCatalog.data.rules.length) && <EmptyState>No rules were returned.</EmptyState>}
            {ruleCatalog.status === 'idle' && <EmptyState>Rule catalog has not been loaded.</EmptyState>}
          </Section>
          <div className="rule-detail-column">
            {!selectedIntent && <Section eyebrow="Rule details" title="Select a rule"><EmptyState>Choose a rule to view its tools and escalation chain.</EmptyState></Section>}
            {selectedIntent && ruleChain.status === 'loading' && <Section eyebrow={selectedIntent} title="Loading rule"><div className="loading-inline"><span className="button-spinner" /> Loading rule detail</div></Section>}
            {selectedIntent && ruleChain.status === 'error' && <Section eyebrow={selectedIntent} title="Rule detail"><ErrorMessage>{ruleChain.error}</ErrorMessage>{ruleChain.rules.map((rule, index) => <RuleDetail key={rule.intent + '-' + String(index)} rule={rule} chainIndex={index} />)}</Section>}
            {selectedIntent && ruleChain.status === 'ready' && ruleChain.rules.map((rule, index) => <RuleDetail key={rule.intent + '-' + String(index)} rule={rule} chainIndex={index} />)}
          </div>
        </div>}

        {page === 'settings' && <div className="settings-layout">
          <Section eyebrow="GET /usage/llm" title="Cumulative LLM token tracker" action={<button type="button" className="button button-secondary" onClick={loadLlmUsage} disabled={llmUsage.status === 'loading'}>{llmUsage.status === 'loading' ? 'Refreshing' : 'Refresh usage'}</button>}>
            {llmUsage.status === 'loading' && <div className="loading-inline"><span className="button-spinner" /> Summing provider-reported token usage from saved run logs</div>}
            {llmUsage.status === 'error' && <ErrorMessage>{llmUsage.error}</ErrorMessage>}
            {llmUsage.status === 'ready' && <><DataList entries={[
              ['Analyses with LLM calls', llmUsage.data.runs_with_calls], ['LLM calls', llmUsage.data.call_count],
              ['Input tokens', llmUsage.data.input_tokens], ['Output tokens', llmUsage.data.output_tokens],
              ['Total reported tokens', llmUsage.data.total_tokens],
            ]} />{llmUsage.data.reported_call_count < llmUsage.data.call_count && <p className="helper-copy">Some calls have no provider-reported token counts; totals include only calls with reported input and output counts.</p>}
            {llmUsage.data.call_count === 0 && <EmptyState>No LLM response usage has been recorded in the run logs.</EmptyState>}
            {Object.keys(llmUsage.data.calls_by_model || {}).length > 0 && <div className="device-inventory-list">{Object.entries(llmUsage.data.calls_by_model).map(([model, stats]) => <article className="device-inventory-card" key={model}><header><div><h3>{model}</h3></div></header><DataList entries={[["Calls", stats.call_count], ["Input tokens", stats.input_tokens], ["Output tokens", stats.output_tokens], ["Total tokens", stats.total_tokens]]} /></article>)}</div>}</>}
          </Section>
          <Section eyebrow="GET /devices" title="Docker Desktop device inventory" action={<button type="button" className="button button-secondary" onClick={loadRouters} disabled={inventory.status === 'loading'}>{inventory.status === 'loading' ? 'Refreshing' : 'Refresh inventory'}</button>}>
            <p className="helper-copy">Router records come from the backend inventory. The API connects to each router container through its published SSH host and port; device data shown in Sessions comes from live BGP tool responses.</p>
            {inventory.status === 'loading' && <div className="loading-inline"><span className="button-spinner" /> Loading backend inventory</div>}
            {inventory.status === 'error' && <ErrorMessage>{inventory.error}</ErrorMessage>}
            {inventory.status === 'ready' && !routers.length && <EmptyState>No devices were returned by GET /devices.</EmptyState>}
            {routers.length > 0 && <div className="device-inventory-list">{routers.map(device => <article className="device-inventory-card" key={device.id}><header><div className="router-avatar"><Icon name="network" /></div><div><h3>{device.name}</h3>{isPresent(device.id) && <span className="mono">{device.id}</span>}</div></header><DataList entries={[["Management IP", device.ip], ["SSH host", device.host], ["Published SSH port", device.port], ["Platform", device.platform], ["Local AS", device.asn], ["Router ID", device.rid], ["Peers", device.peers], ["Peer", device.peer]]} /></article>)}</div>}
          </Section>
        </div>}
      </div>
    </main>

    {runLog && <div className="modal-backdrop" role="presentation" onClick={event => { if (event.target === event.currentTarget) setRunLog(null); }}>
      <section className="run-modal" role="dialog" aria-modal="true" aria-labelledby="run-modal-title">
        <header className="run-modal-head"><div><p className="eyebrow">Backend run log</p><h2 id="run-modal-title">{runLog.id}</h2></div><button type="button" className="icon-button close-button" aria-label="Close run log" onClick={() => setRunLog(null)}>×</button></header>
        {runLog.status === 'loading' && <div className="modal-state"><span className="spinner" /> Loading the run log</div>}
        {runLog.status === 'error' && <ErrorMessage>{runLog.error}</ErrorMessage>}
        {runLog.status === 'ready' && isPresent(runLog.text) && <pre className="run-log-content">{runLog.text}</pre>}
        {runLog.status === 'ready' && !isPresent(runLog.text) && <EmptyState>The run log is empty.</EmptyState>}
      </section>
    </div>}
  </div>;
}

export default App;









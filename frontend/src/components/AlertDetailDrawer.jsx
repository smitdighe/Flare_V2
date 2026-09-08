import { AnimatePresence, motion } from 'motion/react';
import { useEffect, useRef, useState } from 'react';
import Icon from './Icon.jsx';
import StatusDot, { toneText } from './StatusDot.jsx';
import CyberSelect from './CyberSelect.jsx';

// FE-7: the drawer reads the real `trace[]` array. It used to hardcode three
// provider strings ('GROQ // LLAMA-3.1-8B', 'GEMINI-1.5-FLASH // RAG') and infer
// stage status from field presence, so it could not tell skipped from failed
// from never-ran and its provider labels named models the backend does not call.
// The trace is required, minItems 1, one entry per node in pipeline order
// (CONTRACT §4.0/§8.3) and is rendered AS RECEIVED, without sorting.
const STATUS_STYLE = { ok: { dot: 'border-amber bg-amber', text: 'text-amber', badge: 'bg-amber/15 text-amber' }, failed: { dot: 'border-red bg-red', text: 'text-red', badge: 'bg-red/15 text-red' }, skipped: { dot: 'border-line-strong bg-ink-900', text: 'text-ash-dark', badge: 'bg-ink-950 text-ash-dark' } };
function traceStyle(status) { return STATUS_STYLE[status] || STATUS_STYLE.skipped; }
function providerLabel(entry) { const parts = [entry.provider, entry.model].filter(Boolean); return parts.length ? parts.join(' // ').toUpperCase() : 'NOT ATTRIBUTED'; }
function CopyButton({ value, label, onCopy }) { return <button type="button" className="inline-flex items-center gap-1 text-[10px] text-ash transition-colors hover:text-amber" onClick={() => onCopy(value)}><Icon name="content_copy" size={13} /><span>{label}</span></button>; }
function SectionHeader({ label, open, onToggle, action }) { return <div className="flex items-center justify-between"><button type="button" className="drawer-section-toggle flex items-center gap-2 text-left" onClick={onToggle} aria-expanded={open}><Icon name={open ? 'expand_less' : 'expand_more'} size={15} className="text-amber" /><span className="eyebrow text-ash">{label}</span></button>{action}</div>; }

export default function AlertDetailDrawer({ alert, onClose }) {
  const closeRef = useRef(null);
  const drawerRef = useRef(null);
  const scrollContainerRef = useRef(null);
  const [copied, setCopied] = useState('');
  const [openSections, setOpenSections] = useState({ route: true, pipeline: true, rules: true, mitre: true, explanation: true, action: true });
  const [playbooks, setPlaybooks] = useState([]);
  const [selectedPb, setSelectedPb] = useState('');
  const [queueMsg, setQueueMsg] = useState('');
  const [ruleTrace, setRuleTrace] = useState(null);
  const [ruleTraceLoading, setRuleTraceLoading] = useState(false);

  // Prevent background website from scrolling when mouse is over the sidebar
  useEffect(() => {
    const drawer = drawerRef.current;
    if (!drawer) return;

    let isLocked = false;
    const lockBody = () => {
      if (!isLocked) {
        isLocked = true;
        document.body.style.overflow = 'hidden';
        document.documentElement.style.overflow = 'hidden';
      }
    };

    const unlockBody = () => {
      if (isLocked) {
        isLocked = false;
        document.body.style.overflow = '';
        document.documentElement.style.overflow = '';
      }
    };

    const onPointerEnter = () => lockBody();
    const onPointerLeave = () => unlockBody();

    drawer.addEventListener('pointerenter', onPointerEnter);
    drawer.addEventListener('pointerleave', onPointerLeave);

    // If mouse is already over drawer on mount
    if (drawer.matches(':hover')) {
      lockBody();
    }

    // Forward wheel scroll if user wheels over the non-scrollable header
    const onWheel = (e) => {
      e.stopPropagation();
      const container = scrollContainerRef.current;
      if (container && !container.contains(e.target)) {
        e.preventDefault();
        const multiplier = e.deltaMode === 1 ? 36 : e.deltaMode === 2 ? window.innerHeight : 1;
        container.scrollTop += e.deltaY * multiplier;
      }
    };

    drawer.addEventListener('wheel', onWheel, { passive: false });

    return () => {
      drawer.removeEventListener('pointerenter', onPointerEnter);
      drawer.removeEventListener('pointerleave', onPointerLeave);
      drawer.removeEventListener('wheel', onWheel);
      unlockBody();
    };
  }, [alert]);

  useEffect(() => { if (!alert) return undefined; closeRef.current?.focus(); const onKeyDown = (event) => event.key === 'Escape' && onClose(); window.addEventListener('keydown', onKeyDown); return () => window.removeEventListener('keydown', onKeyDown); }, [alert, onClose]);
  useEffect(() => {
    if (!alert) return;
    const token = localStorage.getItem('flare_token');
    fetch(`${import.meta.env.VITE_API_BASE || ''}/api/v1/playbooks`, { headers: { Authorization: `Bearer ${token}` } })
      .then((r) => r.json())
      .then((d) => {
        const list = d.playbooks || [];
        setPlaybooks(list);
        setSelectedPb(list.length ? String(list[0].id) : '');
      })
      .catch(() => {});
  }, [alert]);
  useEffect(() => {
    if (!alert) return;
    setRuleTraceLoading(true);
    const token = localStorage.getItem('flare_token');
    fetch(`${import.meta.env.VITE_API_BASE || ''}/api/v1/rules/alerts/${alert.id}/explain-rules`, { headers: { Authorization: `Bearer ${token}` } })
      .then((r) => r.json())
      .then((d) => setRuleTrace(d))
      .catch(() => setRuleTrace(null))
      .finally(() => setRuleTraceLoading(false));
  }, [alert]);
  if (!alert) return null;
  const toggle = (key) => setOpenSections((current) => ({ ...current, [key]: !current[key] }));
  const copyValue = async (value) => { try { await navigator.clipboard?.writeText(value); setCopied(value); window.setTimeout(() => setCopied(''), 1400); } catch { setCopied('COPY UNAVAILABLE'); } };
  const handleQueueAction = async () => {
    if (!selectedPb) { setQueueMsg('No playbook selected'); return; }
    setQueueMsg('Queuing...');
    const token = localStorage.getItem('flare_token');
    const res = await fetch(`${import.meta.env.VITE_API_BASE || ''}/api/v1/playbooks/${selectedPb}/execute?alert_id=${encodeURIComponent(alert.id)}`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
    });
    if (res.ok) { setQueueMsg('Action queued — playbook started'); } else { setQueueMsg('Failed to queue action'); }
    window.setTimeout(() => setQueueMsg(''), 3000);
  };
  return (
    <motion.aside
      ref={drawerRef}
      style={{ overscrollBehavior: 'contain' }}
      className="drawer-enter fixed top-4 bottom-4 right-4 z-50 flex h-[calc(100vh-32px)] w-[420px] max-w-[90vw] flex-col overflow-hidden rounded-3xl border border-white/10 bg-white/5 backdrop-blur-3xl shadow-[inset_0_1px_1px_rgba(255,255,255,0.1),-10px_10px_40px_rgba(0,0,0,0.8)] overscroll-contain"
      initial={{ x: '100%', opacity: 0 }}
      animate={{ x: 0, opacity: 1 }}
      exit={{ x: '100%', opacity: 0 }}
      transition={{ type: 'spring', stiffness: 260, damping: 28 }}
      aria-label="Alert evidence drawer"
    >
      <div className="flex-shrink-0 flex items-start justify-between border-b border-line-strong px-5 py-4">
        <div>
          <div className="eyebrow mb-2">SIGNAL EVIDENCE // {alert.id}</div>
          <h2 className="max-w-[300px] text-xl font-semibold leading-tight text-paper">{alert.attack_type?.replaceAll('_', ' ')}</h2>
          <div className="mt-2 flex items-center gap-2 font-mono-ui text-[10px] text-ash">
            <StatusDot tone={alert.severity} pulse={alert.severity === 'critical'} />
            {alert.severity?.toUpperCase()} // {alert.protocol}:{alert.dest_port}
          </div>
        </div>
        <button ref={closeRef} type="button" className="ghost-button flex h-8 w-8 items-center justify-center" onClick={onClose} aria-label="Close evidence drawer">
          <Icon name="close" size={17} />
        </button>
      </div>
      <div ref={scrollContainerRef} style={{ overscrollBehavior: 'contain' }} className="flex-1 min-h-0 overflow-y-auto overscroll-contain drawer-scrollbar">
    <section className="drawer-section border-b border-line px-5 py-4" style={{ '--section-index': 0 }}><SectionHeader label="ROUTE" open={openSections.route} onToggle={() => toggle('route')} action={<div className="flex gap-3"><CopyButton value={alert.src_ip} label="COPY SRC" onCopy={copyValue} /><CopyButton value={alert.dest_ip} label="COPY DST" onCopy={copyValue} /></div>} /><AnimatePresence initial={false}>{openSections.route && <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="overflow-hidden"><div className="mt-3 grid grid-cols-[1fr_auto_1fr] items-center gap-3 font-mono-ui text-sm"><span className="truncate text-paper">{alert.src_ip}</span><span className="text-amber">→</span><span className="truncate text-right text-paper">{alert.dest_ip}</span></div><div className="mt-2 flex justify-between font-mono-ui text-[10px] text-ash-dark"><span>DEST PORT {alert.dest_port}</span><span>{alert.protocol}</span></div>{copied && <div className="mt-3 border-l-2 border-green bg-green/10 px-2 py-1 font-mono-ui text-[10px] text-green">{copied === 'COPY UNAVAILABLE' ? copied : 'COPIED TO CLIPBOARD'}</div>}</motion.div>}</AnimatePresence></section>
    <section className="drawer-section border-b border-line px-5 py-4" style={{ '--section-index': 1 }}><SectionHeader label="PIPELINE TRACE" open={openSections.pipeline} onToggle={() => toggle('pipeline')} /><AnimatePresence initial={false}>{openSections.pipeline && <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="mt-4 overflow-hidden">{alert.degraded && <div className="mb-3 border-l-2 border-red bg-red/10 px-2 py-1 font-mono-ui text-[10px] text-red">DEGRADED — at least one tier did not answer for this alert</div>}<div className="space-y-0">{(alert.trace || []).map((entry, index) => { const style = traceStyle(entry.status); const isLast = index === (alert.trace || []).length - 1; return <div key={entry.node} className="pipeline-stage relative flex gap-3 pb-4 last:pb-0" style={{ '--stage-index': index }} data-complete={entry.status === 'ok'}>{!isLast && <div className="absolute left-[5px] top-3 h-[calc(100%-5px)] w-px bg-line-strong" />}<span className={`relative z-10 mt-0.5 h-3 w-3 border ${style.dot}`} /><div className="min-w-0 flex-1"><div className={`flex items-baseline justify-between font-mono-ui text-[11px] ${style.text}`}><span>{entry.node?.toUpperCase()}</span><span className="flex items-center gap-2"><span className={`px-1 py-0.5 text-[9px] ${style.badge}`}>{entry.status?.toUpperCase()}</span><span>{entry.duration_ms == null ? '—' : `${entry.duration_ms}ms`}</span></span></div><div className="mt-1 text-[10px] text-ash-dark">{providerLabel(entry)}{entry.model_version ? ` // v${entry.model_version}` : ''}{entry.key_id ? ` // ${entry.key_id}` : ''}</div>{entry.tokens && <div className="mt-1 font-mono-ui text-[9px] text-ash-dark">{entry.tokens.prompt} prompt / {entry.tokens.completion} completion tokens</div>}{entry.note && <div className="mt-1.5 border-l-2 border-line-strong pl-2 text-[10px] leading-4 text-ash">{entry.note}</div>}{entry.node === 'enrich' && entry.status === 'ok' && <div className="mt-2 grid grid-cols-2 gap-2 font-mono-ui text-[10px]"><span className="border border-line-strong px-2 py-1 text-ash">ABUSE {alert.ioc_reputation == null ? 'N/A' : `${alert.ioc_reputation}%`}</span><span className="border border-line-strong px-2 py-1 text-ash">VT {alert.vt_ip ? alert.vt_ip.toUpperCase() : 'N/A'}</span></div>}</div></div>; })}</div>{(!alert.trace || alert.trace.length === 0) && <div className="font-mono-ui text-[10px] text-ash-dark">No trace on this alert.</div>}</motion.div>}</AnimatePresence></section>
    <section className="drawer-section border-b border-line px-5 py-4" style={{ '--section-index': 2 }}><SectionHeader label="RULE TRACE // WHY FIRED" open={openSections.rules} onToggle={() => toggle('rules')} /><AnimatePresence initial={false}>{openSections.rules && <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="overflow-hidden">{ruleTraceLoading ? <div className="mt-3 font-mono-ui text-[10px] text-ash-dark">Evaluating rules...</div> : !ruleTrace || !ruleTrace.matched_rules || ruleTrace.matched_rules.length === 0 ? <div className="mt-3 font-mono-ui text-[10px] text-ash-dark">No rules evaluated.</div> : <div className="mt-3 space-y-3">{ruleTrace.matched_rules.map((r) => <div key={r.rule_id} className={`border ${r.fired ? 'border-amber/50 bg-amber/5' : 'border-line-strong'} p-2`}><div className="flex items-center justify-between font-mono-ui text-[10px]"><span className={r.fired ? 'text-amber' : 'text-paper'}>{r.rule_name}</span><span className={`px-1 py-0.5 ${r.fired ? 'bg-amber/15 text-amber' : 'bg-ink-950 text-ash-dark'}`}>{r.fired ? 'FIRED' : 'no match'}</span></div><div className="mt-1 space-y-0.5">{r.conditions.map((c, i) => <div key={i} className="flex items-center gap-2 font-mono-ui text-[9px]"><span className={c.result ? 'text-green' : 'text-red'}>{c.result ? '✓' : '✗'}</span><span className="text-ash">{c.field}</span><span className="text-ash-dark">{c.operator}</span><span className="text-paper">{String(c.expected)}</span><span className="text-ash-dark">— actual:</span><span className={c.result ? 'text-green' : 'text-red'}>{String(c.actual)}</span></div>)}</div></div>)}</div>}</motion.div>}</AnimatePresence></section>
    <section className="drawer-section border-b border-line px-5 py-4" style={{ '--section-index': 3 }}><SectionHeader label="MITRE ATT&CK / TECHNIQUE" open={openSections.mitre} onToggle={() => toggle('mitre')} /><AnimatePresence initial={false}>{openSections.mitre && <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="overflow-hidden"><div className={`mt-3 font-mono-ui text-lg font-semibold ${toneText(alert.severity)}`}>{alert.mitre_technique || 'UNMAPPED'}</div><p className="mt-2 text-xs leading-5 text-ash">The retrieved technique is used to ground the reasoning stage and prioritize the next analyst action.</p></motion.div>}</AnimatePresence></section>
    <section className="drawer-section border-b border-line px-5 py-4" style={{ '--section-index': 4 }}><SectionHeader label="AGENT LOG // EXPLANATION" open={openSections.explanation} onToggle={() => toggle('explanation')} /><AnimatePresence initial={false}>{openSections.explanation && <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="overflow-hidden"><div className="mt-3 border border-line-strong bg-ink-950 p-3 font-mono-ui text-[11px] leading-5 text-ash"><span className="text-amber">// </span>{alert.explanation || 'Awaiting reason stage output.'}</div></motion.div>}</AnimatePresence></section>
    <section className="drawer-section px-5 py-4" style={{ '--section-index': 5 }}><SectionHeader label="RECOMMENDED ACTION" open={openSections.action} onToggle={() => toggle('action')} /><AnimatePresence initial={false}>{openSections.action && <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="overflow-hidden"><p className="mt-3 border-l-2 border-amber bg-amber/5 px-3 py-2 text-xs leading-5 text-paper">{alert.remediation || 'Maintain watch state and await additional evidence.'}</p><div className="mt-3 flex items-center gap-2"><CyberSelect prefix="PLAYBOOK" className="flex-1" value={selectedPb} onChange={(val) => setSelectedPb(val)} placeholder="SELECT PLAYBOOK..." options={playbooks.length === 0 ? [{ value: '', label: 'NO PLAYBOOKS' }] : playbooks.map((pb) => ({ value: pb.id, label: pb.name }))} /><button type="button" className="terminal-button inline-flex items-center gap-2 px-3 py-1.5 font-mono-ui text-[10px] uppercase tracking-[0.08em]" onClick={handleQueueAction}>Queue action <Icon name="arrow_forward" size={14} /></button></div>{queueMsg && <div className="mt-2 font-mono-ui text-[10px] text-amber">{queueMsg}</div>}</motion.div>}</AnimatePresence></section>
      </div>
    </motion.aside>
  );
}

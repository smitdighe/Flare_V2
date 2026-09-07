import { useEffect, useMemo, useState } from "react";
import { AnimatePresence, motion } from "motion/react";
import { CornerDownLeft, Search } from "lucide-react";
import { SECTIONS } from "../../lib/flare-data.js";

const API_BASE = import.meta.env.VITE_API_BASE || "";

// FE-15 (PLAN §3.3 / §3.1, "unified search across source IP, dest IP, alert ID
// and signature"). The alert half of this list used to filter the 200-alert
// browser buffer, so anything the buffer had dropped was unfindable. It now
// searches server-side over the whole alerts table. `GET /metrics/overview`
// answers the header's counters for the same predicate but returns counts, not
// rows, so the rows come from `GET /alerts` — the two share one filter
// implementation on the backend and cannot disagree.
export function CommandPalette({ open, onOpenChange, onNavigate }) {
  const [q, setQ] = useState("");
  const [matches, setMatches] = useState([]);

  useEffect(() => {
    const onKey = (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        onOpenChange(!open);
      }
      if (e.key === "Escape") onOpenChange(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onOpenChange]);

  useEffect(() => {
    if (!open) return undefined;
    let cancelled = false;
    // Debounced: one request per pause in typing, not one per keystroke.
    const timer = setTimeout(async () => {
      try {
        const token = localStorage.getItem("flare_token");
        const params = new URLSearchParams({ limit: "5" });
        const needle = q.trim();
        if (needle) params.set("search", needle);
        const res = await fetch(`${API_BASE}/api/v1/alerts?${params.toString()}`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (!res.ok) return;
        const json = await res.json();
        const rows = (json.data || json)?.alerts;
        if (!cancelled && Array.isArray(rows)) setMatches(rows);
      } catch { /* sections still resolve without the network */ }
    }, 250);
    return () => { cancelled = true; clearTimeout(timer); };
  }, [q, open]);

  const results = useMemo(() => {
    const needle = q.trim().toLowerCase();
    const sections = SECTIONS.filter((s) => s.label.includes(needle)).map((s) => ({
      kind: "section",
      title: s.label,
      sub: s.slug,
      slug: s.slug,
    }));
    const alertResults = matches.map((a) => ({
      kind: "alert",
      title: a.signature,
      sub: `${a.id} // ${a.src_ip}`,
      slug: "feed",
    }));
    return [...sections, ...alertResults];
  }, [q, matches]);

  return (
    <AnimatePresence>
      {open && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          className="fixed inset-0 z-[60] flex items-start justify-center bg-background/75 p-4 pt-24 backdrop-blur-sm"
          onClick={() => onOpenChange(false)}
        >
          <motion.div
            initial={{ y: -18, scale: 0.97 }}
            animate={{ y: 0, scale: 1 }}
            exit={{ y: -18, opacity: 0 }}
            transition={{ type: "spring", stiffness: 320, damping: 26 }}
            onClick={(e) => e.stopPropagation()}
            className="w-full max-w-xl border border-border bg-card shadow-[var(--shadow-panel)]"
          >
            <div className="flex items-center gap-3 border-b border-border px-4 py-3">
              <Search className="h-4 w-4 text-primary" />
              <input
                autoFocus
                value={q}
                onChange={(e) => setQ(e.target.value)}
                placeholder="jump to a section, ip, alert id or signature…"
                className="flex-1 bg-transparent font-mono text-sm outline-none placeholder:text-muted-foreground"
              />
              <span className="mono-label text-[9px]">esc</span>
            </div>
            <div className="max-h-80 overflow-y-auto py-1">
              {results.length === 0 && <div className="mono-label px-4 py-6">no matches</div>}
              {results.map((r, i) => (
                <motion.button
                  key={`${r.kind}-${r.sub}-${i}`}
                  type="button"
                  initial={{ opacity: 0, x: 8 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: i * 0.03 }}
                  onClick={() => {
                    onOpenChange(false);
                    setQ("");
                    onNavigate(r.slug);
                  }}
                  className="group flex w-full items-center gap-3 px-4 py-2.5 text-left hover:bg-accent/50"
                >
                  <span className="mono-label w-16 text-[9px] text-primary">{r.kind}</span>
                  <span className="min-w-0 flex-1">
                    <span className="block truncate font-mono text-xs">{r.title}</span>
                    <span className="mono-label text-[9px]">{r.sub}</span>
                  </span>
                  <CornerDownLeft className="h-3.5 w-3.5 text-muted-foreground opacity-0 transition-opacity group-hover:opacity-100" />
                </motion.button>
              ))}
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}

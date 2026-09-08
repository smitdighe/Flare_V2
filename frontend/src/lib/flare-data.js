export const SEVERITY_STYLES = {
  critical: { text: "text-destructive", bg: "bg-destructive/15", ring: "border-destructive/50" },
  high: { text: "text-primary", bg: "bg-primary/15", ring: "border-primary/50" },
  medium: { text: "text-primary-glow", bg: "bg-primary-glow/10", ring: "border-primary-glow/40" },
  low: { text: "text-signal", bg: "bg-signal/10", ring: "border-signal/40" },
  info: { text: "text-sky-400", bg: "bg-sky-400/15", ring: "border-sky-400/40" },
  unknown: { text: "text-muted-foreground", bg: "bg-muted", ring: "border-border" },
};

export const SECTIONS = [
  { slug: "overview", label: "overview" },
  { slug: "feed", label: "live feed" },
  { slug: "health", label: "health metrics" },
  { slug: "timeline", label: "event velocity" },
  { slug: "audit-logs", label: "audit logs" },
  { slug: "correlated", label: "threat clusters" },
  { slug: "eval", label: "evaluation" },
  { slug: "rules", label: "rules" },
  { slug: "playbooks", label: "playbooks" },
  { slug: "notifications", label: "notifications" },
  { slug: "export", label: "export" },
  { slug: "settings", label: "settings" },
];

// FE-12 (PLAN §3.3, I9). These are the graph's real node names, in the graph's
// own order, and they are the ONLY thing this list carries. The invented
// operators `sentinel-alpha` / `cortex-03` / `sentinel-beta` / `reasoner-01`
// are gone, and so are the loads that sat beside them: a load is a
// measurement, it comes from `GET /metrics/rail`, and there is no honest value
// to render before that response arrives. The panel renders nothing until it
// has one (FE-14).
export const PIPELINE_NODES = ["classify", "enrich", "reason", "rules"];

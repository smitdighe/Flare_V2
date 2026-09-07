import { Link, useLocation } from "react-router-dom";
import { motion } from "motion/react";
import {
  LayoutGrid,
  Radio,
  Activity,
  ScrollText,
  Network,
  Gauge,
  SlidersHorizontal,
  BookOpen,
  Bell,
  Download,
  Flame,
} from "lucide-react";

const ITEMS = [
  { to: "/dashboard", label: "overview", icon: LayoutGrid, exact: true },
  { to: "/dashboard?section=feed", label: "live feed", icon: Radio },
  { to: "/dashboard?section=health", label: "health metrics", icon: Activity },
  { to: "/dashboard?section=timeline", label: "event velocity", icon: Activity },
  { to: "/dashboard?section=audit-logs", label: "audit logs", icon: ScrollText },
  { to: "/dashboard?section=correlated", label: "threat clusters", icon: Network },
  { to: "/dashboard?section=eval", label: "evaluation", icon: Gauge },
  { to: "/dashboard?section=rules", label: "rules", icon: SlidersHorizontal },
  { to: "/dashboard?section=playbooks", label: "playbooks", icon: BookOpen },
  { to: "/dashboard?section=notifications", label: "notifications", icon: Bell },
  { to: "/dashboard?section=export", label: "export", icon: Download },
];

export function DashSidebar({ activeSection, onNavigate }) {
  const location = useLocation();

  return (
    <aside className="fixed bottom-0 left-0 top-14 z-50 hidden w-56 flex-col border-r border-border bg-card/40 backdrop-blur-xl lg:flex">
      <Link to="/dashboard" className="group flex items-center gap-3 border-b border-border px-4 py-4">
        <motion.span
          whileHover={{ rotate: -8, scale: 1.08 }}
          className="flex h-8 w-8 items-center justify-center bg-primary"
          style={{ boxShadow: "var(--shadow-ember)" }}
        >
          <Flame className="h-4 w-4 text-primary-foreground" />
        </motion.span>
        <span className="leading-tight">
          <span className="block font-mono text-xs tracking-[0.2em]">
            FLARE <span className="text-muted-foreground">// OPS</span>
          </span>
          <span className="mono-label text-[9px]">incident command</span>
        </span>
      </Link>

      <div className="border-b border-border px-4 py-4">
        <div className="mono-label text-[9px]">workspace</div>
        <div className="mt-1 font-mono text-xs tracking-wide">THREAT OPERATIONS</div>
        <div className="mono-label mt-1 flex items-center gap-1.5 text-[9px] text-signal">
          <span className="animate-blink h-1.5 w-1.5 rounded-full bg-signal" /> system nominal
        </div>
      </div>

      <nav className="flex flex-1 flex-col gap-0.5 p-2">
        {ITEMS.map((item, i) => {
          const Icon = item.icon;
          const isActive = activeSection === (item.to.split("section=")[1] || "overview");
          return (
            <motion.div
              key={item.to}
              initial={{ opacity: 0, x: -10 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: 0.03 * i, duration: 0.3 }}
            >
              <button
                type="button"
                onClick={() => onNavigate(item.to.split("section=")[1] || "overview")}
                className={`group relative flex w-full items-center gap-3 px-3 py-2.5 font-mono text-[11px] uppercase tracking-[0.16em] transition-colors ${
                  isActive ? "text-primary" : "text-muted-foreground hover:text-foreground"
                }`}
              >
                {isActive && (
                  <motion.span
                    layoutId="nav-active"
                    transition={{ type: "spring", stiffness: 420, damping: 34 }}
                    className="absolute inset-0 border-l-2 border-primary bg-primary/10"
                  />
                )}
                <Icon className="relative h-4 w-4 transition-transform duration-300 group-hover:translate-x-0.5" />
                <span className="relative">{item.label}</span>
              </button>
            </motion.div>
          );
        })}
      </nav>

      <div className="space-y-3 border-t border-border p-4">
        <div className="grid grid-cols-2 gap-2">
          <div>
            <div className="mono-label text-[9px]">queue</div>
            <div className="font-mono text-xs">010 / 200</div>
          </div>
          <div>
            <div className="mono-label text-[9px]">uptime</div>
            <div className="font-mono text-xs text-signal">99.98%</div>
          </div>
        </div>
        <div className="border border-border px-3 py-2">
          <div className="mono-label text-[9px]">build</div>
          <div className="font-mono text-xs">v2.4.0-stable</div>
        </div>
      </div>
    </aside>
  );
}

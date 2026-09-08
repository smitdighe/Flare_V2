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
  Settings,
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
  { to: "/dashboard?section=settings", label: "settings", icon: Settings },
];

export function DashSidebar({ activeSection, onNavigate }) {
  const location = useLocation();

  return (
    <aside className="fixed bottom-0 left-0 top-14 z-50 hidden w-64 flex-col bg-black/75 backdrop-blur-2xl shadow-[12px_0_36px_rgba(0,0,0,0.6)] lg:flex">
      <Link to="/dashboard" className="group flex items-center gap-3.5 px-5 py-4 transition-colors hover:bg-white/[0.02]">
        <motion.div
          whileHover={{ scale: 1.05 }}
          className="flex h-9 w-9 items-center justify-center rounded-xl border border-white/30 bg-gradient-to-br from-white/20 to-white/5 p-1.5 shadow-[0_0_16px_rgba(255,255,255,0.15)]"
        >
          <img src="/flare-logo.png" alt="Flare" className="h-6 w-6 object-contain" />
        </motion.div>
        <div className="leading-tight">
          <div className="flex items-center gap-1.5">
            <span className="font-sans font-bold text-sm tracking-wider text-white">FLARE</span>
            <span className="rounded-md border border-white/10 bg-white/[0.04] px-1.5 py-0.2 text-[9px] font-mono text-zinc-400">OPS</span>
          </div>
          <span className="text-[10px] text-zinc-400 font-sans tracking-wide">incident command</span>
        </div>
      </Link>



      <nav className="flex flex-1 flex-col gap-1 p-2.5 overflow-y-auto">
        {ITEMS.map((item, i) => {
          const Icon = item.icon;
          const isActive = activeSection === (item.to.split("section=")[1] || "overview");
          return (
            <motion.div
              key={item.to}
              initial={{ opacity: 0, x: -8 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: 0.015 * i, duration: 0.2 }}
            >
              <button
                type="button"
                onClick={() => onNavigate(item.to.split("section=")[1] || "overview")}
                className={`group relative flex w-full items-center gap-3 rounded-xl px-3.5 py-2.5 font-sans text-[13px] capitalize transition-all ${
                  isActive
                    ? "text-white font-semibold"
                    : "text-zinc-400 hover:text-white hover:bg-white/[0.04] font-medium"
                }`}
              >
                {isActive && (
                  <motion.span
                    layoutId="nav-active"
                    transition={{ type: "spring", stiffness: 420, damping: 32 }}
                    className="absolute inset-0 rounded-xl border border-white/30 bg-gradient-to-r from-white/15 to-white/5 shadow-[0_0_16px_rgba(255,255,255,0.14)]"
                  />
                )}
                <Icon className="relative h-4 w-4 transition-transform duration-200 group-hover:scale-110" />
                <span className="relative">{item.label}</span>
              </button>
            </motion.div>
          );
        })}
      </nav>

      <div className="space-y-2 border-t border-white/[0.06] p-3.5 bg-white/[0.01]">
        <div className="grid grid-cols-2 gap-2 rounded-xl border border-white/10 bg-white/[0.03] backdrop-blur-md p-2.5 shadow-[inset_0_1px_0_rgba(255,255,255,0.08)]">
          <div>
            <div className="text-[9px] uppercase tracking-wider font-mono text-zinc-500">queue</div>
            <div className="font-mono text-xs text-foreground font-medium mt-0.5">010 / 200</div>
          </div>
          <div>
            <div className="text-[9px] uppercase tracking-wider font-mono text-zinc-500">uptime</div>
            <div className="font-mono text-xs text-emerald-400 font-medium mt-0.5">99.98%</div>
          </div>
        </div>
        <div className="rounded-xl border border-white/10 bg-white/[0.03] backdrop-blur-md px-3 py-2 flex items-center justify-between shadow-[inset_0_1px_0_rgba(255,255,255,0.08)]">
          <span className="text-[9px] uppercase tracking-wider font-mono text-zinc-500">build</span>
          <span className="font-mono text-[11px] text-zinc-400">v2.4.0-stable</span>
        </div>
      </div>
    </aside>
  );
}

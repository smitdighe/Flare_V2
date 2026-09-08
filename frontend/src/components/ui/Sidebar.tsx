import { 
  LayoutDashboard, 
  Radio, 
  Activity, 
  TrendingUp, 
  ScrollText, 
  Network, 
  Gauge, 
  LineChart, 
  SlidersHorizontal, 
  BookOpen, 
  Bell, 
  Settings,
  User,
  Download
} from 'lucide-react';
import type { ReactNode } from 'react';
import { motion } from 'framer-motion';

export type TabId = 
  | 'overview' 
  | 'live_feed' 
  | 'health_metrics' 
  | 'event_velocity' 
  | 'audit_logs' 
  | 'threat_clusters' 
  | 'evaluation' 
  | 'benchmarks' 
  | 'rules' 
  | 'playbooks' 
  | 'notifications' 
  | 'export' 
  | 'settings'
  | 'profile';

interface SidebarProps {
  activeTab: TabId;
  onTabChange: (tab: TabId) => void;
}

export function Sidebar({ activeTab, onTabChange }: SidebarProps) {
  const navItems = [
    { id: 'overview', label: 'Overview', icon: <LayoutDashboard size={16} /> },
    { id: 'live_feed', label: 'Live Feed', icon: <Radio size={16} /> },
    { id: 'health_metrics', label: 'Health Metrics', icon: <Activity size={16} /> },
    { id: 'event_velocity', label: 'Event Velocity', icon: <TrendingUp size={16} /> },
    { id: 'audit_logs', label: 'Audit Logs', icon: <ScrollText size={16} /> },
    { id: 'threat_clusters', label: 'Threat Clusters', icon: <Network size={16} /> },
    { id: 'evaluation', label: 'Evaluation', icon: <Gauge size={16} /> },
    { id: 'benchmarks', label: 'Benchmarks', icon: <LineChart size={16} /> },
    { id: 'rules', label: 'Rules', icon: <SlidersHorizontal size={16} /> },
    { id: 'playbooks', label: 'Playbooks', icon: <BookOpen size={16} /> },
    { id: 'notifications', label: 'Notifications', icon: <Bell size={16} /> },
    { id: 'export', label: 'Export', icon: <Download size={16} /> },
  ];

  return (
    <div className="w-[280px] h-screen flex flex-col pt-5 pb-4 px-4 overflow-y-auto custom-scrollbar select-none">
      
      {/* Navigation Links */}
      <nav className="flex-1 space-y-1">
        {navItems.map((item) => {
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onTabChange(item.id as TabId)}
              className={`w-full flex items-center gap-3 px-4 py-2.5 rounded-2xl transition-all duration-200 group relative cursor-pointer ${
                isActive 
                  ? 'text-white' 
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/30'
              }`}
            >
              {isActive && (
                <motion.div
                  layoutId="activeTabIndicator"
                  className="absolute inset-0 border border-slate-700 bg-slate-800/50 rounded-2xl z-0"
                  initial={false}
                  transition={{ type: "spring", stiffness: 400, damping: 30 }}
                />
              )}
              <span className="relative z-10 flex items-center gap-3 w-full font-sans text-[13px] font-medium tracking-wide">
                <span className={`${isActive ? 'text-white' : 'text-slate-500 group-hover:text-slate-300'}`}>
                  {item.icon}
                </span>
                {item.label}
              </span>
            </button>
          );
        })}
      </nav>

      {/* Footer Profile & Settings */}
      <div className="mt-8 pt-4 border-t border-slate-800/50">
        <div className="flex items-center justify-between">
          <button 
            onClick={() => onTabChange('profile')}
            className={`flex items-center gap-3 p-2 rounded-xl transition-all ${
              activeTab === 'profile' ? 'bg-slate-800/50 border border-slate-700/50' : 'hover:bg-slate-800/30 border border-transparent'
            }`}
          >
            <div className="w-8 h-8 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center text-slate-300 shrink-0">
              <User size={14} />
            </div>
            <div className="text-left flex-1 min-w-0">
              <div className="text-[11px] font-bold text-white truncate">Demo Operative</div>
              <div className="text-[9px] font-mono text-emerald-400">Online</div>
            </div>
          </button>
          
          <button
            onClick={() => onTabChange('settings')}
            className={`p-2.5 rounded-xl transition-all ${
              activeTab === 'settings' ? 'bg-slate-800/50 text-white border border-slate-700/50' : 'text-slate-400 hover:text-white hover:bg-slate-800/30 border border-transparent'
            }`}
          >
            <Settings size={18} />
          </button>
        </div>
      </div>
    </div>
  );
}

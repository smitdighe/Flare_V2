import { motion } from 'framer-motion';
import { Settings, Shield, Bell, Database, Globe } from 'lucide-react';

export function SettingsPanel() {
  const sections = [
    {
      title: 'Global Preferences',
      icon: <Globe size={18} />,
      items: [
        { label: 'Theme Mode', value: 'Tactical Dark' },
        { label: 'Timezone', value: 'UTC' },
        { label: 'Default View', value: 'Live Feed' },
      ]
    },
    {
      title: 'Security & Access',
      icon: <Shield size={18} />,
      items: [
        { label: 'Two-Factor Authentication', value: 'Enabled' },
        { label: 'Session Timeout', value: '30 Minutes' },
        { label: 'API Keys', value: '2 Active' },
      ]
    },
    {
      title: 'Notifications',
      icon: <Bell size={18} />,
      items: [
        { label: 'Email Alerts', value: 'Critical Only' },
        { label: 'Desktop Notifications', value: 'Enabled' },
        { label: 'Digest Frequency', value: 'Daily' },
      ]
    },
    {
      title: 'Data & Integrations',
      icon: <Database size={18} />,
      items: [
        { label: 'Threat Intel Feeds', value: 'AbuseIPDB, VT' },
        { label: 'Retention Period', value: '90 Days' },
        { label: 'Export Format', value: 'JSON/CSV' },
      ]
    }
  ];

  return (
    <div className="w-full max-w-4xl mx-auto h-full flex flex-col">
      <div className="mb-6 flex items-center gap-3">
        <div className="w-10 h-10 rounded-xl bg-slate-900/50 border border-slate-700/50 flex items-center justify-center text-slate-300">
          <Settings size={20} />
        </div>
        <div>
          <h2 className="font-orbitron font-bold text-xl text-white tracking-wider">SYSTEM SETTINGS</h2>
          <p className="text-sm text-slate-400 font-sans">Configure platform parameters and operative preferences</p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {sections.map((section, idx) => (
          <motion.div
            key={section.title}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: idx * 0.1 }}
            className="rounded-xl border border-slate-700/30 bg-slate-900/30 backdrop-blur-md p-5"
          >
            <div className="flex items-center gap-2 mb-4 text-white font-orbitron font-semibold tracking-wide border-b border-slate-800 pb-2">
              <span className="text-slate-400">{section.icon}</span>
              {section.title}
            </div>
            
            <div className="space-y-3">
              {section.items.map((item) => (
                <div key={item.label} className="flex items-center justify-between">
                  <span className="text-sm font-sans text-slate-400">{item.label}</span>
                  <span className="text-sm font-mono text-slate-200 bg-slate-800/50 px-2 py-0.5 rounded border border-slate-700/50">
                    {item.value}
                  </span>
                </div>
              ))}
            </div>
            
            <button className="mt-4 w-full py-2 rounded-lg bg-slate-800/40 hover:bg-slate-700/50 border border-slate-700/50 text-xs font-mono text-slate-300 transition-colors uppercase tracking-wider">
              Configure
            </button>
          </motion.div>
        ))}
      </div>
    </div>
  );
}

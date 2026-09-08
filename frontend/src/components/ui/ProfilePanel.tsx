import { motion } from 'framer-motion';
import { User, Mail, ShieldAlert, KeyRound, Clock, Activity } from 'lucide-react';

export function ProfilePanel() {
  return (
    <div className="w-full max-w-4xl mx-auto h-full flex flex-col">
      <div className="mb-6 flex items-center gap-4">
        <div className="w-16 h-16 rounded-2xl bg-slate-800 border border-slate-600 flex items-center justify-center text-slate-300 shadow-xl">
          <User size={32} />
        </div>
        <div>
          <h2 className="font-orbitron font-bold text-2xl text-white tracking-wider">DEMO OPERATIVE</h2>
          <div className="flex items-center gap-3 mt-1">
            <span className="text-sm text-slate-400 font-mono bg-slate-900/50 px-2 py-0.5 rounded border border-slate-800">
              ID: FLR-OP-9482
            </span>
            <span className="flex items-center gap-1.5 text-xs font-bold text-emerald-400 uppercase tracking-widest bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
              <span className="relative flex h-1.5 w-1.5">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-emerald-500"></span>
              </span>
              Active
            </span>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="rounded-xl border border-slate-700/30 bg-slate-900/30 backdrop-blur-md p-4 flex items-center gap-4"
        >
          <div className="p-3 rounded-lg bg-blue-500/10 text-blue-400 border border-blue-500/20">
            <ShieldAlert size={20} />
          </div>
          <div>
            <div className="text-[10px] font-mono text-slate-500 uppercase tracking-widest">Clearance</div>
            <div className="font-bold text-white tracking-wide">Level 4 (Admin)</div>
          </div>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="rounded-xl border border-slate-700/30 bg-slate-900/30 backdrop-blur-md p-4 flex items-center gap-4"
        >
          <div className="p-3 rounded-lg bg-amber-500/10 text-amber-400 border border-amber-500/20">
            <Activity size={20} />
          </div>
          <div>
            <div className="text-[10px] font-mono text-slate-500 uppercase tracking-widest">Shift Status</div>
            <div className="font-bold text-white tracking-wide">On Duty</div>
          </div>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="rounded-xl border border-slate-700/30 bg-slate-900/30 backdrop-blur-md p-4 flex items-center gap-4"
        >
          <div className="p-3 rounded-lg bg-purple-500/10 text-purple-400 border border-purple-500/20">
            <Clock size={20} />
          </div>
          <div>
            <div className="text-[10px] font-mono text-slate-500 uppercase tracking-widest">Time In</div>
            <div className="font-bold text-white tracking-wide">08:00 UTC</div>
          </div>
        </motion.div>
      </div>

      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.4 }}
        className="rounded-xl border border-slate-700/30 bg-slate-900/30 backdrop-blur-md p-5 flex-1"
      >
        <h3 className="font-orbitron font-semibold text-white tracking-wider border-b border-slate-800 pb-2 mb-4">
          CONTACT & CREDENTIALS
        </h3>
        
        <div className="space-y-4 max-w-lg">
          <div>
            <label className="text-[10px] font-mono text-slate-500 uppercase tracking-widest mb-1 flex items-center gap-1.5">
              <Mail size={12} /> Email Address
            </label>
            <div className="w-full bg-slate-950/50 border border-slate-800 rounded-lg px-3 py-2 text-slate-300 font-mono text-sm">
              operative@flare.dev
            </div>
          </div>
          
          <div>
            <label className="text-[10px] font-mono text-slate-500 uppercase tracking-widest mb-1 flex items-center gap-1.5">
              <KeyRound size={12} /> Access Token
            </label>
            <div className="w-full bg-slate-950/50 border border-slate-800 rounded-lg px-3 py-2 text-slate-500 font-mono text-sm flex justify-between items-center">
              <span>••••••••••••••••••••••••••••</span>
              <button className="text-blue-400 hover:text-blue-300 text-xs font-bold uppercase tracking-wider">Rotate</button>
            </div>
            <p className="text-[10px] text-slate-500 mt-1">Token expires in 12 hours.</p>
          </div>
        </div>
      </motion.div>
    </div>
  );
}

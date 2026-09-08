import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Users, 
  CheckCircle2, 
  Clock, 
  ShieldAlert, 
  Plus, 
  Search, 
  CheckSquare, 
  Square, 
  Lock, 
  Unlock, 
  KeyRound, 
  ArrowRight,
  Shield,
  ChevronDown,
  Filter,
  Check
} from 'lucide-react';
import type { Severity } from '@/types';

export interface TeamMember {
  id: string;
  name: string;
  role: string;
  avatar: string;
  status: 'active' | 'investigating' | 'standby';
  dailyQuota: number;
  completedToday: number;
}

export interface AttackTask {
  id: string;
  alertId: string;
  title: string;
  attackType: string;
  severity: Severity;
  assigneeId: string;
  status: 'todo' | 'in_progress' | 'done';
  srcIp: string;
  targetAsset: string;
  iocScore: number;
  mitreId: string;
  dueTime: string;
  todos: { id: string; text: string; completed: boolean }[];
}

const INITIAL_TEAM: TeamMember[] = [
  { id: 'op_alex', name: 'Alex Carter', role: 'Lead IR', avatar: 'AC', status: 'investigating', dailyQuota: 4, completedToday: 3 },
  { id: 'op_maya', name: 'Maya Lin', role: 'Threat Analyst', avatar: 'ML', status: 'investigating', dailyQuota: 4, completedToday: 2 },
  { id: 'op_david', name: 'David Chen', role: 'Hunter', avatar: 'DC', status: 'active', dailyQuota: 3, completedToday: 3 },
  { id: 'op_sarah', name: 'Sarah Jenkins', role: 'DFIR Specialist', avatar: 'SJ', status: 'investigating', dailyQuota: 4, completedToday: 1 },
  { id: 'op_jordan', name: 'Jordan Reed', role: 'SOC Tier-1', avatar: 'JR', status: 'active', dailyQuota: 3, completedToday: 2 },
];

const INITIAL_TASKS: AttackTask[] = [
  {
    id: 'TSK-101',
    alertId: 'ALT-40918',
    title: 'Cobalt Strike C2 Beaconing Channel',
    attackType: 'malware_c2',
    severity: 'critical',
    assigneeId: 'op_alex',
    status: 'in_progress',
    srcIp: '45.13.2.99',
    targetAsset: 'Prod-DB (192.168.10.50)',
    iocScore: 98,
    mitreId: 'T1071.001',
    dueTime: '35m remaining',
    todos: [
      { id: 'td-1', text: 'Validate VirusTotal positive hashes', completed: true },
      { id: 'td-2', text: 'Isolate endpoint 192.168.10.50 via EDR agent', completed: true },
      { id: 'td-3', text: 'Inject IP block rule into perimeter firewall', completed: false },
      { id: 'td-4', text: 'Capture volatile RAM memory dump', completed: false },
    ],
  },
  {
    id: 'TSK-102',
    alertId: 'ALT-51293',
    title: 'Log4j JNDI Remote Code Execution Probe',
    attackType: 'web_attack',
    severity: 'critical',
    assigneeId: 'op_maya',
    status: 'in_progress',
    srcIp: '194.26.29.112',
    targetAsset: 'Auth-API (192.168.10.12)',
    iocScore: 94,
    mitreId: 'T1190',
    dueTime: '1h 10m remaining',
    todos: [
      { id: 'td-5', text: 'Extract JNDI payload string from Suricata log', completed: true },
      { id: 'td-6', text: 'Verify Java runtime patch status on container', completed: true },
      { id: 'td-7', text: 'Apply hotpatch to log4j library v2.17.1', completed: false },
    ],
  },
  {
    id: 'TSK-103',
    alertId: 'ALT-60421',
    title: 'DNS Tunneling Data Exfiltration',
    attackType: 'data_exfiltration',
    severity: 'critical',
    assigneeId: 'op_sarah',
    status: 'todo',
    srcIp: '104.244.76.13',
    targetAsset: 'Finance-NAS (192.168.10.88)',
    iocScore: 91,
    mitreId: 'T1048.003',
    dueTime: '45m remaining',
    todos: [
      { id: 'td-9', text: 'Analyze TXT record query frequency (>500/min)', completed: false },
      { id: 'td-10', text: 'Sinkhole domain ns1.shadow-c2.net in CoreDNS', completed: false },
      { id: 'td-11', text: 'Audit exfiltrated payload from PCAP flow', completed: false },
    ],
  },
  {
    id: 'TSK-104',
    alertId: 'ALT-38204',
    title: 'Distributed SSH Password Spray Attack',
    attackType: 'brute_force',
    severity: 'high',
    assigneeId: 'op_jordan',
    status: 'todo',
    srcIp: '185.220.101.5',
    targetAsset: 'Bastion-Gateway (192.168.10.25)',
    iocScore: 88,
    mitreId: 'T1110.001',
    dueTime: '2h remaining',
    todos: [
      { id: 'td-12', text: 'Verify failed SSH handshake rate from Tor exit node', completed: false },
      { id: 'td-13', text: 'Add IP to automated Fail2Ban 24h jail', completed: false },
      { id: 'td-14', text: 'Rotate SSH host authorized_keys for admin', completed: false },
    ],
  },
  {
    id: 'TSK-105',
    alertId: 'ALT-29140',
    title: 'PowerShell CLM Bypass & Execution',
    attackType: 'privilege_escalation',
    severity: 'high',
    assigneeId: 'op_david',
    status: 'done',
    srcIp: '172.16.4.12',
    targetAsset: 'Eng-Workstation (192.168.10.105)',
    iocScore: 85,
    mitreId: 'T1059.001',
    dueTime: 'Resolved',
    todos: [
      { id: 'td-15', text: 'De-obfuscate Base64 script in Event ID 4104', completed: true },
      { id: 'td-16', text: 'Apply Constrained Language Mode policy via GPO', completed: true },
      { id: 'td-17', text: 'Confirm zero persistence in registry Run keys', completed: true },
    ],
  },
  {
    id: 'TSK-106',
    alertId: 'ALT-18452',
    title: 'Kerberoasting SPN Ticket Extraction',
    attackType: 'credential_access',
    severity: 'medium',
    assigneeId: 'op_alex',
    status: 'done',
    srcIp: '172.16.2.80',
    targetAsset: 'Domain-Controller (192.168.10.5)',
    iocScore: 62,
    mitreId: 'T1558.003',
    dueTime: 'Resolved',
    todos: [
      { id: 'td-18', text: 'Identify targeted SPN service account', completed: true },
      { id: 'td-19', text: 'Enforce AES256 encryption on Kerberos tickets', completed: true },
      { id: 'td-20', text: 'Reset service account password', completed: true },
    ],
  },
  {
    id: 'TSK-107',
    alertId: 'ALT-77190',
    title: 'SQL Injection on Auth Endpoint',
    attackType: 'web_attack',
    severity: 'high',
    assigneeId: 'op_maya',
    status: 'done',
    srcIp: '91.240.118.2',
    targetAsset: 'Web-App (192.168.10.40)',
    iocScore: 79,
    mitreId: 'T1190',
    dueTime: 'Resolved',
    todos: [
      { id: 'td-21', text: 'Inspect WAF block telemetry on POST payload', completed: true },
      { id: 'td-22', text: 'Verify PostgreSQL query log for syntax errors', completed: true },
      { id: 'td-23', text: 'Confirm parameterized query patch in staging', completed: true },
    ],
  },
  {
    id: 'TSK-108',
    alertId: 'ALT-83021',
    title: 'SYN Stealth Port Reconnaissance',
    attackType: 'port_scan',
    severity: 'low',
    assigneeId: 'op_jordan',
    status: 'done',
    srcIp: '198.51.100.42',
    targetAsset: 'DMZ Subnet (192.168.10.0/24)',
    iocScore: 35,
    mitreId: 'T1046',
    dueTime: 'Resolved',
    todos: [
      { id: 'td-24', text: 'Review dropped SYN packets on DMZ firewall', completed: true },
      { id: 'td-25', text: 'Confirm internal non-public ports remain filtered', completed: true },
    ],
  },
];

export function OverviewPanel() {
  // Passkey Security Gate State
  const [isUnlocked, setIsUnlocked] = useState<boolean>(() => {
    return sessionStorage.getItem('flare_overview_unlocked') === 'true';
  });
  const [passkeyInput, setPasskeyInput] = useState('');
  const [passkeyError, setPasskeyError] = useState(false);

  // Board State
  const [team] = useState<TeamMember[]>(INITIAL_TEAM);
  const [tasks, setTasks] = useState<AttackTask[]>(INITIAL_TASKS);
  const [selectedAssignee, setSelectedAssignee] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [isNewTaskModalOpen, setIsNewTaskModalOpen] = useState(false);

  // New Task Form
  const [newTitle, setNewTitle] = useState('');
  const [newSeverity, setNewSeverity] = useState<Severity>('high');
  const [newAssignee, setNewAssignee] = useState(INITIAL_TEAM[0].id);
  const [newSrcIp, setNewSrcIp] = useState('');
  const [newTarget, setNewTarget] = useState('');
  const [newMitre, setNewMitre] = useState('T1059');

  const handlePasskeySubmit = (e: React.FormEvent) => {
    e.preventDefault();
    // Accept valid passkeys: 'flare2026', 'admin123', 'flare', or any 4+ char key for demo convenience
    if (passkeyInput.trim().length >= 4) {
      setIsUnlocked(true);
      sessionStorage.setItem('flare_overview_unlocked', 'true');
      setPasskeyError(false);
    } else {
      setPasskeyError(true);
    }
  };

  const handleQuickUnlock = () => {
    setIsUnlocked(true);
    sessionStorage.setItem('flare_overview_unlocked', 'true');
  };

  const handleLock = () => {
    setIsUnlocked(false);
    sessionStorage.removeItem('flare_overview_unlocked');
    setPasskeyInput('');
  };

  // Toggle Todo Item
  const toggleTodoItem = (taskId: string, todoId: string) => {
    setTasks((prev) =>
      prev.map((task) => {
        if (task.id !== taskId) return task;
        const updatedTodos = task.todos.map((todo) =>
          todo.id === todoId ? { ...todo, completed: !todo.completed } : todo
        );
        const allCompleted = updatedTodos.every((t) => t.completed);
        return {
          ...task,
          todos: updatedTodos,
          status: allCompleted ? 'done' : task.status === 'done' ? 'in_progress' : task.status,
        };
      })
    );
  };

  const moveTaskStatus = (taskId: string, nextStatus: 'todo' | 'in_progress' | 'done') => {
    setTasks((prev) =>
      prev.map((task) => (task.id === taskId ? { ...task, status: nextStatus } : task))
    );
  };

  const handleCreateTask = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTitle.trim()) return;

    const newTask: AttackTask = {
      id: `TSK-${Math.floor(100 + Math.random() * 900)}`,
      alertId: `ALT-${Math.floor(10000 + Math.random() * 90000)}`,
      title: newTitle,
      attackType: 'malware_c2',
      severity: newSeverity,
      assigneeId: newAssignee,
      status: 'todo',
      srcIp: newSrcIp || '198.51.100.22',
      targetAsset: newTarget || 'Internal Asset',
      iocScore: newSeverity === 'critical' ? 95 : 80,
      mitreId: newMitre || 'T1059',
      dueTime: '2h remaining',
      todos: [
        { id: `td-${Date.now()}-1`, text: 'Perform IOC lookup on AbuseIPDB & VirusTotal', completed: false },
        { id: `td-${Date.now()}-2`, text: 'Verify host network traffic in Suricata logs', completed: false },
        { id: `td-${Date.now()}-3`, text: 'Apply mitigation rule on perimeter firewall', completed: false },
      ],
    };

    setTasks([newTask, ...tasks]);
    setIsNewTaskModalOpen(false);
    setNewTitle('');
    setNewSrcIp('');
    setNewTarget('');
  };

  // Metrics
  const totalTasks = tasks.length;
  const doneTasks = tasks.filter((t) => t.status === 'done').length;
  const inProgressTasks = tasks.filter((t) => t.status === 'in_progress').length;
  const criticalCount = tasks.filter((t) => t.severity === 'critical' && t.status !== 'done').length;
  const completionPercentage = Math.round((doneTasks / totalTasks) * 100);

  const filteredTasks = tasks.filter((task) => {
    const matchesAssignee = selectedAssignee === 'all' || task.assigneeId === selectedAssignee;
    const matchesSearch =
      task.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      task.srcIp.toLowerCase().includes(searchQuery.toLowerCase()) ||
      task.targetAsset.toLowerCase().includes(searchQuery.toLowerCase()) ||
      task.mitreId.toLowerCase().includes(searchQuery.toLowerCase()) ||
      task.alertId.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesAssignee && matchesSearch;
  });

  const todoList = filteredTasks.filter((t) => t.status === 'todo');
  const inProgressList = filteredTasks.filter((t) => t.status === 'in_progress');
  const doneList = filteredTasks.filter((t) => t.status === 'done');

  // ================= 1. SECURITY PASSKEY GATE VIEW =================
  if (!isUnlocked) {
    return (
      <div className="min-h-[520px] flex items-center justify-center p-4">
        <motion.div
          initial={{ opacity: 0, y: 15 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.35 }}
          className="max-w-md w-full p-7 rounded-2xl border border-white/[0.08] bg-[#030712]/70 backdrop-blur-2xl shadow-[0_16px_40px_rgba(0,0,0,0.7)] text-center space-y-5 relative overflow-hidden before:absolute before:inset-x-0 before:top-0 before:h-px before:bg-gradient-to-r before:from-transparent before:via-white/20 before:to-transparent"
        >
          <div className="w-12 h-12 rounded-xl bg-black/50 border border-white/[0.08] flex items-center justify-center mx-auto text-slate-400 shadow-inner">
            <KeyRound size={22} className="text-red-400" />
          </div>

          <div className="space-y-1">
            <h2 className="text-base font-semibold text-white tracking-wide font-syne">SOC Clearance Gate</h2>
            <p className="text-xs text-slate-400">
              Enter security passkey to access incident dispatch board.
            </p>
          </div>

          <form onSubmit={handlePasskeySubmit} className="space-y-4 text-left">
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <label className="text-[11px] font-mono uppercase tracking-wider text-slate-400">
                  Security Passkey
                </label>
                <span className="text-[10px] font-mono text-slate-500">Default: admin123</span>
              </div>
              <input
                type="password"
                value={passkeyInput}
                onChange={(e) => {
                  setPasskeyInput(e.target.value);
                  setPasskeyError(false);
                }}
                placeholder="••••••••"
                className={`w-full bg-black/50 border rounded-lg px-3.5 py-2.5 text-xs font-mono text-white placeholder-slate-600 outline-none transition-colors ${
                  passkeyError ? 'border-red-500/80 focus:border-red-500' : 'border-white/[0.08] focus:border-white/20'
                }`}
                autoFocus
              />
              {passkeyError && (
                <p className="text-[11px] font-mono text-red-400 mt-1.5">
                  Passkey must be at least 4 characters.
                </p>
              )}
            </div>

            <div className="space-y-2 pt-1">
              <button
                type="submit"
                className="w-full py-2.5 bg-gradient-to-r from-red-600/80 to-orange-500/80 hover:from-red-600 hover:to-orange-500 border border-white/15 rounded-lg text-xs font-medium text-white transition-all cursor-pointer flex items-center justify-center gap-2 shadow-[0_0_15px_rgba(239,68,68,0.3)]"
              >
                <span>Authorize &amp; Unlock</span>
                <ArrowRight size={14} />
              </button>

              <button
                type="button"
                onClick={handleQuickUnlock}
                className="w-full py-2 bg-transparent hover:bg-white/[0.04] rounded-lg text-[11px] font-mono text-slate-400 hover:text-slate-300 transition-colors cursor-pointer"
              >
                Quick Demo Unlock
              </button>
            </div>
          </form>
        </motion.div>
      </div>
    );
  }

  // ================= 2. MINIMALIST OVERVIEW BOARD =================
  return (
    <div className="space-y-5 pb-10 font-sans select-none text-slate-200">
      {/* HEADER STRIP: TRANSLUCENT GLASS */}
      <div className="p-4 sm:p-5 rounded-2xl border border-white/[0.07] bg-[#030712]/55 backdrop-blur-xl shadow-[0_8px_32px_rgba(0,0,0,0.6)] flex flex-col sm:flex-row sm:items-center justify-between gap-4 relative overflow-hidden before:absolute before:inset-x-0 before:top-0 before:h-px before:bg-gradient-to-r before:from-transparent before:via-white/15 before:to-transparent">
        <div className="space-y-1">
          <div className="flex items-center gap-2.5">
            <h1 className="text-base sm:text-lg font-semibold text-white tracking-tight">
              Incident Dispatch
            </h1>
            <span className="text-[10px] font-mono px-2.5 py-0.5 rounded-full bg-white/[0.04] border border-white/[0.08] text-slate-300">
              Shift: 08:00 - 16:00 UTC
            </span>
          </div>
          <p className="text-xs text-slate-400 font-normal">
            {doneTasks} of {totalTasks} attacks mitigated ({completionPercentage}%) · {inProgressTasks} active in triage · {criticalCount} critical
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            onClick={() => setIsNewTaskModalOpen(true)}
            className="px-3.5 py-1.5 rounded-xl bg-white/[0.05] hover:bg-white/[0.09] border border-white/[0.1] text-xs font-medium text-white flex items-center gap-1.5 transition-all cursor-pointer backdrop-blur-md shadow-sm"
          >
            <Plus size={14} />
            <span>New Incident</span>
          </button>

          <button
            onClick={handleLock}
            title="Lock Session"
            className="p-2 rounded-xl bg-white/[0.03] hover:bg-white/[0.08] border border-white/[0.07] text-slate-400 hover:text-slate-200 transition-colors cursor-pointer backdrop-blur-md"
          >
            <Lock size={14} />
          </button>
        </div>
      </div>

      {/* FILTER & SEARCH BAR */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
        {/* Operative Filter Tabs */}
        <div className="flex items-center gap-1.5 overflow-x-auto pb-1 md:pb-0 scrollbar-none">
          <button
            onClick={() => setSelectedAssignee('all')}
            className={`px-3 py-1.5 rounded-xl text-xs font-medium transition-all cursor-pointer backdrop-blur-md ${
              selectedAssignee === 'all'
                ? 'bg-white/[0.1] text-white border border-white/20 shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-white/[0.04] border border-transparent'
            }`}
          >
            All Members ({team.length})
          </button>

          {team.map((op) => {
            const opTasks = tasks.filter((t) => t.assigneeId === op.id);
            const opDone = opTasks.filter((t) => t.status === 'done').length;
            const isSelected = selectedAssignee === op.id;

            return (
              <button
                key={op.id}
                onClick={() => setSelectedAssignee(op.id)}
                className={`px-2.5 py-1.5 rounded-xl text-xs transition-all flex items-center gap-1.5 cursor-pointer backdrop-blur-md ${
                  isSelected
                    ? 'bg-white/[0.1] text-white border border-white/20 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-white/[0.04] border border-transparent'
                }`}
              >
                <span className="w-4 h-4 rounded-full bg-black/50 border border-white/[0.1] text-[9px] font-mono text-slate-300 flex items-center justify-center">
                  {op.avatar}
                </span>
                <span>{op.name.split(' ')[0]}</span>
                <span className="text-[10px] text-slate-500 font-mono">
                  {opDone}/{opTasks.length}
                </span>
              </button>
            );
          })}
        </div>

        {/* Search */}
        <div className="relative min-w-[220px]">
          <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search incidents..."
            className="w-full bg-[#030712]/50 backdrop-blur-md border border-white/[0.07] focus:border-white/20 rounded-xl pl-8 pr-3 py-1.5 text-xs text-white placeholder-slate-500 outline-none transition-colors"
          />
        </div>
      </div>

      {/* 3-COLUMN MINIMALIST KANBAN */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 items-start">
        {/* COLUMN 1: TO DO */}
        <div className="space-y-3">
          <div className="flex items-center justify-between px-1 text-xs font-medium text-slate-400">
            <span className="flex items-center gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-slate-500" />
              Backlog
            </span>
            <span className="font-mono text-[11px] text-slate-500">{todoList.length}</span>
          </div>

          <div className="space-y-2.5">
            {todoList.length === 0 ? (
              <div className="p-6 rounded-2xl border border-dashed border-white/[0.06] text-center text-xs text-slate-500 bg-[#030712]/30 backdrop-blur-md">
                No incidents in backlog
              </div>
            ) : (
              todoList.map((task) => (
                <MinimalTaskCard
                  key={task.id}
                  task={task}
                  team={team}
                  onToggleTodo={toggleTodoItem}
                  onMoveStatus={moveTaskStatus}
                />
              ))
            )}
          </div>
        </div>

        {/* COLUMN 2: IN INVESTIGATION */}
        <div className="space-y-3">
          <div className="flex items-center justify-between px-1 text-xs font-medium text-slate-400">
            <span className="flex items-center gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-amber-400" />
              In Investigation
            </span>
            <span className="font-mono text-[11px] text-slate-500">{inProgressList.length}</span>
          </div>

          <div className="space-y-2.5">
            {inProgressList.length === 0 ? (
              <div className="p-6 rounded-2xl border border-dashed border-white/[0.06] text-center text-xs text-slate-500 bg-[#030712]/30 backdrop-blur-md">
                No active investigations
              </div>
            ) : (
              inProgressList.map((task) => (
                <MinimalTaskCard
                  key={task.id}
                  task={task}
                  team={team}
                  onToggleTodo={toggleTodoItem}
                  onMoveStatus={moveTaskStatus}
                />
              ))
            )}
          </div>
        </div>

        {/* COLUMN 3: RESOLVED */}
        <div className="space-y-3">
          <div className="flex items-center justify-between px-1 text-xs font-medium text-slate-400">
            <span className="flex items-center gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
              Resolved
            </span>
            <span className="font-mono text-[11px] text-slate-500">{doneList.length}</span>
          </div>

          <div className="space-y-2.5">
            {doneList.length === 0 ? (
              <div className="p-6 rounded-2xl border border-dashed border-white/[0.06] text-center text-xs text-slate-500 bg-[#030712]/30 backdrop-blur-md">
                No resolved incidents yet
              </div>
            ) : (
              doneList.map((task) => (
                <MinimalTaskCard
                  key={task.id}
                  task={task}
                  team={team}
                  onToggleTodo={toggleTodoItem}
                  onMoveStatus={moveTaskStatus}
                />
              ))
            )}
          </div>
        </div>
      </div>

      {/* CREATE TASK MODAL */}
      <AnimatePresence>
        {isNewTaskModalOpen && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 z-50 bg-black/80 backdrop-blur-xl flex items-center justify-center p-4"
          >
            <motion.div
              initial={{ scale: 0.96, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.96, opacity: 0 }}
              className="max-w-md w-full p-6 rounded-2xl border border-white/[0.09] bg-[#030712]/85 backdrop-blur-2xl shadow-2xl space-y-4 relative overflow-hidden before:absolute before:inset-x-0 before:top-0 before:h-px before:bg-gradient-to-r before:from-transparent before:via-white/20 before:to-transparent"
            >
              <div className="flex items-center justify-between border-b border-white/[0.08] pb-3">
                <h3 className="text-sm font-semibold text-white">Create Incident Task</h3>
                <button
                  onClick={() => setIsNewTaskModalOpen(false)}
                  className="text-slate-500 hover:text-white text-xs cursor-pointer p-1 rounded-md hover:bg-white/[0.05]"
                >
                  ✕
                </button>
              </div>

              <form onSubmit={handleCreateTask} className="space-y-3.5 text-xs">
                <div className="space-y-1">
                  <label className="text-[11px] font-mono text-slate-400">Incident Title</label>
                  <input
                    type="text"
                    value={newTitle}
                    onChange={(e) => setNewTitle(e.target.value)}
                    placeholder="e.g. Cobalt Strike Beaconing Channel"
                    className="w-full bg-black/50 border border-white/[0.08] focus:border-white/20 rounded-xl px-3 py-2 text-white outline-none"
                    required
                  />
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div className="space-y-1">
                    <label className="text-[11px] font-mono text-slate-400">Severity</label>
                    <select
                      value={newSeverity}
                      onChange={(e) => setNewSeverity(e.target.value as Severity)}
                      className="w-full bg-black/50 border border-white/[0.08] focus:border-white/20 rounded-xl px-2.5 py-2 text-white outline-none"
                    >
                      <option value="critical" className="bg-slate-950">Critical</option>
                      <option value="high" className="bg-slate-950">High</option>
                      <option value="medium" className="bg-slate-950">Medium</option>
                      <option value="low" className="bg-slate-950">Low</option>
                    </select>
                  </div>

                  <div className="space-y-1">
                    <label className="text-[11px] font-mono text-slate-400">Assignee</label>
                    <select
                      value={newAssignee}
                      onChange={(e) => setNewAssignee(e.target.value)}
                      className="w-full bg-black/50 border border-white/[0.08] focus:border-white/20 rounded-xl px-2.5 py-2 text-white outline-none"
                    >
                      {team.map((op) => (
                        <option key={op.id} value={op.id} className="bg-slate-950">
                          {op.name}
                        </option>
                      ))}
                    </select>
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div className="space-y-1">
                    <label className="text-[11px] font-mono text-slate-400">Source IP</label>
                    <input
                      type="text"
                      value={newSrcIp}
                      onChange={(e) => setNewSrcIp(e.target.value)}
                      placeholder="185.220.101.5"
                      className="w-full bg-black/50 border border-white/[0.08] focus:border-white/20 rounded-xl px-3 py-2 text-white font-mono outline-none"
                    />
                  </div>
                  <div className="space-y-1">
                    <label className="text-[11px] font-mono text-slate-400">Target Asset</label>
                    <input
                      type="text"
                      value={newTarget}
                      onChange={(e) => setNewTarget(e.target.value)}
                      placeholder="Prod-DB (10.50)"
                      className="w-full bg-black/50 border border-white/[0.08] focus:border-white/20 rounded-xl px-3 py-2 text-white outline-none"
                    />
                  </div>
                </div>

                <div className="flex items-center justify-end gap-2.5 pt-3 border-t border-white/[0.08]">
                  <button
                    type="button"
                    onClick={() => setIsNewTaskModalOpen(false)}
                    className="px-3.5 py-1.5 rounded-xl bg-white/[0.05] hover:bg-white/[0.09] text-xs text-slate-300 transition-colors cursor-pointer"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="px-4 py-1.5 rounded-xl bg-white/[0.1] hover:bg-white/[0.16] border border-white/20 text-xs font-medium text-white transition-colors cursor-pointer shadow-sm"
                  >
                    Create Task
                  </button>
                </div>
              </form>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

// MINIMALIST DARK TRANSLUCENT GLASS TASK CARD
function MinimalTaskCard({
  task,
  team,
  onToggleTodo,
  onMoveStatus,
}: {
  task: AttackTask;
  team: TeamMember[];
  onToggleTodo: (taskId: string, todoId: string) => void;
  onMoveStatus: (taskId: string, nextStatus: 'todo' | 'in_progress' | 'done') => void;
}) {
  const assignee = team.find((op) => op.id === task.assigneeId);
  const completedCount = task.todos.filter((t) => t.completed).length;
  const totalTodos = task.todos.length;

  const severityBadge: Record<Severity, string> = {
    critical: 'bg-red-500/10 text-red-400 border-red-500/30',
    high: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
    medium: 'bg-blue-500/10 text-blue-400 border-blue-500/30',
    low: 'bg-slate-500/10 text-slate-400 border-slate-700',
    info: 'bg-slate-500/10 text-slate-400 border-slate-700',
  };

  return (
    <div className="p-3.5 rounded-2xl border border-white/[0.07] bg-[#030712]/50 backdrop-blur-xl hover:border-white/[0.18] hover:bg-[#030712]/70 transition-all space-y-3 shadow-[0_8px_24px_rgba(0,0,0,0.5)] hover:shadow-[0_12px_32px_rgba(0,0,0,0.7)] relative overflow-hidden before:absolute before:inset-x-0 before:top-0 before:h-px before:bg-gradient-to-r before:from-transparent before:via-white/10 before:to-transparent group">
      {/* Top Header */}
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <span className="text-[10px] font-mono text-slate-500 font-medium">
            {task.alertId}
          </span>
          <span
            className={`text-[9px] font-mono uppercase font-semibold px-1.5 py-0.5 rounded border ${
              severityBadge[task.severity]
            }`}
          >
            {task.severity}
          </span>
        </div>

        <select
          value={task.status}
          onChange={(e) => onMoveStatus(task.id, e.target.value as any)}
          className="bg-black/50 border border-white/[0.08] hover:border-white/20 text-[10px] font-mono text-slate-300 rounded-lg px-2 py-0.5 outline-none cursor-pointer transition-colors"
        >
          <option value="todo" className="bg-slate-950">To Do</option>
          <option value="in_progress" className="bg-slate-950">In Progress</option>
          <option value="done" className="bg-slate-950">Resolved</option>
        </select>
      </div>

      {/* Title & Target Details */}
      <div className="space-y-1">
        <h3 className="text-xs font-medium text-white leading-snug group-hover:text-slate-100 transition-colors">
          {task.title}
        </h3>
        <p className="text-[11px] font-mono text-slate-400 truncate">
          {task.srcIp} &rarr; {task.targetAsset}
        </p>
      </div>

      {/* Checklist Box */}
      <div className="p-2.5 rounded-xl bg-black/40 border border-white/[0.04] space-y-1.5">
        <div className="flex items-center justify-between text-[10px] font-mono text-slate-500">
          <span>Checklist</span>
          <span className="text-slate-400 font-medium">{completedCount}/{totalTodos}</span>
        </div>

        <div className="space-y-1">
          {task.todos.map((todo) => (
            <div
              key={todo.id}
              onClick={() => onToggleTodo(task.id, todo.id)}
              className="flex items-start gap-2 text-xs text-slate-300 hover:text-white cursor-pointer select-none group/item"
            >
              {todo.completed ? (
                <CheckSquare size={13} className="text-emerald-400 shrink-0 mt-0.5" />
              ) : (
                <Square size={13} className="text-slate-600 group-hover/item:text-slate-400 shrink-0 mt-0.5" />
              )}
              <span className={`text-[11px] leading-tight ${todo.completed ? 'line-through text-slate-500' : ''}`}>
                {todo.text}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Footer */}
      <div className="pt-2 border-t border-white/[0.05] flex items-center justify-between text-[11px]">
        <div className="flex items-center gap-1.5">
          <div className="w-4 h-4 rounded-full bg-black/60 border border-white/[0.1] text-[8px] font-mono text-slate-300 flex items-center justify-center">
            {assignee?.avatar || 'OP'}
          </div>
          <span className="text-[10px] text-slate-400">{assignee?.name}</span>
        </div>

        <span className="text-[10px] font-mono text-slate-500">{task.dueTime}</span>
      </div>
    </div>
  );
}


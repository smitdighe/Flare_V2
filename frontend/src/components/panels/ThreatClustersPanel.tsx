import { useState } from 'react';
import { Card3D } from '@/components/ui/Card3D';
import { Network, ShieldAlert, Zap, Globe, Server, ArrowRight, ShieldCheck } from 'lucide-react';

interface ThreatCluster {
  id: string;
  name: string;
  severity: 'critical' | 'high' | 'medium';
  primaryVector: string;
  mitreTechnique: string;
  sourceIps: string[];
  targetSubnet: string;
  alertCount: number;
  maxIocScore: number;
  firstSeen: string;
  lastSeen: string;
  status: 'ACTIVE_CAMPAIGN' | 'CONTAINED' | 'MITIGATED';
  mitigationAdvice: string;
}

const CLUSTERS: ThreatCluster[] = [
  {
    id: 'CLS-8801',
    name: 'Distributed Mirai Variant Recon & Brute',
    severity: 'critical',
    primaryVector: 'Brute Force SSH / Telnet',
    mitreTechnique: 'T1110.001 (Password Guessing)',
    sourceIps: ['185.220.101.5', '185.220.101.9', '185.220.101.42', '194.26.29.112'],
    targetSubnet: '192.168.10.0/24',
    alertCount: 142,
    maxIocScore: 96,
    firstSeen: '25m ago',
    lastSeen: 'Just now',
    status: 'ACTIVE_CAMPAIGN',
    mitigationAdvice: 'Drop ingress TCP port 22/23 from Tor exit subnets and rate-limit SSH handshake to 3 attempts/minute.',
  },
  {
    id: 'CLS-8802',
    name: 'Automated WordPress XML-RPC Exploitation',
    severity: 'high',
    primaryVector: 'Web Attack / Remote Code Execution',
    mitreTechnique: 'T1505.003 (Web Shell)',
    sourceIps: ['172.16.0.1', '103.251.167.20', '45.154.255.87'],
    targetSubnet: '192.168.10.50 (Web Cluster)',
    alertCount: 88,
    maxIocScore: 82,
    firstSeen: '1h 10m ago',
    lastSeen: '4m ago',
    status: 'ACTIVE_CAMPAIGN',
    mitigationAdvice: 'Deploy WAF rule to block xmlrpc.php POST endpoints and sanitize user-agent strings matching curl/python-requests.',
  },
  {
    id: 'CLS-8803',
    name: 'Stealth SYN/ACK Port Scan Sweep',
    severity: 'medium',
    primaryVector: 'Reconnaissance / Network Sweep',
    mitreTechnique: 'T1046 (Network Service Discovery)',
    sourceIps: ['89.248.165.12', '89.248.165.74'],
    targetSubnet: '192.168.10.0/24 (DMZ Gateway)',
    alertCount: 460,
    maxIocScore: 48,
    firstSeen: '3h ago',
    lastSeen: '12m ago',
    status: 'CONTAINED',
    mitigationAdvice: 'Automated SYN cookie enabled; source CIDR 89.248.165.0/24 blackholed at border gateway.',
  },
];

export function ThreatClustersPanel() {
  const [selectedCluster, setSelectedCluster] = useState<ThreatCluster>(CLUSTERS[0]);
  const [containedIds, setContainedIds] = useState<Set<string>>(new Set());

  const handleContain = (id: string) => {
    setContainedIds((prev) => new Set([...prev, id]));
  };

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between gap-4 flex-wrap pb-2 border-b border-edge/60">
        <div>
          <div className="flex items-center gap-2">
            <Network className="text-purple-400" size={18} />
            <h1 className="font-mono text-sm font-bold tracking-[0.2em] uppercase text-ink">
              Correlated Threat Clusters
            </h1>
            <span className="font-mono text-[10px] px-2 py-0.5 rounded bg-purple-500/10 border border-purple-500/30 text-purple-400 font-bold">
              3 Active Campaigns
            </span>
          </div>
          <p className="text-xs text-dim mt-1">
            Graph-correlated clusters linking disparate flow alerts sharing common attacker subnets, MITRE techniques, and target topology.
          </p>
        </div>
      </div>

      {/* Main Split: Cluster List and Detail Inspector */}
      <div className="grid grid-cols-1 lg:grid-cols-[1fr_420px] gap-4">
        {/* Cluster Cards */}
        <div className="space-y-3">
          {CLUSTERS.map((cluster) => {
            const isSelected = selectedCluster.id === cluster.id;
            const isContained = containedIds.has(cluster.id) || cluster.status === 'CONTAINED';
            return (
              <Card3D key={cluster.id} intensity={3} glare={true}>
                <div
                  onClick={() => setSelectedCluster(cluster)}
                  className={`p-4 glass-panel-3d rounded-md border transition-all cursor-pointer ${
                    isSelected
                      ? 'border-purple-500/70 bg-slate-800/40 shadow-[0_0_20px_rgba(168,85,247,0.15)]'
                      : 'border-edge/80 hover:border-edge-bright'
                  }`}
                >
                  <div className="flex items-center justify-between gap-2 flex-wrap mb-2">
                    <div className="flex items-center gap-2">
                      <span
                        className={`font-mono text-[10px] px-2 py-0.5 rounded font-bold uppercase ${
                          cluster.severity === 'critical'
                            ? 'bg-red-500/20 text-red-400 border border-red-500/40'
                            : 'bg-amber-500/20 text-amber-400 border border-amber-500/40'
                        }`}
                      >
                        {cluster.severity}
                      </span>
                      <span className="font-mono text-xs font-bold text-ink">{cluster.name}</span>
                    </div>

                    <span
                      className={`font-mono text-[10px] px-2 py-0.5 rounded border font-semibold ${
                        isContained
                          ? 'bg-emerald-500/15 border-emerald-500/40 text-emerald-400'
                          : 'bg-red-500/15 border-red-500/40 text-red-400 animate-pulse'
                      }`}
                    >
                      {isContained ? 'CONTAINED' : cluster.status}
                    </span>
                  </div>

                  <div className="grid grid-cols-2 md:grid-cols-4 gap-2 font-mono text-xs text-dim my-3">
                    <div>
                      <span className="text-[10px] block">Attack Vector:</span>
                      <strong className="text-slate-200 text-[11px] truncate block">{cluster.primaryVector}</strong>
                    </div>
                    <div>
                      <span className="text-[10px] block">MITRE ATT&CK:</span>
                      <strong className="text-purple-400 text-[11px] block">{cluster.mitreTechnique}</strong>
                    </div>
                    <div>
                      <span className="text-[10px] block">Correlated Alerts:</span>
                      <strong className="text-ink text-[11px] block">{cluster.alertCount} events</strong>
                    </div>
                    <div>
                      <span className="text-[10px] block">Max IOC Reputation:</span>
                      <strong className="text-red-400 text-[11px] block">{cluster.maxIocScore} / 100</strong>
                    </div>
                  </div>

                  <div className="flex items-center justify-between text-[11px] font-mono text-dim pt-2 border-t border-edge/40">
                    <span className="flex items-center gap-1.5">
                      <Globe size={12} className="text-purple-400" />
                      {cluster.sourceIps.length} Malicious IPs ({cluster.sourceIps.slice(0, 2).join(', ')}...)
                    </span>
                    <span className="text-purple-400 flex items-center gap-1 font-semibold">
                      Inspect Cluster Details <ArrowRight size={12} />
                    </span>
                  </div>
                </div>
              </Card3D>
            );
          })}
        </div>

        {/* Selected Cluster Deep Inspection */}
        <div>
          <Card3D intensity={4} glare={false} className="h-full">
            <div className="p-5 glass-panel-3d rounded-md border border-edge/80 h-full flex flex-col justify-between space-y-4">
              <div>
                <div className="flex items-center justify-between pb-3 border-b border-edge/60">
                  <div className="flex items-center gap-2">
                    <ShieldAlert size={16} className="text-purple-400" />
                    <span className="font-mono text-xs font-bold text-ink uppercase tracking-wider">
                      Cluster Intelligence
                    </span>
                  </div>
                  <span className="font-mono text-[10px] text-dim">{selectedCluster.id}</span>
                </div>

                <div className="mt-4 space-y-3 font-mono text-xs">
                  <div>
                    <span className="text-dim text-[10px] uppercase block">Target Network Scope</span>
                    <span className="text-ink font-bold flex items-center gap-1.5 mt-0.5">
                      <Server size={13} className="text-blue-400" />
                      {selectedCluster.targetSubnet}
                    </span>
                  </div>

                  <div>
                    <span className="text-dim text-[10px] uppercase block">Source IPs in Campaign</span>
                    <div className="flex flex-wrap gap-1.5 mt-1">
                      {selectedCluster.sourceIps.map((ip) => (
                        <span key={ip} className="px-2 py-0.5 rounded bg-void/80 border border-edge text-slate-300 text-[11px]">
                          {ip}
                        </span>
                      ))}
                    </div>
                  </div>

                  <div>
                    <span className="text-dim text-[10px] uppercase block">Recommended SOC Action</span>
                    <div className="p-3 mt-1 rounded bg-purple-950/30 border border-purple-800/40 text-purple-200 text-[11px] leading-relaxed">
                      {selectedCluster.mitigationAdvice}
                    </div>
                  </div>
                </div>
              </div>

              <div className="pt-4 border-t border-edge/60 space-y-2">
                <button
                  onClick={() => handleContain(selectedCluster.id)}
                  disabled={containedIds.has(selectedCluster.id) || selectedCluster.status === 'CONTAINED'}
                  className="w-full py-2 px-3 rounded-md bg-purple-600 hover:bg-purple-500 font-mono text-xs font-bold text-white transition-all flex items-center justify-center gap-2 shadow-[0_0_15px_rgba(168,85,247,0.4)] cursor-pointer disabled:opacity-50"
                >
                  <Zap size={13} />
                  <span>
                    {containedIds.has(selectedCluster.id) || selectedCluster.status === 'CONTAINED'
                      ? 'Cluster Containment Active'
                      : 'Auto-Contain Threat Cluster'}
                  </span>
                </button>

                <div className="text-center font-mono text-[10px] text-dim flex items-center justify-center gap-1">
                  <ShieldCheck size={12} className="text-emerald-400" />
                  <span>Mitigation synced with edge firewall</span>
                </div>
              </div>
            </div>
          </Card3D>
        </div>
      </div>
    </div>
  );
}

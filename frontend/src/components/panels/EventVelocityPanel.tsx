import { useState } from 'react';
import { Card3D } from '@/components/ui/Card3D';
import { TrendingUp, ArrowUpRight, BarChart3, Clock } from 'lucide-react';

interface VelocityBucket {
  time: string;
  count: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

const VELOCITY_HISTORY: VelocityBucket[] = [
  { time: '04:00', count: 18, critical: 2, high: 6, medium: 7, low: 3 },
  { time: '04:02', count: 24, critical: 3, high: 8, medium: 9, low: 4 },
  { time: '04:04', count: 32, critical: 5, high: 11, medium: 12, low: 4 },
  { time: '04:06', count: 48, critical: 9, high: 18, medium: 16, low: 5 },
  { time: '04:08', count: 41, critical: 7, high: 15, medium: 14, low: 5 },
  { time: '04:10', count: 29, critical: 4, high: 10, medium: 11, low: 4 },
  { time: '04:12', count: 35, critical: 6, high: 12, medium: 13, low: 4 },
  { time: '04:14', count: 52, critical: 11, high: 20, medium: 17, low: 4 },
  { time: '04:16', count: 38, critical: 6, high: 14, medium: 14, low: 4 },
  { time: '04:18', count: 30, critical: 4, high: 10, medium: 12, low: 4 },
  { time: '04:20', count: 33, critical: 5, high: 12, medium: 12, low: 4 },
  { time: '04:22', count: 45, critical: 8, high: 17, medium: 15, low: 5 },
  { time: '04:24', count: 36, critical: 5, high: 14, medium: 13, low: 4 },
];

const ATTACK_VECTORS = [
  { name: 'Port Scan / Recon', share: 34, velocity: '11.8 / min', color: 'bg-blue-500', bar: 'text-blue-400' },
  { name: 'Web Attack / SQLi / XSS', share: 28, velocity: '9.4 / min', color: 'bg-amber-500', bar: 'text-amber-400' },
  { name: 'Brute Force SSH/FTP', share: 22, velocity: '7.6 / min', color: 'bg-orange-500', bar: 'text-orange-400' },
  { name: 'DDoS / SynFlood', share: 12, velocity: '4.2 / min', color: 'bg-red-500', bar: 'text-red-400' },
  { name: 'Malware C2 Beaconing', share: 4, velocity: '1.4 / min', color: 'bg-purple-500', bar: 'text-purple-400' },
];

export function EventVelocityPanel() {
  const [selectedBucket, setSelectedBucket] = useState<VelocityBucket | null>(VELOCITY_HISTORY[VELOCITY_HISTORY.length - 1]);
  const maxCount = Math.max(...VELOCITY_HISTORY.map((v) => v.count));

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between gap-4 flex-wrap pb-2 border-b border-edge/60">
        <div>
          <div className="flex items-center gap-2">
            <TrendingUp className="text-orange-400" size={18} />
            <h1 className="font-mono text-sm font-bold tracking-[0.2em] uppercase text-ink">
              Signal Velocity & Ingestion Cadence
            </h1>
            <span className="font-mono text-[10px] px-2 py-0.5 rounded bg-orange-500/10 border border-orange-500/30 text-orange-400 font-bold">
              Current: 34.4 alerts / min
            </span>
          </div>
          <p className="text-xs text-dim mt-1">
            Sampled time-series buckets across a rolling 30-minute window with burst pressure forecasting.
          </p>
        </div>

        <div className="flex items-center gap-2 font-mono text-[11px] text-dim">
          <Clock size={13} />
          <span>Aggregation Window: <strong>60s Buckets</strong></span>
        </div>
      </div>

      {/* Top Metrics Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
        <Card3D intensity={3} glare={false}>
          <div className="p-3.5 glass-panel-3d rounded-md border border-edge/80">
            <span className="text-dim text-[10px] font-mono uppercase tracking-wider block">Peak Observed Velocity</span>
            <div className="mt-1 flex items-baseline gap-2 font-mono">
              <span className="text-2xl font-extrabold text-ink">52.0</span>
              <span className="text-[11px] text-dim">alerts/min</span>
            </div>
            <span className="text-[10px] text-amber-400 flex items-center gap-0.5 mt-1 font-mono">
              <ArrowUpRight size={11} /> +18% surge at 04:14
            </span>
          </div>
        </Card3D>

        <Card3D intensity={3} glare={false}>
          <div className="p-3.5 glass-panel-3d rounded-md border border-edge/80">
            <span className="text-dim text-[10px] font-mono uppercase tracking-wider block">Forecast (Next 15m)</span>
            <div className="mt-1 flex items-baseline gap-2 font-mono">
              <span className="text-2xl font-extrabold text-emerald-400">32 - 38</span>
              <span className="text-[11px] text-dim">stable</span>
            </div>
            <span className="text-[10px] text-dim mt-1 block font-mono">Delta below burst threshold</span>
          </div>
        </Card3D>

        <Card3D intensity={3} glare={false}>
          <div className="p-3.5 glass-panel-3d rounded-md border border-edge/80">
            <span className="text-dim text-[10px] font-mono uppercase tracking-wider block">Queue Saturation</span>
            <div className="mt-1 flex items-baseline gap-2 font-mono">
              <span className="text-2xl font-extrabold text-ink">0 / 20</span>
              <span className="text-[11px] text-emerald-400 font-bold">0% load</span>
            </div>
            <span className="text-[10px] text-dim mt-1 block font-mono">Triage pipeline real-time flush</span>
          </div>
        </Card3D>

        <Card3D intensity={3} glare={false}>
          <div className="p-3.5 glass-panel-3d rounded-md border border-edge/80">
            <span className="text-dim text-[10px] font-mono uppercase tracking-wider block">Total Ingested (Run)</span>
            <div className="mt-1 flex items-baseline gap-2 font-mono">
              <span className="text-2xl font-extrabold text-ink">1,800</span>
              <span className="text-[11px] text-dim">events</span>
            </div>
            <span className="text-[10px] text-dim mt-1 block font-mono">100% deduplicated</span>
          </div>
        </Card3D>
      </div>

      {/* Main Velocity Interactive Chart */}
      <Card3D intensity={4} glare={true}>
        <div className="p-5 glass-panel-3d rounded-md border border-edge/80 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 font-mono">
              <BarChart3 size={15} className="text-orange-400" />
              <span className="text-xs font-bold text-ink uppercase tracking-wider">Alert Intake Histogram</span>
            </div>
            {selectedBucket && (
              <div className="font-mono text-xs flex items-center gap-3 bg-void/60 px-3 py-1 rounded border border-edge">
                <span className="text-dim">Timestamp: <strong className="text-ink">{selectedBucket.time}</strong></span>
                <span>Total: <strong className="text-orange-400">{selectedBucket.count}</strong></span>
                <span className="text-red-400">Crit: {selectedBucket.critical}</span>
                <span className="text-amber-400">High: {selectedBucket.high}</span>
              </div>
            )}
          </div>

          {/* Interactive Bar Columns */}
          <div className="h-56 flex items-end gap-2 pt-6 pb-2 px-2 border-b border-edge/40">
            {VELOCITY_HISTORY.map((bucket) => {
              const heightPct = Math.round((bucket.count / maxCount) * 100);
              const isSelected = selectedBucket?.time === bucket.time;
              return (
                <div
                  key={bucket.time}
                  onClick={() => setSelectedBucket(bucket)}
                  className="flex-1 flex flex-col items-center h-full justify-end group cursor-pointer"
                >
                  <span className="font-mono text-[9px] text-dim mb-1 opacity-0 group-hover:opacity-100 transition-opacity">
                    {bucket.count}
                  </span>
                  <div
                    className={`w-full rounded-t-sm transition-all duration-300 relative overflow-hidden ${
                      isSelected
                        ? 'bg-gradient-to-t from-orange-600 to-amber-400 shadow-[0_0_14px_rgba(245,158,11,0.5)]'
                        : 'bg-slate-700/60 hover:bg-slate-600/80'
                    }`}
                    style={{ height: `${heightPct}%` }}
                  >
                    {/* Visual Segment lines */}
                    <div
                      className="absolute bottom-0 left-0 right-0 bg-red-500/70"
                      style={{ height: `${(bucket.critical / bucket.count) * 100}%` }}
                    />
                  </div>
                  <span className={`font-mono text-[10px] mt-2 ${isSelected ? 'text-orange-400 font-bold' : 'text-dim'}`}>
                    {bucket.time}
                  </span>
                </div>
              );
            })}
          </div>

          <div className="flex items-center justify-between text-[11px] font-mono text-dim pt-1">
            <span>Hover or click a timestamp bucket to inspect breakdown</span>
            <div className="flex items-center gap-3">
              <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded bg-red-500" /> Critical</span>
              <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded bg-amber-500" /> High</span>
              <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded bg-slate-600" /> Baseline</span>
            </div>
          </div>
        </div>
      </Card3D>

      {/* Vector Distribution */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <Card3D intensity={3} glare={false}>
          <div className="p-4 glass-panel-3d rounded-md border border-edge/80 space-y-3">
            <h3 className="font-mono text-xs font-bold text-ink uppercase tracking-wider">
              Velocity Breakdown by Attack Vector
            </h3>
            <div className="space-y-2.5">
              {ATTACK_VECTORS.map((vec) => (
                <div key={vec.name} className="space-y-1">
                  <div className="flex items-center justify-between font-mono text-[11px]">
                    <span className="text-slate-300">{vec.name}</span>
                    <span className="text-dim font-semibold">{vec.velocity} ({vec.share}%)</span>
                  </div>
                  <div className="w-full h-1.5 bg-void rounded-full overflow-hidden border border-edge/60">
                    <div className={`h-full rounded-full ${vec.color}`} style={{ width: `${vec.share}%` }} />
                  </div>
                </div>
              ))}
            </div>
          </div>
        </Card3D>

        <Card3D intensity={3} glare={false}>
          <div className="p-4 glass-panel-3d rounded-md border border-edge/80 space-y-3">
            <h3 className="font-mono text-xs font-bold text-ink uppercase tracking-wider">
              Ingestion Capacity & Queue Health
            </h3>
            <div className="space-y-3 pt-1">
              <div className="flex items-center justify-between p-2.5 rounded bg-void/50 border border-edge/60 font-mono text-xs">
                <span className="text-dim">Replay Ingestion Throttle:</span>
                <span className="text-emerald-400 font-bold">30.0 events/s (Healthy)</span>
              </div>
              <div className="flex items-center justify-between p-2.5 rounded bg-void/50 border border-edge/60 font-mono text-xs">
                <span className="text-dim">LightGBM Triage Concurrency:</span>
                <span className="text-ink font-bold">8 parallel workers</span>
              </div>
              <div className="flex items-center justify-between p-2.5 rounded bg-void/50 border border-edge/60 font-mono text-xs">
                <span className="text-dim">Drop Policy:</span>
                <span className="text-slate-300 font-bold">Drop-Oldest (Client Buffer)</span>
              </div>
              <div className="flex items-center justify-between p-2.5 rounded bg-void/50 border border-edge/60 font-mono text-xs">
                <span className="text-dim">Memory Consumption:</span>
                <span className="text-purple-400 font-bold">142 MB / 1024 MB</span>
              </div>
            </div>
          </div>
        </Card3D>
      </div>
    </div>
  );
}

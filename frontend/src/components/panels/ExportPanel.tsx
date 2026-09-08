import { useState } from 'react';
import { Card3D } from '@/components/ui/Card3D';
import { Download, FileText, CheckCircle2, Filter, Layers } from 'lucide-react';

export function ExportPanel() {
  const [format, setFormat] = useState<'csv' | 'json' | 'eve'>('csv');
  const [limit, setLimit] = useState<number>(200);
  const [includeEnrichment, setIncludeEnrichment] = useState(true);
  const [includeTrace, setIncludeTrace] = useState(true);
  const [isExporting, setIsExporting] = useState(false);
  const [downloadSuccess, setDownloadSuccess] = useState(false);

  const handleDownload = () => {
    setIsExporting(true);

    setTimeout(() => {
      let content = '';
      let mimeType = 'text/plain';
      let filename = `flare_alerts_export_${Date.now()}`;

      if (format === 'csv') {
        mimeType = 'text/csv';
        filename += '.csv';
        content =
          'id,timestamp,severity,attack_type,src_ip,dest_ip,dest_port,confidence,ioc_score,status\n' +
          'ALT-36CEAA,2026-09-08T04:22:15Z,critical,web_attack,172.16.0.1,192.168.10.50,80,0.99,96,done\n' +
          'ALT-226905,2026-09-08T04:21:40Z,low,port_scan,10.0.0.12,192.168.10.1,22,0.95,12,done\n' +
          'ALT-21BA87,2026-09-08T04:20:10Z,high,brute_force,185.220.101.5,192.168.10.25,22,0.98,85,done\n' +
          'ALT-991204,2026-09-08T04:18:02Z,critical,malware_c2,194.26.29.112,192.168.10.15,443,0.99,92,done\n';
      } else if (format === 'json') {
        mimeType = 'application/json';
        filename += '.json';
        const sample = [
          {
            id: 'ALT-36CEAA',
            timestamp: '2026-09-08T04:22:15Z',
            severity: 'critical',
            attack_type: 'web_attack',
            src_ip: '172.16.0.1',
            dest_ip: '192.168.10.50',
            dest_port: 80,
            confidence: 0.99,
            max_ioc_score: 96,
            enrichment: includeEnrichment ? { abuseipdb_score: 96, virustotal_positives: 18 } : undefined,
            trace: includeTrace ? [{ node: 'classify', duration_ms: 7.2, provider: 'lightgbm' }] : undefined,
          },
          {
            id: 'ALT-21BA87',
            timestamp: '2026-09-08T04:20:10Z',
            severity: 'high',
            attack_type: 'brute_force',
            src_ip: '185.220.101.5',
            dest_ip: '192.168.10.25',
            dest_port: 22,
            confidence: 0.98,
            max_ioc_score: 85,
          },
        ];
        content = JSON.stringify(sample, null, 2);
      } else {
        mimeType = 'application/json';
        filename += '.eve.json';
        content =
          '{"timestamp":"2026-09-08T04:22:15.000Z","event_type":"alert","src_ip":"172.16.0.1","dest_ip":"192.168.10.50","proto":"TCP","alert":{"action":"blocked","signature":"ET WEB_SPECIFIC_APPS PHP Exploit"}}\n' +
          '{"timestamp":"2026-09-08T04:20:10.000Z","event_type":"alert","src_ip":"185.220.101.5","dest_ip":"192.168.10.25","proto":"TCP","alert":{"action":"allowed","signature":"ET SCAN Potential SSH Scan"}}\n';
      }

      const blob = new Blob([content], { type: mimeType });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      setIsExporting(false);
      setDownloadSuccess(true);
      setTimeout(() => setDownloadSuccess(false), 3000);
    }, 600);
  };

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between gap-4 flex-wrap pb-2 border-b border-edge/60">
        <div>
          <div className="flex items-center gap-2">
            <Download className="text-blue-400" size={18} />
            <h1 className="font-mono text-sm font-bold tracking-[0.2em] uppercase text-ink">
              Data & Incident Telemetry Export Center
            </h1>
            <span className="font-mono text-[10px] px-2 py-0.5 rounded bg-blue-500/10 border border-blue-500/30 text-blue-400 font-bold">
              SIEM & Compliance Ready
            </span>
          </div>
          <p className="text-xs text-dim mt-1">
            Generate bounded snapshots of classified intrusion records, enrichment scores, and reasoning traces for external SIEM ingest or offline research.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-[1fr_360px] gap-4">
        {/* Settings */}
        <Card3D intensity={3} glare={false}>
          <div className="p-5 glass-panel-3d rounded-md border border-edge/80 space-y-4">
            <h3 className="font-mono text-xs font-bold text-ink uppercase tracking-wider flex items-center gap-2">
              <FileText size={15} className="text-blue-400" />
              <span>Export Format & Encoding</span>
            </h3>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
              {[
                { id: 'csv', name: 'CSV Spreadsheets', desc: 'Standard tabular format for Excel / Pandas' },
                { id: 'json', name: 'JSON Arrays', desc: 'Full nested objects with enrichment traces' },
                { id: 'eve', name: 'Suricata EVE JSON', desc: 'Line-delimited JSON for Zeek / Splunk' },
              ].map((fmt) => (
                <div
                  key={fmt.id}
                  onClick={() => setFormat(fmt.id as any)}
                  className={`p-3 rounded-md border cursor-pointer transition-all ${
                    format === fmt.id
                      ? 'bg-blue-500/15 border-blue-500/50 shadow-[0_0_12px_rgba(59,130,246,0.2)]'
                      : 'bg-void/60 border-edge/60 hover:border-edge'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-mono text-xs font-bold text-ink">{fmt.name}</span>
                    {format === fmt.id && <CheckCircle2 size={13} className="text-blue-400" />}
                  </div>
                  <p className="text-[11px] text-dim">{fmt.desc}</p>
                </div>
              ))}
            </div>

            <div className="pt-3 border-t border-edge/40 space-y-3 font-mono text-xs">
              <h4 className="font-bold text-slate-200 uppercase tracking-wider text-[11px] flex items-center gap-2">
                <Filter size={13} className="text-blue-400" />
                <span>Scope & Filters</span>
              </h4>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="text-dim text-[10px] block mb-1">Record Limit (Max 500)</label>
                  <select
                    value={limit}
                    onChange={(e) => setLimit(Number(e.target.value))}
                    className="w-full px-3 py-1.5 bg-void/80 border border-edge rounded font-mono text-ink text-xs focus:outline-none"
                  >
                    <option value={50}>50 Latest Alerts</option>
                    <option value={100}>100 Latest Alerts</option>
                    <option value={200}>200 Latest Alerts</option>
                    <option value={500}>500 Maximum Permitted</option>
                  </select>
                </div>

                <div>
                  <label className="text-dim text-[10px] block mb-1">Severity Threshold</label>
                  <select className="w-full px-3 py-1.5 bg-void/80 border border-edge rounded font-mono text-ink text-xs focus:outline-none">
                    <option value="all">All Severities (Critical to Info)</option>
                    <option value="high">High and Critical Only</option>
                    <option value="critical">Critical Only</option>
                  </select>
                </div>
              </div>

              <div className="pt-2 space-y-2">
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={includeEnrichment}
                    onChange={(e) => setIncludeEnrichment(e.target.checked)}
                    className="accent-blue-500 rounded cursor-pointer"
                  />
                  <span className="text-slate-300 text-[11px]">Include Threat Intelligence Lookups (AbuseIPDB, VirusTotal)</span>
                </label>

                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={includeTrace}
                    onChange={(e) => setIncludeTrace(e.target.checked)}
                    className="accent-blue-500 rounded cursor-pointer"
                  />
                  <span className="text-slate-300 text-[11px]">Include Execution Graph Trace (Node latencies & LLM token usage)</span>
                </label>
              </div>
            </div>
          </div>
        </Card3D>

        {/* Summary Card & Download Trigger */}
        <Card3D intensity={4} glare={true}>
          <div className="p-5 glass-panel-3d rounded-md border border-edge/80 h-full flex flex-col justify-between space-y-4">
            <div>
              <h3 className="font-mono text-xs font-bold text-ink uppercase tracking-wider flex items-center gap-2 pb-3 border-b border-edge/60">
                <Layers size={15} className="text-blue-400" />
                <span>Export Summary</span>
              </h3>

              <div className="mt-4 space-y-2.5 font-mono text-xs">
                <div className="flex justify-between py-1 border-b border-edge/40">
                  <span className="text-dim">Selected Format:</span>
                  <span className="text-ink font-bold uppercase">{format}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-edge/40">
                  <span className="text-dim">Rows to Extract:</span>
                  <span className="text-blue-400 font-bold">{limit} events</span>
                </div>
                <div className="flex justify-between py-1 border-b border-edge/40">
                  <span className="text-dim">Intel Enrichment:</span>
                  <span className={includeEnrichment ? 'text-emerald-400' : 'text-dim'}>
                    {includeEnrichment ? 'Included' : 'Omitted'}
                  </span>
                </div>
                <div className="flex justify-between py-1 border-b border-edge/40">
                  <span className="text-dim">Estimated Payload:</span>
                  <span className="text-slate-300 font-semibold">~148 KB</span>
                </div>
              </div>
            </div>

            <div className="space-y-2">
              <button
                onClick={handleDownload}
                disabled={isExporting}
                className="w-full py-2.5 px-4 rounded-md bg-blue-600 hover:bg-blue-500 font-mono text-xs font-bold text-white transition-all flex items-center justify-center gap-2 shadow-[0_0_15px_rgba(59,130,246,0.4)] cursor-pointer disabled:opacity-50"
              >
                <Download size={14} />
                <span>{isExporting ? 'Packaging Export...' : 'Download Export File'}</span>
              </button>

              {downloadSuccess && (
                <div className="text-center font-mono text-[10px] text-emerald-400 flex items-center justify-center gap-1">
                  <CheckCircle2 size={12} />
                  <span>File downloaded to your device!</span>
                </div>
              )}
            </div>
          </div>
        </Card3D>
      </div>
    </div>
  );
}

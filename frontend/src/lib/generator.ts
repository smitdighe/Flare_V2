import type {
  AlertDetail,
  AlertStats,
  AlertStatus,
  AlertSummary,
  AttackType,
  BenchmarkReport,
  EvalReport,
  IocVerdict,
  MitreTechnique,
  Remediation,
  RemediationStep,
  ReplayStatus,
  Severity,
  TraceNode,
} from '@/types';

const ATTACK_TYPES: AttackType[] = [
  'port_scan',
  'brute_force',
  'ddos',
  'web_attack',
  'malware_c2',
  'data_exfiltration',
  'privilege_escalation',
  'recon',
  'benign',
];

const SIGNATURES: Record<AttackType, string[]> = {
  port_scan: [
    'ET SCAN Suricata Nmap SYN Scan Detected',
    'SURICATA PORT_SCAN aggressive sweep',
    'MASSCAN rapid network discovery',
  ],
  brute_force: [
    'ET POLICY SSH Brute Force Attempt (High Frequency)',
    'RDP Authentication Failure Spike',
    'HTTP POST /login Credential Stuffing Pattern',
  ],
  ddos: [
    'SURICATA ANOMALY UDP Flood Volumetric Spike',
    'SYN Flood Rate Threshold Exceeded',
    'HTTP GET Amplification Attack Detected',
  ],
  web_attack: [
    'ET WEB_SERVER SQLi UNION SELECT Injection',
    'XSS Script Payload in Query String',
    'Path Traversal /etc/passwd Attempt',
  ],
  malware_c2: [
    'ET TROJAN Cobalt Strike Beacon DNS Request',
    'AsyncRAT C2 TLS Handshake Fingerprint',
    'RedLine Stealer Exfiltration Callback',
  ],
  data_exfiltration: [
    'LARGE DNS TUNNELING EXFILTRATION DETECTED',
    'AWS S3 Bulk Sync Anomaly (Unusual User-Agent)',
    'Encrypted Archive Export over Non-Standard Port',
  ],
  privilege_escalation: [
    'Windows Event 4672 SeDebugPrivilege Assigned',
    'Linux sudoers file modification',
    'Active Directory Kerberoasting TGS Request',
  ],
  recon: [
    'ET PROBE Active Directory LDAP Enumeration',
    'SMB Session Enumeration from Internal Host',
    'DNS Zone Transfer Request',
  ],
  benign: [
    'HTTP GET /healthcheck normal telemetry',
    'Standard NTP Time Synchronization',
    'DNS Query api.github.com',
  ],
  unknown: ['Anomaly Detected: Uncategorized Flow Traffic'],
};

function randomItem<T>(arr: T[]): T {
  return arr[Math.floor(Math.random() * arr.length)];
}

function randomIp(publicOnly = false): string {
  if (publicOnly) {
    return `${Math.floor(Math.random() * 180) + 1.1}.${Math.floor(Math.random() * 254)}.${Math.floor(
      Math.random() * 254,
    )}.${Math.floor(Math.random() * 254)}`;
  }
  const isPrivate = Math.random() > 0.4;
  if (isPrivate) {
    return `10.0.${Math.floor(Math.random() * 10)}.${Math.floor(Math.random() * 250) + 1}`;
  }
  return `${Math.floor(Math.random() * 180) + 1}.${Math.floor(Math.random() * 254)}.${Math.floor(
    Math.random() * 254,
  )}.${Math.floor(Math.random() * 254)}`;
}

let counter = 1000;

export function generateAlertSummary(partial?: Partial<AlertSummary>): AlertSummary {
  counter += 1;
  const attackType = randomItem(ATTACK_TYPES);
  const signature = randomItem(SIGNATURES[attackType]);

  const severities: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
  const severity = randomItem(severities);

  const statuses: AlertStatus[] = ['classified', 'enriched', 'reasoned', 'done'];
  const status = randomItem(statuses);

  const hasEnrichment = status !== 'classified';
  const hasRemediation = status === 'reasoned' || status === 'done';

  let maxIocScore: number | null = null;
  if (hasEnrichment) {
    maxIocScore = severity === 'critical' ? 85 + Math.random() * 15 : severity === 'high' ? 60 + Math.random() * 30 : Math.floor(Math.random() * 45);
  }

  return {
    id: `alert-${Date.now()}-${counter}`,
    timestamp: new Date().toISOString(),
    status,
    severity,
    confidence: Number((0.75 + Math.random() * 0.24).toFixed(2)),
    attack_type: attackType,
    signature,
    src_ip: randomIp(true),
    dst_ip: randomIp(false),
    src_port: Math.floor(Math.random() * 50000) + 1024,
    dst_port: randomItem([80, 443, 22, 3389, 53, 8080]),
    protocol: randomItem(['TCP', 'UDP', 'ICMP']),
    source: randomItem(['suricata', 'cicids2017']),
    has_enrichment: hasEnrichment,
    has_remediation: hasRemediation,
    max_ioc_score: maxIocScore ? Number(maxIocScore.toFixed(1)) : null,
    ...partial,
  };
}

const MITRE_BY_ATTACK: Record<string, MitreTechnique[]> = {
  ddos: [
    {
      id: 'T1498',
      name: 'Network Denial of Service',
      tactic: 'Impact',
      url: 'https://attack.mitre.org/techniques/T1498/',
      excerpt: 'Adversaries may perform Network Denial of Service attacks to degrade or block the availability of targeted resources by exhausting network bandwidth. This includes volumetric floods, often amplified and reflected through third-party servers, that saturate the link to the victim.',
    },
    {
      id: 'T1499',
      name: 'Endpoint Denial of Service',
      tactic: 'Impact',
      url: 'https://attack.mitre.org/techniques/T1499/',
      excerpt: 'Adversaries may perform Endpoint Denial of Service attacks to degrade or block the availability of services to users by exhausting the system resources or application capacity of the endpoint. This includes application-layer floods, service exhaustion, and application exhaustion that overwhelm a spe',
    },
  ],
  brute_force: [
    {
      id: 'T1110',
      name: 'Brute Force',
      tactic: 'Credential Access',
      url: 'https://attack.mitre.org/techniques/T1110/',
      excerpt: 'Adversaries may use brute force techniques to gain access to accounts by guessing credentials with high frequency attempts.',
    },
    {
      id: 'T1110.001',
      name: 'Password Guessing',
      tactic: 'Credential Access',
      url: 'https://attack.mitre.org/techniques/T1110/001/',
      excerpt: 'Adversaries may attempt to guess passwords of valid accounts to authenticate and establish persistence.',
    },
  ],
  web_attack: [
    {
      id: 'T1190',
      name: 'Exploit Public-Facing Application',
      tactic: 'Initial Access',
      url: 'https://attack.mitre.org/techniques/T1190/',
      excerpt: 'Adversaries may attempt to exploit a vulnerability in an Internet-facing computer or program using software, package, or service flaws.',
    },
    {
      id: 'T1059',
      name: 'Command and Scripting Interpreter',
      tactic: 'Execution',
      url: 'https://attack.mitre.org/techniques/T1059/',
      excerpt: 'Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.',
    },
  ],
  malware_c2: [
    {
      id: 'T1071',
      name: 'Application Layer Protocol',
      tactic: 'Command and Control',
      url: 'https://attack.mitre.org/techniques/T1071/',
      excerpt: 'Adversaries may communicate using application layer protocols to avoid detection/network filtering by blending in with existing traffic.',
    },
    {
      id: 'T1573',
      name: 'Encrypted Channel',
      tactic: 'Command and Control',
      url: 'https://attack.mitre.org/techniques/T1573/',
      excerpt: 'Adversaries may employ a known, encryption algorithm to conceal command and control traffic.',
    },
  ],
  recon: [
    {
      id: 'T1595',
      name: 'Active Scanning',
      tactic: 'Reconnaissance',
      url: 'https://attack.mitre.org/techniques/T1595/',
      excerpt: 'Adversaries may execute active reconnaissance scans to gather information about targeted infrastructure.',
    },
    {
      id: 'T1046',
      name: 'Network Service Discovery',
      tactic: 'Discovery',
      url: 'https://attack.mitre.org/techniques/T1046/',
      excerpt: 'Adversaries may attempt to get a listing of services running on remote hosts.',
    },
  ],
  port_scan: [
    {
      id: 'T1046',
      name: 'Network Service Discovery',
      tactic: 'Discovery',
      url: 'https://attack.mitre.org/techniques/T1046/',
      excerpt: 'Adversaries may attempt to get a listing of services running on remote hosts.',
    },
    {
      id: 'T1040',
      name: 'Network Sniffing',
      tactic: 'Credential Access',
      url: 'https://attack.mitre.org/techniques/T1040/',
      excerpt: 'Adversaries may sniff network traffic to capture authentication credentials and probe open socket responses.',
    },
  ],
  data_exfiltration: [
    {
      id: 'T1048',
      name: 'Exfiltration Over Alternative Protocol',
      tactic: 'Exfiltration',
      url: 'https://attack.mitre.org/techniques/T1048/',
      excerpt: 'Adversaries may steal data by exfiltrating it over an alternative protocol than the existing command and control channel.',
    },
    {
      id: 'T1567',
      name: 'Exfiltration Over Web Service',
      tactic: 'Exfiltration',
      url: 'https://attack.mitre.org/techniques/T1567/',
      excerpt: 'Adversaries may use an existing, legitimate external Web service to exfiltrate data.',
    },
  ],
  privilege_escalation: [
    {
      id: 'T1068',
      name: 'Exploitation for Privilege Escalation',
      tactic: 'Privilege Escalation',
      url: 'https://attack.mitre.org/techniques/T1068/',
      excerpt: 'Adversaries may exploit software vulnerabilities in an attempt to elevate privileges.',
    },
    {
      id: 'T1078',
      name: 'Valid Accounts',
      tactic: 'Defense Evasion',
      url: 'https://attack.mitre.org/techniques/T1078/',
      excerpt: 'Adversaries may obtain and abuse credentials of existing accounts to gain higher clearance.',
    },
  ],
};

export function generateAlertDetail(summary?: AlertSummary): AlertDetail {
  const base = summary || generateAlertSummary();
  const attackKey = String(base.attack_type || 'recon').toLowerCase();

  const iocs: IocVerdict[] = base.has_enrichment
    ? [
        {
          indicator: base.src_ip,
          indicator_type: 'ip',
          score: base.max_ioc_score ?? 45,
          malicious: (base.max_ioc_score ?? 45) >= 50,
          cached: Math.random() > 0.3,
          sources: [
            {
              source: 'abuseipdb',
              raw_score: base.max_ioc_score ?? 45,
              categories: [attackKey],
              last_seen: new Date(Date.now() - 3600000 * 2).toISOString(),
              link: `https://www.abuseipdb.com/check/${base.src_ip}`,
            },
            {
              source: 'virustotal',
              raw_score: Math.max(0, (base.max_ioc_score ?? 45) - 5),
              categories: ['malicious_traffic'],
              last_seen: new Date(Date.now() - 3600000 * 5).toISOString(),
              link: `https://www.virustotal.com/gui/ip-address/${base.src_ip}`,
            },
          ],
        },
      ]
    : [];

  const techniques: MitreTechnique[] = MITRE_BY_ATTACK[attackKey] || MITRE_BY_ATTACK.recon;
  const techIds = techniques.map((t) => t.id).join(', ');

  const steps: RemediationStep[] = [
    {
      order: 1,
      action: 'Contain the source',
      detail: `Block the source address at the perimeter and drop active flows.`,
      urgency: 'immediate',
    },
    {
      order: 2,
      action: 'Preserve evidence',
      detail: `Capture full packet data and host telemetry for the affected pair.`,
      urgency: 'soon',
    },
    {
      order: 3,
      action: 'Close the exposure',
      detail: `Rotate any credentials reachable from the destination host and patch the exposed service.`,
      urgency: 'monitor',
    },
  ];

  const remediation: Remediation = {
    summary: `Offline playbook for suspected ${attackKey}. Contain the source, preserve evidence, then close the exposure that allowed it.`,
    steps,
    techniques,
    generated_at: new Date().toISOString(),
    duration_ms: 1450,
  };

  const reasoning = `The flow is consistent with ${attackKey} activity and is triaged at ${base.severity || 'high'} severity. Reputation context comes only from the IOC verdicts supplied with this alert. Mapped ATT&CK coverage: ${techIds}. Generated offline by a deterministic analyzer, not a language model.`;

  const trace: TraceNode[] = [
    {
      node: 'classify',
      status: 'ok',
      provider: 'offline:offline-deterministic',
      duration_ms: 0,
      tokens_in: 921,
      tokens_out: 32,
      note: `offline heuristic: signature keywords indicate ${attackKey}`,
    },
    {
      node: 'enrich',
      status: 'ok',
      provider: null,
      duration_ms: 0,
      tokens_in: null,
      tokens_out: null,
      note: base.has_enrichment && base.max_ioc_score ? `IOC reputation score: ${base.max_ioc_score} / 100` : 'no public IOCs to enrich',
    },
    {
      node: 'retrieve',
      status: 'ok',
      provider: null,
      duration_ms: 0,
      tokens_in: null,
      tokens_out: null,
      note: `retrieved ${techIds}`,
    },
    {
      node: 'reason',
      status: 'ok',
      provider: 'offline:offline-deterministic',
      duration_ms: 0,
      tokens_in: 606,
      tokens_out: 66,
      note: null,
    },
    {
      node: 'recommend',
      status: 'ok',
      provider: 'offline:offline-deterministic',
      duration_ms: 0,
      tokens_in: 497,
      tokens_out: 224,
      note: '3 step(s), 2 technique(s); dropped 1 hallucinated/absent technique id(s)',
    },
  ];

  return {
    ...base,
    raw: {
      timestamp: base.timestamp,
      flow_id: 948271038,
      src_ip: base.src_ip,
      src_port: base.src_port,
      dest_ip: base.dst_ip,
      dest_port: base.dst_port,
      proto: base.protocol,
      event_type: 'alert',
      alert: {
        action: 'allowed',
        gid: 1,
        signature_id: 2010928,
        signature: base.signature,
        category: base.attack_type,
        severity: base.severity === 'critical' ? 1 : base.severity === 'high' ? 2 : 3,
      },
    },
    reasoning: (base as any).reasoning || reasoning,
    enrichment: {
      iocs,
      enriched_at: new Date().toISOString(),
      duration_ms: 1120,
    },
    remediation,
    trace,
    total_duration_ms: base.has_remediation ? 3915 : 240,
  };
}

export function seedAlerts(count = 15): AlertDetail[] {
  return Array.from({ length: count }, () => generateAlertDetail());
}

export function generateAlertStats(alerts: AlertSummary[]): AlertStats {
  const by_severity: Partial<Record<Severity, number>> = {};
  const by_attack_type: Record<string, number> = {};
  const by_status: Partial<Record<AlertStatus, number>> = {};
  let malicious_iocs = 0;

  for (const a of alerts) {
    if (a.severity) {
      by_severity[a.severity] = (by_severity[a.severity] || 0) + 1;
    }
    if (a.attack_type) {
      by_attack_type[a.attack_type] = (by_attack_type[a.attack_type] || 0) + 1;
    }
    by_status[a.status] = (by_status[a.status] || 0) + 1;
    if ((a.max_ioc_score ?? 0) >= 50) {
      malicious_iocs += 1;
    }
  }

  const timeline = Array.from({ length: 10 }).map((_, i) => ({
    bucket: new Date(Date.now() - (9 - i) * 60000).toISOString(),
    count: Math.floor(Math.random() * 30) + 5,
    critical: Math.floor(Math.random() * 3),
  }));

  return {
    total: alerts.length,
    by_severity,
    by_attack_type,
    by_status,
    malicious_iocs,
    avg_triage_ms: 840.5,
    alerts_per_min: 42.0,
    timeline,
  };
}

export function generateReplayStatus(): ReplayStatus {
  return {
    state: 'running',
    dataset: 'cicids2017',
    events_per_second: 5.0,
    emitted: 320,
    total: 500,
    queue_depth: { triage: 2, enrich: 4 },
    started_at: new Date(Date.now() - 60000).toISOString(),
    skipped: 12,
  };
}

export function generateEvalReport(sample_size = 200): EvalReport {
  const runNum = Math.floor(1000 + Math.random() * 8999);
  const varPrec = 0.91 + (Math.random() * 0.05 - 0.025);
  const varRec = 0.87 + (Math.random() * 0.05 - 0.025);
  const varAcc = 0.93 + (Math.random() * 0.04 - 0.02);

  return {
    run_id: `eval-run-${runNum}`,
    status: 'completed',
    sample_size,
    started_at: new Date(Date.now() - 45000).toISOString(),
    completed_at: new Date().toISOString(),
    overall: {
      precision: Number(varPrec.toFixed(3)),
      recall: Number(varRec.toFixed(3)),
      f1: Number(((2 * varPrec * varRec) / (varPrec + varRec)).toFixed(3)),
      accuracy: Number(varAcc.toFixed(3)),
    },
    per_class: [
      { label: 'critical', precision: Number((varPrec + 0.03).toFixed(2)), recall: Number((varRec + 0.02).toFixed(2)), f1: 0.93, support: Math.round(sample_size * 0.12) },
      { label: 'high', precision: Number((varPrec - 0.01).toFixed(2)), recall: Number((varRec - 0.02).toFixed(2)), f1: 0.88, support: Math.round(sample_size * 0.22) },
      { label: 'medium', precision: Number((varPrec - 0.03).toFixed(2)), recall: Number((varRec + 0.01).toFixed(2)), f1: 0.87, support: Math.round(sample_size * 0.32) },
      { label: 'low', precision: Number((varPrec + 0.02).toFixed(2)), recall: Number((varRec + 0.03).toFixed(2)), f1: 0.93, support: Math.round(sample_size * 0.24) },
      { label: 'info', precision: Number((varPrec + 0.04).toFixed(2)), recall: Number((varRec + 0.06).toFixed(2)), f1: 0.96, support: Math.round(sample_size * 0.10) },
    ],
    confusion_matrix: {
      labels: ['critical', 'high', 'medium', 'low', 'info'],
      matrix: [
        [Math.round(sample_size * 0.11), 2, 0, 0, 0],
        [2, Math.round(sample_size * 0.19), 3, 0, 0],
        [0, 3, Math.round(sample_size * 0.28), 4, 0],
        [0, 0, 2, Math.round(sample_size * 0.22), 1],
        [0, 0, 0, 1, Math.round(sample_size * 0.09)],
      ],
    },
    attack_type: {
      overall: {
        precision: Number((varPrec - 0.02).toFixed(3)),
        recall: Number((varRec - 0.01).toFixed(3)),
        f1: Number((varPrec - 0.015).toFixed(3)),
        accuracy: Number((varAcc - 0.02).toFixed(3)),
      },
      per_class: [
        { label: 'port_scan', precision: 0.94, recall: 0.92, f1: 0.93, support: Math.round(sample_size * 0.3) },
        { label: 'brute_force', precision: 0.88, recall: 0.85, f1: 0.86, support: Math.round(sample_size * 0.25) },
        { label: 'ddos', precision: 0.95, recall: 0.93, f1: 0.94, support: Math.round(sample_size * 0.25) },
        { label: 'web_attack', precision: 0.82, recall: 0.79, f1: 0.8, support: Math.round(sample_size * 0.2) },
      ],
      confusion_matrix: {
        labels: ['port_scan', 'brute_force', 'ddos', 'web_attack'],
        matrix: [
          [Math.round(sample_size * 0.27), 3, 1, 0],
          [2, Math.round(sample_size * 0.22), 1, 1],
          [0, 1, Math.round(sample_size * 0.23), 1],
          [0, 2, 1, Math.round(sample_size * 0.17)],
        ],
      },
    },
    error: null,
  };
}

export function generateBenchmarkReport(sample_size = 25): BenchmarkReport {
  const runNum = Math.floor(1000 + Math.random() * 8999);
  const agreement = Number((0.84 + Math.random() * 0.08).toFixed(2));
  const fastLat = Math.floor(180 + Math.random() * 60);
  const qualLat = Math.floor(580 + Math.random() * 120);

  const sampleDisagreements = [
    { alert_id: `alert-c2-${runNum}`, signature: 'ET SCAN Suricata Cobalt Strike Beacon', fast_prediction: 'medium', quality_prediction: 'critical', ground_truth: 'critical' },
    { alert_id: `alert-ssh-${runNum}`, signature: 'SSH Brute-Force Auth Anomaly', fast_prediction: 'low', quality_prediction: 'high', ground_truth: 'high' },
    { alert_id: `alert-sql-${runNum}`, signature: 'Web Application SQL Injection Probe', fast_prediction: 'info', quality_prediction: 'medium', ground_truth: 'medium' },
  ];

  return {
    run_id: `bench-run-${runNum}`,
    status: 'completed',
    sample_size,
    results: [
      {
        tier: 'fast',
        provider: 'groq',
        model: 'llama-3.1-8b-instant',
        avg_latency_ms: fastLat,
        p95_latency_ms: fastLat + 160,
        accuracy: Number((0.83 + Math.random() * 0.04).toFixed(2)),
        avg_tokens: 220,
        failures: 0,
        p50_latency_ms: fastLat - 20,
        min_latency_ms: fastLat - 60,
        max_latency_ms: fastLat + 240,
        avg_tokens_in: 180,
        avg_tokens_out: 40,
        attack_type_accuracy: 0.79,
        estimated_cost: 0.0004,
        calls: sample_size,
        warmup_calls: 2,
        throttled: false,
        throttle_retries: 0,
      },
      {
        tier: 'quality',
        provider: 'gemini',
        model: 'gemini-flash-latest',
        avg_latency_ms: qualLat,
        p95_latency_ms: qualLat + 280,
        accuracy: Number((0.93 + Math.random() * 0.04).toFixed(2)),
        avg_tokens: 890,
        failures: 0,
        p50_latency_ms: qualLat - 30,
        min_latency_ms: qualLat - 180,
        max_latency_ms: qualLat + 420,
        avg_tokens_in: 680,
        avg_tokens_out: 210,
        attack_type_accuracy: 0.92,
        estimated_cost: 0.0028,
        calls: sample_size,
        warmup_calls: 2,
        throttled: false,
        throttle_retries: 0,
      },
    ],
    agreement_rate: agreement,
    disagreement_examples: sampleDisagreements,
    error: null,
  };
}

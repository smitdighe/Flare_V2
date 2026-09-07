import { useEffect, useRef } from 'react';

function add(a, b) { return { x: a.x + b.x, y: a.y + b.y, z: a.z + b.z }; }
function norm(p) {
  const l = Math.hypot(p.x, p.y, p.z) || 1;
  return { x: p.x / l, y: p.y / l, z: p.z / l };
}

function rot(p, ax, ay) {
  const cy = Math.cos(ay), sy = Math.sin(ay);
  const x1 = p.x * cy + p.z * sy;
  const z1 = -p.x * sy + p.z * cy;
  const cx = Math.cos(ax), sx = Math.sin(ax);
  const y1 = p.y * cx - z1 * sx;
  const z2 = p.y * sx + z1 * cx;
  return { x: x1, y: y1, z: z2 };
}

function icosphere(subdiv) {
  const t = (1 + Math.sqrt(5)) / 2;
  let verts = [
    { x: -1, y: t, z: 0 }, { x: 1, y: t, z: 0 },
    { x: -1, y: -t, z: 0 }, { x: 1, y: -t, z: 0 },
    { x: 0, y: -1, z: t }, { x: 0, y: 1, z: t },
    { x: 0, y: -1, z: -t }, { x: 0, y: 1, z: -t },
    { x: t, y: 0, z: -1 }, { x: t, y: 0, z: 1 },
    { x: -t, y: 0, z: -1 }, { x: -t, y: 0, z: 1 },
  ].map(norm);

  let faces = [
    [0,11,5],[0,5,1],[0,1,7],[0,7,10],[0,10,11],
    [1,5,9],[5,11,4],[11,10,2],[10,7,6],[7,1,8],
    [3,9,4],[3,4,2],[3,2,6],[3,6,8],[3,8,9],
    [4,9,5],[2,4,11],[6,2,10],[8,6,7],[9,8,1],
  ];

  for (let s = 0; s < subdiv; s++) {
    const cache = new Map();
    const mid = (a, b) => {
      const key = a < b ? `${a}_${b}` : `${b}_${a}`;
      const hit = cache.get(key);
      if (hit !== undefined) return hit;
      verts.push(norm(add(verts[a], verts[b])));
      const idx = verts.length - 1;
      cache.set(key, idx);
      return idx;
    };
    const next = [];
    for (const [a, b, c] of faces) {
      const ab = mid(a, b), bc = mid(b, c), ca = mid(c, a);
      next.push([a, ab, ca], [b, bc, ab], [c, ca, bc], [ab, bc, ca]);
    }
    faces = next;
  }

  const edgeSet = new Set();
  const edges = [];
  for (const [a, b, c] of faces) {
    for (const [p, q] of [[a, b], [b, c], [c, a]]) {
      const key = p < q ? `${p}_${q}` : `${q}_${p}`;
      if (edgeSet.has(key)) continue;
      edgeSet.add(key);
      edges.push([p, q]);
    }
  }
  return { verts, faces, edges };
}

export function Globe({ className = '' }) {
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const pointer = { x: 0, y: 0, tx: 0, ty: 0 };
    let raf = 0, w = 0, h = 0;

    const resize = () => {
      const rect = canvas.getBoundingClientRect();
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      w = rect.width; h = rect.height;
      canvas.width = Math.max(1, Math.floor(w * dpr));
      canvas.height = Math.max(1, Math.floor(h * dpr));
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    };
    resize();
    window.addEventListener('resize', resize);

    const onMove = (e) => {
      pointer.tx = (e.clientX / window.innerWidth - 0.5) * 2;
      pointer.ty = (e.clientY / window.innerHeight - 0.5) * 2;
    };
    window.addEventListener('pointermove', onMove);

    const { verts, faces, edges } = icosphere(4);

    const HOTSPOTS = Array.from({ length: 22 }, (_, i) => {
      const k = i + 0.5;
      const phi = Math.acos(1 - (2 * k) / 22);
      const theta = Math.PI * (1 + Math.sqrt(5)) * k * 1.7;
      return { x: Math.cos(theta) * Math.sin(phi), y: Math.cos(phi) * 0.85, z: Math.sin(theta) * Math.sin(phi) };
    }).map(norm);

    const ARCS = HOTSPOTS.slice(0, 12).map((a, i) => ({
      a, b: HOTSPOTS[(i * 5 + 3) % HOTSPOTS.length], phase: i * 0.7,
    }));

    const RINGS = [
      { r: 1.26, tilt: 1.18, yaw: 0.2, speed: 0.14, alpha: 0.5, ticks: 72 },
      { r: 1.5, tilt: -0.72, yaw: 1.1, speed: -0.09, alpha: 0.32, ticks: 54 },
      { r: 1.82, tilt: 0.4, yaw: -0.6, speed: 0.05, alpha: 0.18, ticks: 108 },
    ];

    const start = performance.now();

    const draw = (now) => {
      const t = (now - start) / 1000;
      pointer.x += (pointer.tx - pointer.x) * 0.04;
      pointer.y += (pointer.ty - pointer.y) * 0.04;

      const cx = w * 0.5, cy = h * 0.5;
      const R = Math.min(w, h) * 0.3;
      const ax = -0.35 + pointer.y * 0.26;
      const ay = t * 0.075 + pointer.x * 0.32;

      ctx.clearRect(0, 0, w, h);

      const proj = (p) => {
        const r = rot(p, ax, ay);
        const persp = 1 / (1 + r.z * 0.3);
        return { sx: cx + r.x * R * persp, sy: cy + r.y * R * persp, z: r.z, persp };
      };
      const rp = verts.map(proj);

      // atmosphere
      const g = ctx.createRadialGradient(cx, cy, R * 0.6, cx, cy, R * 2.15);
      g.addColorStop(0, 'rgba(255,150,40,0.12)');
      g.addColorStop(0.4, 'rgba(255,110,30,0.05)');
      g.addColorStop(1, 'rgba(0,0,0,0)');
      ctx.fillStyle = g;
      ctx.beginPath(); ctx.arc(cx, cy, R * 2.15, 0, Math.PI * 2); ctx.fill();

      // body
      const body = ctx.createRadialGradient(cx - R * 0.35, cy - R * 0.4, R * 0.08, cx, cy, R);
      body.addColorStop(0, 'rgba(66,40,20,0.6)');
      body.addColorStop(0.7, 'rgba(22,15,10,0.85)');
      body.addColorStop(1, 'rgba(8,7,6,0.92)');
      ctx.fillStyle = body;
      ctx.beginPath(); ctx.arc(cx, cy, R, 0, Math.PI * 2); ctx.fill();

      const hs = HOTSPOTS.map((p) => rot(p, ax, ay));

      // faces
      for (const [ia, ib, ic] of faces) {
        const a = rp[ia], b = rp[ib], c = rp[ic];
        if (a.z > 0.02 && b.z > 0.02 && c.z > 0.02) continue;
        const zc = (a.z + b.z + c.z) / 3;
        const depth = Math.max(0, -zc);
        const mx = (a.sx + b.sx + c.sx) / 3;
        const my = (a.sy + b.sy + c.sy) / 3;
        let heat = 0;
        for (const p of hs) {
          if (p.z > 0.1) continue;
          const px = cx + p.x * R, py = cy + p.y * R;
          const d = Math.hypot(px - mx, py - my) / (R * 0.34);
          if (d < 1) heat = Math.max(heat, (1 - d) * (0.55 + 0.45 * Math.sin(t * 1.4 + p.x * 6)));
        }
        ctx.beginPath();
        ctx.moveTo(a.sx, a.sy); ctx.lineTo(b.sx, b.sy); ctx.lineTo(c.sx, c.sy); ctx.closePath();
        if (heat > 0.02) {
          ctx.fillStyle = `rgba(255,${140 + heat * 70},${40 + heat * 40},${heat * 0.3 * (0.35 + depth)})`;
        } else {
          ctx.fillStyle = `rgba(255,170,80,${0.012 + depth * 0.02})`;
        }
        ctx.fill();
      }

      // edges
      ctx.lineWidth = 0.55;
      for (const [ia, ib] of edges) {
        const a = rp[ia], b = rp[ib];
        const zc = (a.z + b.z) / 2;
        const front = zc <= 0.02;
        const depth = Math.max(0, -zc);
        let heat = 0;
        const mx = (a.sx + b.sx) / 2, my = (a.sy + b.sy) / 2;
        for (const p of hs) {
          if (p.z > 0.1) continue;
          const d = Math.hypot(cx + p.x * R - mx, cy + p.y * R - my) / (R * 0.3);
          if (d < 1) heat = Math.max(heat, 1 - d);
        }
        const alpha = front ? 0.05 + depth * 0.16 + heat * 0.5 : 0.02;
        ctx.strokeStyle = heat > 0.05
          ? `rgba(255,${170 + heat * 60},${90 + heat * 60},${alpha})`
          : `rgba(255,190,120,${alpha})`;
        ctx.beginPath(); ctx.moveTo(a.sx, a.sy); ctx.lineTo(b.sx, b.sy); ctx.stroke();
      }

      // vertices
      for (let i = 0; i < rp.length; i += 3) {
        const q = rp[i];
        if (q.z > 0) continue;
        const depth = -q.z;
        ctx.fillStyle = `rgba(255,215,150,${0.06 + depth * 0.18})`;
        ctx.beginPath(); ctx.arc(q.sx, q.sy, 0.7 + depth * 0.7, 0, Math.PI * 2); ctx.fill();
      }

      // hotspot flares
      hs.forEach((p, i) => {
        if (p.z > 0.06) return;
        const persp = 1 / (1 + p.z * 0.3);
        const sx = cx + p.x * R * persp, sy = cy + p.y * R * persp;
        const pulse = 0.5 + 0.5 * Math.sin(t * 1.6 + i);
        const rr = 3 + pulse * 12;
        const fg = ctx.createRadialGradient(sx, sy, 0, sx, sy, rr * 2.4);
        fg.addColorStop(0, `rgba(255,220,160,${0.5 * (0.4 + pulse * 0.6)})`);
        fg.addColorStop(0.35, `rgba(255,150,50,${0.22 * pulse})`);
        fg.addColorStop(1, 'rgba(255,120,30,0)');
        ctx.fillStyle = fg;
        ctx.beginPath(); ctx.arc(sx, sy, rr * 2.4, 0, Math.PI * 2); ctx.fill();
        ctx.fillStyle = `rgba(255,235,200,${0.5 + pulse * 0.4})`;
        ctx.beginPath(); ctx.arc(sx, sy, 1.3, 0, Math.PI * 2); ctx.fill();
      });

      // travelling arcs
      for (const arc of ARCS) {
        const steps = 26;
        const head = ((t * 0.28 + arc.phase) % 1.6) - 0.3;
        ctx.lineWidth = 0.9;
        for (let s = 0; s < steps; s++) {
          const u0 = s / steps, u1 = (s + 1) / steps;
          const pt = (u) => {
            const m = norm({
              x: arc.a.x + (arc.b.x - arc.a.x) * u,
              y: arc.a.y + (arc.b.y - arc.a.y) * u,
              z: arc.a.z + (arc.b.z - arc.a.z) * u,
            });
            const lift = 1 + Math.sin(u * Math.PI) * 0.14;
            return proj({ x: m.x * lift, y: m.y * lift, z: m.z * lift });
          };
          const q0 = pt(u0), q1 = pt(u1);
          if (q0.z > 0.05 || q1.z > 0.05) continue;
          const near = 1 - Math.min(1, Math.abs(u0 - head) / 0.22);
          if (near <= 0) continue;
          ctx.strokeStyle = `rgba(255,${180 + near * 60},${110 + near * 80},${near * 0.6})`;
          ctx.beginPath(); ctx.moveTo(q0.sx, q0.sy); ctx.lineTo(q1.sx, q1.sy); ctx.stroke();
        }
      }

      // rim
      ctx.lineWidth = 1;
      const rim = ctx.createLinearGradient(cx - R, cy - R, cx + R, cy + R);
      rim.addColorStop(0, 'rgba(255,190,110,0.4)');
      rim.addColorStop(1, 'rgba(255,120,30,0.18)');
      ctx.strokeStyle = rim;
      ctx.beginPath(); ctx.arc(cx, cy, R, 0, Math.PI * 2); ctx.stroke();

      // orbital rings
      RINGS.forEach((ring, idx) => {
        const spin = t * ring.speed;
        const pts = [];
        for (let j = 0; j <= 180; j++) {
          const a = (j / 180) * Math.PI * 2;
          pts.push(rot({ x: Math.cos(a) * ring.r, y: 0, z: Math.sin(a) * ring.r }, ring.tilt, ring.yaw + spin));
        }
        for (const front of [false, true]) {
          ctx.beginPath();
          let pen = false;
          for (const p of pts) {
            const q = proj(p);
            if (q.z <= 0 !== front) { pen = false; continue; }
            if (!pen) { ctx.moveTo(q.sx, q.sy); pen = true; } else ctx.lineTo(q.sx, q.sy);
          }
          ctx.lineWidth = front ? 1.1 : 0.6;
          ctx.strokeStyle = front ? `rgba(255,164,60,${ring.alpha})` : `rgba(255,164,60,${ring.alpha * 0.28})`;
          ctx.stroke();
        }

        for (let j = 0; j < ring.ticks; j++) {
          const a = (j / ring.ticks) * Math.PI * 2;
          const mk = (k) => proj(rot({ x: Math.cos(a) * ring.r * k, y: 0, z: Math.sin(a) * ring.r * k }, ring.tilt, ring.yaw + spin));
          const qi = mk(0.978), qo = mk(1.022);
          ctx.strokeStyle = `rgba(255,225,180,${qi.z <= 0 ? 0.15 : 0.045})`;
          ctx.lineWidth = 0.6;
          ctx.beginPath(); ctx.moveTo(qi.sx, qi.sy); ctx.lineTo(qo.sx, qo.sy); ctx.stroke();
        }

        const na = t * (0.55 + idx * 0.22) * (ring.speed > 0 ? 1 : -1);
        const node = rot({ x: Math.cos(na) * ring.r, y: 0, z: Math.sin(na) * ring.r }, ring.tilt, ring.yaw + spin);
        const qn = proj(node);
        const nAlpha = qn.z <= 0 ? 1 : 0.22;
        ctx.fillStyle = `rgba(255,205,130,${nAlpha})`;
        ctx.beginPath(); ctx.arc(qn.sx, qn.sy, 2.4, 0, Math.PI * 2); ctx.fill();
        ctx.strokeStyle = `rgba(255,150,45,${0.25 * nAlpha})`;
        ctx.lineWidth = 1;
        ctx.beginPath(); ctx.arc(qn.sx, qn.sy, 7 + Math.sin(t * 3 + idx) * 2.5, 0, Math.PI * 2); ctx.stroke();
      });

      raf = requestAnimationFrame(draw);
    };

    raf = requestAnimationFrame(draw);

    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener('resize', resize);
      window.removeEventListener('pointermove', onMove);
    };
  }, []);

  return <canvas ref={canvasRef} className={className} aria-hidden="true" />;
}

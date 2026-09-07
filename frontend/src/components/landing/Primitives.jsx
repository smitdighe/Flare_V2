import { useEffect, useRef, useState } from 'react';
import { useReveal } from '../../hooks/use-reveal.js';

export function Reveal({ children, delay = 0, className = '', variant = 'up' }) {
  const { ref, shown } = useReveal();
  const base = variant === 'left' ? 'reveal-left' : variant === 'scale' ? 'reveal-scale' : 'reveal';
  return (
    <div ref={ref} className={`${base} ${shown ? 'reveal-in' : ''} ${className}`} style={{ transitionDelay: `${delay}ms` }}>
      {children}
    </div>
  );
}

export function Magnetic({ children, className = '', href, strength = 10 }) {
  const ref = useRef(null);

  return (
    <a
      ref={ref}
      href={href}
      className={`group relative overflow-hidden ${className}`}
      onPointerMove={(e) => {
        const el = ref.current;
        if (!el) return;
        const r = el.getBoundingClientRect();
        const dx = (e.clientX - (r.left + r.width / 2)) / (r.width / 2);
        const dy = (e.clientY - (r.top + r.height / 2)) / (r.height / 2);
        el.style.transform = `translate(${dx * strength}px, ${dy * strength * 0.5}px)`;
      }}
      onPointerLeave={() => { if (ref.current) ref.current.style.transform = 'translate(0,0)'; }}
      style={{ transition: 'transform 0.4s var(--ease-out-soft)' }}
    >
      <span aria-hidden className="pointer-events-none absolute inset-y-0 -left-full w-1/2 skew-x-[-18deg] bg-foreground/10 transition-none group-hover:animate-sweep" />
      <span className="relative flex items-center gap-3">{children}</span>
    </a>
  );
}

export function TiltPanel({ children, className = '', max = 6 }) {
  const ref = useRef(null);
  return (
    <div style={{ perspective: '1200px' }}>
      <div
        ref={ref}
        className={className}
        style={{ transition: 'transform 0.5s var(--ease-out-soft)' }}
        onPointerMove={(e) => {
          const el = ref.current;
          if (!el) return;
          const r = el.getBoundingClientRect();
          const dx = (e.clientX - (r.left + r.width / 2)) / (r.width / 2);
          const dy = (e.clientY - (r.top + r.height / 2)) / (r.height / 2);
          el.style.transform = `rotateY(${dx * max}deg) rotateX(${-dy * max}deg)`;
        }}
        onPointerLeave={() => { if (ref.current) ref.current.style.transform = 'rotateY(0deg) rotateX(0deg)'; }}
      >
        {children}
      </div>
    </div>
  );
}

export function CountUp({ to, decimals = 0, duration = 1400 }) {
  const { ref, shown } = useReveal(0.4);
  const [v, setV] = useState(0);

  useEffect(() => {
    if (!shown) return;
    let raf = 0;
    const t0 = performance.now();
    const tick = (now) => {
      const p = Math.min(1, (now - t0) / duration);
      setV(to * (1 - Math.pow(1 - p, 3)));
      if (p < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [shown, to, duration]);

  return <span ref={ref}>{v.toFixed(decimals)}</span>;
}

const GLYPHS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/#*<>';

export function Scramble({ text }) {
  const { ref, shown } = useReveal(0.5);
  const [out, setOut] = useState(text);
  const runRef = useRef(0);

  const run = () => {
    cancelAnimationFrame(runRef.current);
    const t0 = performance.now();
    const dur = 620;
    const tick = (now) => {
      const p = Math.min(1, (now - t0) / dur);
      const cut = Math.floor(text.length * p);
      setOut(
        text.split('').map((c, i) =>
          i < cut || c === ' ' ? c : GLYPHS[Math.floor(Math.random() * GLYPHS.length)]
        ).join('')
      );
      if (p < 1) runRef.current = requestAnimationFrame(tick);
      else setOut(text);
    };
    runRef.current = requestAnimationFrame(tick);
  };

  useEffect(() => {
    if (shown) run();
    return () => cancelAnimationFrame(runRef.current);
  }, [shown]);

  return <span ref={ref} onPointerEnter={run}>{out}</span>;
}

export function Parallax({ children, amount = 40 }) {
  const ref = useRef(null);

  useEffect(() => {
    let raf = 0;
    const onScroll = () => {
      cancelAnimationFrame(raf);
      raf = requestAnimationFrame(() => {
        const el = ref.current;
        if (!el) return;
        const r = el.getBoundingClientRect();
        const p = (r.top + r.height / 2 - window.innerHeight / 2) / window.innerHeight;
        el.style.transform = `translate3d(0, ${(-p * amount).toFixed(2)}px, 0)`;
      });
    };
    onScroll();
    window.addEventListener('scroll', onScroll, { passive: true });
    return () => { cancelAnimationFrame(raf); window.removeEventListener('scroll', onScroll); };
  }, [amount]);

  return <div ref={ref}>{children}</div>;
}

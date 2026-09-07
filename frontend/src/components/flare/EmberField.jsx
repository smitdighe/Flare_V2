import { useEffect, useRef } from 'react';

export function EmberField() {
  const ref = useRef(null);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const onMove = (e) => {
      el.style.setProperty('--mx', `${e.clientX}px`);
      el.style.setProperty('--my', `${e.clientY}px`);
    };
    window.addEventListener('pointermove', onMove);
    return () => window.removeEventListener('pointermove', onMove);
  }, []);

  return (
    <div ref={ref} className="pointer-events-none fixed inset-0 overflow-hidden" aria-hidden="true">
      <div className="absolute inset-0 grid-field opacity-[0.5]" />
      <div
        className="absolute inset-0 grid-field opacity-70"
        style={{
          maskImage:
            'radial-gradient(220px circle at var(--mx, 50%) var(--my, 40%), oklch(1 0 0 / 0.9), transparent 70%)',
          WebkitMaskImage:
            'radial-gradient(220px circle at var(--mx, 50%) var(--my, 40%), oklch(1 0 0 / 0.9), transparent 70%)',
          filter: 'brightness(2.6) saturate(2)',
        }}
      />
      <div className="ember-glow animate-drift absolute -left-40 top-1/4 h-[46rem] w-[46rem] opacity-60" />
      <div className="ember-glow animate-drift absolute -right-52 bottom-0 h-[40rem] w-[40rem] opacity-40 [animation-delay:-8s]" />
      <div
        className="absolute inset-0"
        style={{
          background:
            'radial-gradient(120% 90% at 50% 0%, transparent 40%, oklch(0.1 0.004 60 / 0.85) 100%)',
        }}
      />
    </div>
  );
}

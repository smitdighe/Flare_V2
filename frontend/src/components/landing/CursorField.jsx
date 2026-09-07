import { useEffect, useRef } from 'react';

export function CursorField() {
  const glow = useRef(null);
  const ring = useRef(null);

  useEffect(() => {
    let x = window.innerWidth / 2, y = window.innerHeight / 2;
    let gx = x, gy = y, rx = x, ry = y;
    let raf = 0;

    const onMove = (e) => { x = e.clientX; y = e.clientY; };
    window.addEventListener('pointermove', onMove);

    const tick = () => {
      gx += (x - gx) * 0.06;
      gy += (y - gy) * 0.06;
      rx += (x - rx) * 0.22;
      ry += (y - ry) * 0.22;
      if (glow.current) glow.current.style.transform = `translate3d(${gx - 320}px,${gy - 320}px,0)`;
      if (ring.current) ring.current.style.transform = `translate3d(${rx - 14}px,${ry - 14}px,0)`;
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);

    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener('pointermove', onMove);
    };
  }, []);

  return (
    <div className="pointer-events-none fixed inset-0 z-50 hidden overflow-hidden md:block">
      <div
        ref={glow}
        className="absolute h-[640px] w-[640px] rounded-full opacity-60 blur-[80px]"
        style={{ background: 'var(--gradient-cursor)' }}
      />
      <div
        ref={ring}
        className="absolute h-7 w-7 rounded-full border border-accent/50 mix-blend-screen"
      >
        <span className="absolute left-1/2 top-1/2 h-1 w-1 -translate-x-1/2 -translate-y-1/2 rounded-full bg-accent" />
      </div>
    </div>
  );
}

import { motionValue, springValue } from 'motion';
import { useEffect, useMemo, useRef } from 'react';

export default function useMotionPointer() {
  const pointerRef = useRef({ x: 0, y: 0, active: false });
  const x = useMemo(() => motionValue(0), []);
  const y = useMemo(() => motionValue(0), []);
  const smoothX = useMemo(() => springValue(x, { stiffness: 180, damping: 28, mass: 0.7 }), [x]);
  const smoothY = useMemo(() => springValue(y, { stiffness: 180, damping: 28, mass: 0.7 }), [y]);

  useEffect(() => {
    const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const coarse = window.matchMedia('(pointer: coarse)').matches;
    if (reduced || coarse) return undefined;

    const handlePointerMove = (event) => {
      pointerRef.current = { x: event.clientX, y: event.clientY, active: true };
      x.set(event.clientX);
      y.set(event.clientY);
      document.documentElement.style.setProperty('--pointer-x', `${event.clientX}px`);
      document.documentElement.style.setProperty('--pointer-y', `${event.clientY}px`);
    };
    const handlePointerLeave = () => {
      pointerRef.current = { ...pointerRef.current, active: false };
      document.documentElement.style.setProperty('--pointer-active', '0');
    };
    const handlePointerEnter = () => document.documentElement.style.setProperty('--pointer-active', '1');

    document.addEventListener('pointermove', handlePointerMove, { passive: true });
    document.addEventListener('pointerleave', handlePointerLeave, { passive: true });
    document.addEventListener('pointerenter', handlePointerEnter, { passive: true });
    document.documentElement.style.setProperty('--pointer-active', '0');
    return () => {
      document.removeEventListener('pointermove', handlePointerMove);
      document.removeEventListener('pointerleave', handlePointerLeave);
      document.removeEventListener('pointerenter', handlePointerEnter);
      smoothX.stop();
      smoothY.stop();
    };
  }, [smoothX, smoothY, x, y]);

  return { pointerRef, x, y, smoothX, smoothY };
}

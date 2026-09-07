import { animate } from 'motion';
import { useEffect, useRef } from 'react';

export default function AnimatedNumber({ value, prefix = '', suffix = '', decimals = 0, className = '' }) {
  const ref = useRef(null);
  const numericValue = Number(value);

  useEffect(() => {
    if (!ref.current || Number.isNaN(numericValue)) return undefined;
    const controls = animate(0, numericValue, {
      duration: 0.72,
      ease: [0.16, 1, 0.3, 1],
      onUpdate: (latest) => {
        if (ref.current) ref.current.textContent = `${prefix}${latest.toFixed(decimals)}${suffix}`;
      },
    });
    return () => controls.stop();
  }, [decimals, numericValue, prefix, suffix]);

  return <span ref={ref} className={className}>{`${prefix}${numericValue.toFixed(decimals)}${suffix}`}</span>;
}

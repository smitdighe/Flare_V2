const TONE_CLASS = {
  critical: 'bg-red text-red',
  high: 'bg-amber text-amber',
  medium: 'bg-yellow text-yellow',
  low: 'bg-ash text-ash',
  live: 'bg-green text-green',
  idle: 'bg-ash-dark text-ash-dark',
};

export default function StatusDot({ tone = 'idle', pulse = false }) {
  const [background, text] = (TONE_CLASS[tone] || TONE_CLASS.idle).split(' ');
  return <span className={`inline-block h-1.5 w-1.5 rounded-full ${background} ${pulse ? 'animate-pulse' : ''}`} aria-hidden="true" />;
}

export function toneText(tone) {
  return TONE_CLASS[tone]?.split(' ')[1] || 'text-ash';
}

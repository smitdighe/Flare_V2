const TONE_CLASS = {
  critical: 'bg-[#d00000] text-[#ff8080]',
  high: 'bg-[#CC5500] text-[#ffa55c]',
  medium: 'bg-[#E49B0F] text-[#fed978]',
  low: 'bg-[#E5B75D] text-[#f8e4b4]',
  info: 'bg-[#71717a] text-[#d4d4d8]',
  unknown: 'bg-[#71717a] text-[#d4d4d8]',
  live: 'bg-emerald-500 text-emerald-400',
  idle: 'bg-zinc-500 text-zinc-400',
};

export default function StatusDot({ tone = 'idle', pulse = false }) {
  const [background, text] = (TONE_CLASS[tone] || TONE_CLASS.idle).split(' ');
  return (
    <span
      className={`inline-block h-2 w-2 rounded-full ${background} ${pulse ? 'animate-pulse shadow-[0_0_8px_currentColor]' : ''}`}
      aria-hidden="true"
    />
  );
}

export function toneText(tone) {
  return TONE_CLASS[tone]?.split(' ')[1] || 'text-zinc-400';
}

import { useState, useRef, useEffect } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { ChevronDown, Check } from 'lucide-react';

export default function CyberSelect({
  value,
  onChange,
  options = [],
  prefix,
  placeholder = 'SELECT...',
  className = '',
  menuClassName = '',
  disabled = false,
  align = 'left',
}) {
  const [open, setOpen] = useState(false);
  const containerRef = useRef(null);

  // Normalize options: can be strings, numbers, or { value, label }
  const normalizedOptions = options.map((opt) => {
    if (typeof opt === 'object' && opt !== null) {
      return { value: opt.value ?? '', label: String(opt.label ?? opt.value ?? '') };
    }
    return { value: opt, label: String(opt) };
  });

  const selectedOption = normalizedOptions.find((opt) => String(opt.value) === String(value));
  const displayLabel = selectedOption ? selectedOption.label : placeholder;

  // Click outside & Escape key listeners
  useEffect(() => {
    if (!open) return;
    const handleClickOutside = (e) => {
      if (containerRef.current && !containerRef.current.contains(e.target)) {
        setOpen(false);
      }
    };
    const handleKeyDown = (e) => {
      if (e.key === 'Escape') setOpen(false);
    };
    document.addEventListener('mousedown', handleClickOutside);
    document.addEventListener('keydown', handleKeyDown);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
      document.removeEventListener('keydown', handleKeyDown);
    };
  }, [open]);

  return (
    <div ref={containerRef} className={`relative inline-block ${className}`}>
      <button
        type="button"
        disabled={disabled}
        onClick={() => setOpen(!open)}
        className={`group flex items-center justify-between gap-2 border border-border bg-card/90 px-2.5 py-1.5 font-mono text-[10px] uppercase tracking-[0.14em] text-foreground transition-all hover:border-primary/60 hover:bg-card focus:border-primary focus:outline-none disabled:opacity-50 ${
          open ? 'border-primary shadow-[0_0_14px_rgba(235,115,26,0.22)] bg-card' : ''
        }`}
      >
        <span className="flex items-center gap-1.5 truncate">
          {prefix && (
            <span className="font-semibold text-muted-foreground">{prefix}</span>
          )}
          <span className={selectedOption && selectedOption.value ? 'font-semibold text-primary' : 'text-foreground'}>
            {displayLabel}
          </span>
        </span>
        <ChevronDown
          className={`h-3 w-3 shrink-0 text-muted-foreground transition-transform duration-200 group-hover:text-primary ${
            open ? 'rotate-180 text-primary' : ''
          }`}
        />
      </button>

      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ opacity: 0, y: -4, scale: 0.98 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -4, scale: 0.98 }}
            transition={{ duration: 0.14, ease: 'easeOut' }}
            className={`absolute z-50 mt-1 max-h-60 overflow-y-auto border border-border bg-card py-1 shadow-2xl backdrop-blur-xl ${
              align === 'right' ? 'right-0' : 'left-0'
            } ${menuClassName}`}
            style={{
              boxShadow: '0 16px 36px rgba(0, 0, 0, 0.75), 0 0 0 1px rgba(235, 115, 26, 0.3)',
              minWidth: 'max(100%, 140px)',
            }}
          >
            {normalizedOptions.length === 0 ? (
              <div className="px-3 py-2 font-mono text-[10px] text-muted-foreground">
                NO OPTIONS AVAILABLE
              </div>
            ) : (
              normalizedOptions.map((opt) => {
                const isSelected = String(opt.value) === String(value);
                return (
                  <button
                    key={String(opt.value)}
                    type="button"
                    onClick={() => {
                      onChange(opt.value);
                      setOpen(false);
                    }}
                    className={`flex w-full items-center justify-between gap-3 px-3 py-1.5 text-left font-mono text-[10px] uppercase tracking-[0.14em] transition-colors ${
                      isSelected
                        ? 'border-l-2 border-primary bg-primary/20 font-semibold text-primary'
                        : 'border-l-2 border-transparent text-muted-foreground hover:border-border hover:bg-secondary/60 hover:text-foreground'
                    }`}
                  >
                    <span className="truncate">{opt.label}</span>
                    {isSelected && <Check className="h-3 w-3 shrink-0 text-primary" />}
                  </button>
                );
              })
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

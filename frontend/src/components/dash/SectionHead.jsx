import { motion } from "motion/react";

export function SectionHead({ kicker, title, desc }) {
  return (
    <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.4 }}>
      <div className="mono-label flex items-center gap-3 text-primary">
        <span className="h-px w-8 bg-primary" /> {kicker}
      </div>
      <h1 className="font-display mt-2 text-4xl leading-[0.95] md:text-5xl">{title}</h1>
      <p className="mt-2 max-w-2xl text-sm text-muted-foreground">{desc}</p>
    </motion.div>
  );
}

"use client";

// ─── Spring count-up number (framer-motion) ──────────────────────────────────

import { animate } from "framer-motion";
import { useEffect, useRef, useState } from "react";

export function AnimatedNumber({
  value,
  format,
  duration = 0.6,
}: {
  value: number;
  format?: (n: number) => string;
  duration?: number;
}) {
  const [display, setDisplay] = useState(0);
  const prevRef = useRef(0);

  useEffect(() => {
    const from = prevRef.current;
    prevRef.current = value;
    if (from === value) return; // nothing to animate — display already settled
    const controls = animate(from, value, {
      duration,
      ease: [0.16, 1, 0.3, 1],
      onUpdate: (v) => setDisplay(v),
    });
    return () => controls.stop();
  }, [value, duration]);

  return (
    <span className="tabular-nums">
      {format ? format(display) : Math.round(display).toLocaleString("en-US")}
    </span>
  );
}

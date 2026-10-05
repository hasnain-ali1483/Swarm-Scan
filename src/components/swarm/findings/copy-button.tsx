"use client";

// ─── Copy-to-clipboard icon button with toast announcement ──────────────────
// Used for hashes, head hashes and PoC scripts across the findings/ledger views.

import { useState } from "react";
import { Check, Copy } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useToast } from "@/hooks/use-toast";
import { cn } from "@/lib/swarm/format";
import { copyToClipboard } from "./browser-utils";

interface CopyButtonProps {
  value: string;
  /** Announced in the toast + used for the accessible name, e.g. "Hash". */
  toastLabel: string;
  className?: string;
}

export function CopyButton({ value, toastLabel, className }: CopyButtonProps) {
  const [copied, setCopied] = useState(false);
  const { toast } = useToast();

  const onCopy = async () => {
    const ok = await copyToClipboard(value);
    if (ok) {
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1_600);
      toast({ title: `${toastLabel} copied to clipboard` });
    } else {
      toast({ title: "Copy failed", description: "Clipboard unavailable in this context.", variant: "destructive" });
    }
  };

  return (
    <Button
      type="button"
      variant="ghost"
      size="icon"
      onClick={onCopy}
      aria-label={`Copy ${toastLabel.toLowerCase()} to clipboard`}
      className={cn("h-6 w-6 text-zinc-500 hover:text-zinc-200 hover:bg-zinc-800/60", className)}
    >
      {copied ? <Check className="h-3.5 w-3.5 text-emerald-400" aria-hidden /> : <Copy className="h-3.5 w-3.5" aria-hidden />}
    </Button>
  );
}

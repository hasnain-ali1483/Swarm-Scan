"use client";

// ─── Export scheduler — cadence jobs whose deliveries land in the audit trail ─

import { useMemo, useState } from "react";
import { motion } from "framer-motion";
import {
  CalendarClock,
  CheckCircle2,
  Loader2,
  Lock,
  Pause,
  Play,
  Plus,
  Trash2,
  XCircle,
} from "lucide-react";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { roleCan } from "@/lib/swarm/access-roles";
import { cn, timeAgo } from "@/lib/swarm/format";
import type { AccessRole, SchedulerJob } from "@/lib/swarm/types";
import { useSwarmUi } from "@/lib/swarm/ui-store";
import { useNow, useScheduler, useSchedulerMutate } from "./use-compliance";

const FORMAT_META: Record<SchedulerJob["format"], { badge: string; label: string }> = {
  soc2: { badge: "border-emerald-500/40 bg-emerald-500/10 text-emerald-300", label: "soc2" },
  sarif: { badge: "border-zinc-600/60 bg-zinc-500/10 text-zinc-300", label: "sarif" },
  executive: { badge: "border-amber-500/40 bg-amber-500/10 text-amber-300", label: "executive" },
};

const CRON_PRESETS = [
  { cron: "0 8 * * 1", label: "Weekly — Monday 08:00 UTC" },
  { cron: "0 9 1 * *", label: "Monthly — 1st 09:00 UTC" },
  { cron: "0 18 * * *", label: "Daily — 18:00 UTC" },
  { cron: "0 */6 * * *", label: "Every 6 hours UTC" },
];

const FORMATS: SchedulerJob["format"][] = ["soc2", "sarif", "executive"];

function formatCountdown(ms: number): string {
  const s = Math.max(0, Math.floor(ms / 1000));
  const d = Math.floor(s / 86_400);
  const h = Math.floor((s % 86_400) / 3_600);
  const m = Math.floor((s % 3_600) / 60);
  const sec = s % 60;
  const mm = String(m).padStart(2, "0");
  const ss = String(sec).padStart(2, "0");
  if (d > 0) return `${d}d ${h}h ${mm}m ${ss}s`;
  if (h > 0) return `${h}h ${mm}m ${ss}s`;
  return `${m}m ${ss}s`;
}

function JobRow({
  job,
  now,
  canManage,
  onAction,
  pending,
}: {
  job: SchedulerJob;
  now: number;
  canManage: boolean;
  onAction: (action: "pause" | "resume" | "run-now" | "delete") => void;
  pending: boolean;
}) {
  const format = FORMAT_META[job.format];
  const nextIn = new Date(job.nextRunAt).getTime() - now;

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.25 }}
      className={cn(
        "rounded-lg border bg-card/60 p-3 transition-colors",
        job.status === "paused" ? "border-zinc-800/80 opacity-75" : "border-border/80"
      )}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <span className="truncate text-sm font-medium" title={job.name}>
              {job.name}
            </span>
            <Badge variant="outline" className={cn("text-[10px]", format.badge)}>
              {format.label}
            </Badge>
          </div>
          <p className="mt-1 truncate font-mono text-[10px] text-zinc-500" title={job.humanCron}>
            {job.cron} · {job.humanCron}
          </p>
        </div>
        <span className="flex shrink-0 items-center gap-1.5 font-mono text-[10px] text-zinc-400">
          <span
            className={cn(
              "h-1.5 w-1.5 rounded-full",
              job.status === "enabled" ? "bg-emerald-400" : "bg-zinc-600"
            )}
            aria-hidden
          />
          {job.status}
        </span>
      </div>

      <div className="mt-2.5 grid grid-cols-2 gap-x-3 gap-y-2 sm:grid-cols-4">
        <div className="min-w-0">
          <p className="text-[9px] uppercase tracking-wider text-zinc-600">next run</p>
          <p
            className="font-mono text-[11px] tabular-nums text-zinc-300"
            title={`at ${new Date(job.nextRunAt).toLocaleString()} (UTC)`}
          >
            in {formatCountdown(nextIn)}
          </p>
        </div>
        <div className="min-w-0">
          <p className="text-[9px] uppercase tracking-wider text-zinc-600">last run</p>
          {job.lastRunAt ? (
            <p className="flex items-center gap-1 font-mono text-[11px] text-zinc-300">
              {job.lastStatus === "success" ? (
                <CheckCircle2 className="h-3 w-3 shrink-0 text-emerald-400" aria-hidden />
              ) : (
                <XCircle className="h-3 w-3 shrink-0 text-red-400" aria-hidden />
              )}
              <span className="truncate" title={job.lastRunAt}>
                {timeAgo(job.lastRunAt)}
                {job.lastDurationMs ? ` · ${(job.lastDurationMs / 1000).toFixed(1)}s` : ""}
              </span>
            </p>
          ) : (
            <p className="font-mono text-[11px] text-zinc-600">never</p>
          )}
        </div>
        <div>
          <p className="text-[9px] uppercase tracking-wider text-zinc-600">deliveries</p>
          <p className="font-mono text-[11px] tabular-nums text-zinc-300">{job.deliveries}</p>
        </div>
        <div className="min-w-0">
          <p className="text-[9px] uppercase tracking-wider text-zinc-600">cadence</p>
          <p className="truncate font-mono text-[11px] text-zinc-400" title={job.humanCron}>
            {job.humanCron}
          </p>
        </div>
      </div>

      {canManage ? (
        <div className="mt-2.5 flex items-center justify-end gap-1.5">
          <Button
            variant="ghost"
            size="sm"
            disabled={pending}
            onClick={() => onAction(job.status === "enabled" ? "pause" : "resume")}
            className="h-7 gap-1.5 px-2 text-[11px] text-zinc-400"
            aria-label={`${job.status === "enabled" ? "Pause" : "Resume"} ${job.name}`}
          >
            {pending ? (
              <Loader2 className="h-3 w-3 animate-spin" aria-hidden />
            ) : job.status === "enabled" ? (
              <Pause className="h-3 w-3" aria-hidden />
            ) : (
              <Play className="h-3 w-3" aria-hidden />
            )}
            {job.status === "enabled" ? "Pause" : "Resume"}
          </Button>
          <Button
            variant="ghost"
            size="sm"
            disabled={pending}
            onClick={() => onAction("run-now")}
            className="h-7 gap-1.5 px-2 text-[11px] text-emerald-400 hover:bg-emerald-500/10 hover:text-emerald-400"
            aria-label={`Run ${job.name} now`}
          >
            <Play className="h-3 w-3" aria-hidden />
            Run now
          </Button>
          <AlertDialog>
            <AlertDialogTrigger asChild>
              <Button
                variant="ghost"
                size="sm"
                disabled={pending}
                className="h-7 gap-1.5 px-2 text-[11px] text-red-400 hover:bg-red-500/10 hover:text-red-400"
                aria-label={`Delete ${job.name}`}
              >
                <Trash2 className="h-3 w-3" aria-hidden />
              </Button>
            </AlertDialogTrigger>
            <AlertDialogContent>
              <AlertDialogHeader>
                <AlertDialogTitle>Delete “{job.name}”?</AlertDialogTitle>
                <AlertDialogDescription>
                  The job stops delivering after {job.deliveries} audit-trail deliveries. The
                  events already written stay in the WORM log — deletions are also logged.
                </AlertDialogDescription>
              </AlertDialogHeader>
              <AlertDialogFooter>
                <AlertDialogCancel>Keep job</AlertDialogCancel>
                <AlertDialogAction
                  onClick={() => onAction("delete")}
                  className="bg-destructive text-white hover:bg-destructive/90"
                >
                  Delete job
                </AlertDialogAction>
              </AlertDialogFooter>
            </AlertDialogContent>
          </AlertDialog>
        </div>
      ) : null}
    </motion.div>
  );
}

function NewJobDialog({
  onCreate,
  pending,
  canManage,
}: {
  onCreate: (input: { name: string; cron: string; format: string }) => void;
  pending: boolean;
  canManage: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [cron, setCron] = useState(CRON_PRESETS[0].cron);
  const [format, setFormat] = useState<SchedulerJob["format"]>("soc2");

  const submit = () => {
    onCreate({ name: name.trim(), cron, format });
    setOpen(false);
    setName("");
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <Tooltip>
        <TooltipTrigger asChild>
          <span className="inline-flex">
            <DialogTrigger asChild>
              <Button
                size="sm"
                disabled={!canManage || pending}
                className="gap-1.5"
                aria-label={canManage ? "New scheduled export job" : "scheduler:manage required"}
              >
                {canManage ? <Plus className="h-3.5 w-3.5" aria-hidden /> : <Lock className="h-3.5 w-3.5" aria-hidden />}
                New job
              </Button>
            </DialogTrigger>
          </span>
        </TooltipTrigger>
        {!canManage ? (
          <TooltipContent>scheduler:manage denied for your acting role</TooltipContent>
        ) : null}
      </Tooltip>

      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>New export job</DialogTitle>
          <DialogDescription>
            Deliveries append to the WORM audit trail — no side-channel files.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 py-2">
          <div className="space-y-1.5">
            <Label htmlFor="job-name" className="text-[11px] uppercase tracking-wider text-zinc-500">
              Name
            </Label>
            <Input
              id="job-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. Weekly SOC 2 evidence pack"
              className="text-sm"
              maxLength={80}
            />
          </div>

          <div className="space-y-1.5">
            <Label className="text-[11px] uppercase tracking-wider text-zinc-500">Cadence</Label>
            <Select value={cron} onValueChange={setCron}>
              <SelectTrigger className="font-mono text-xs" aria-label="Job cadence preset">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {CRON_PRESETS.map((preset) => (
                  <SelectItem key={preset.cron} value={preset.cron} className="text-xs">
                    <span className="text-zinc-400">{preset.label}</span>
                    <span className="ml-2 font-mono text-[10px] text-zinc-600">{preset.cron}</span>
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-1.5">
            <Label className="text-[11px] uppercase tracking-wider text-zinc-500">Format</Label>
            <Select value={format} onValueChange={(v) => setFormat(v as SchedulerJob["format"])}>
              <SelectTrigger className="text-xs" aria-label="Export format">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {FORMATS.map((f) => (
                  <SelectItem key={f} value={f} className="text-xs capitalize">
                    {f}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>

        <DialogFooter>
          <Button
            size="sm"
            onClick={submit}
            disabled={pending || !name.trim()}
            className="gap-1.5"
          >
            {pending ? <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden /> : null}
            Create job
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export function SchedulerPanel() {
  const { data, isLoading } = useScheduler();
  const mutateJob = useSchedulerMutate();
  const now = useNow(1_000);

  const actingRole = useSwarmUi((s) => s.actingRole) as AccessRole;
  const canManage = roleCan(actingRole, "scheduler:manage");

  const jobs = useMemo(() => data?.jobs ?? [], [data]);

  const onAction = (action: "pause" | "resume" | "run-now" | "delete", id: string) =>
    mutateJob.mutate({ action, id });

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="min-w-0"
    >
      <Card className="border-border/80 bg-card/40">
        <CardHeader className="pb-3">
          <CardTitle className="flex flex-wrap items-center justify-between gap-2 text-sm">
            <span className="flex items-center gap-2">
              <CalendarClock className="h-4 w-4 text-primary" aria-hidden />
              Export scheduler
            </span>
            <NewJobDialog
              onCreate={(input) => mutateJob.mutate({ action: "create", ...input })}
              pending={mutateJob.isPending}
              canManage={canManage}
            />
          </CardTitle>
          <p className="text-[11px] leading-relaxed text-muted-foreground">
            Deliveries append to the WORM audit trail — never side-channel files. Pause, resume
            and run-now mutate the computed cadence; next runs are derived from cron, live.
          </p>
          {!canManage ? (
            <span className="sr-only">
              scheduler:manage denied for {actingRole} — job actions hidden
            </span>
          ) : null}
        </CardHeader>
        <CardContent className="pb-4">
          {isLoading ? (
            <div className="space-y-2.5">
              {Array.from({ length: 4 }).map((_, i) => (
                <Skeleton key={i} className="h-[118px] rounded-lg" />
              ))}
            </div>
          ) : jobs.length === 0 ? (
            <p className="rounded-lg border border-dashed border-zinc-800 px-4 py-8 text-center text-xs text-zinc-500">
              No export jobs — create one to start cadenced audit-trail deliveries.
            </p>
          ) : (
            <div className="max-h-[560px] space-y-2.5 overflow-y-auto pr-0.5 swarm-scroll">
              {jobs.map((job) => (
                <JobRow
                  key={job.id}
                  job={job}
                  now={now}
                  canManage={canManage}
                  pending={mutateJob.isPending}
                  onAction={(action) => onAction(action, job.id)}
                />
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </motion.div>
  );
}

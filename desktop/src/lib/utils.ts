import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  if (ms < 3600000) return `${Math.floor(ms / 60000)}m ${Math.floor((ms % 60000) / 1000)}s`;
  return `${Math.floor(ms / 3600000)}h ${Math.floor((ms % 3600000) / 60000)}m`;
}

export function formatNumber(num: number): string {
  if (num >= 1000000) return `${(num / 1000000).toFixed(1)}M`;
  if (num >= 1000) return `${(num / 1000).toFixed(1)}K`;
  return num.toString();
}

export function getSeverityColor(severity: string): string {
  const colors: Record<string, string> = {
    critical: "text-red-500",
    high: "text-orange-500",
    medium: "text-yellow-500",
    low: "text-green-500",
    info: "text-blue-500",
  };
  return colors[severity.toLowerCase()] || "text-muted-foreground";
}

export function getSeverityBgColor(severity: string): string {
  const colors: Record<string, string> = {
    critical: "bg-red-500/10",
    high: "bg-orange-500/10",
    medium: "bg-yellow-500/10",
    low: "bg-green-500/10",
    info: "bg-blue-500/10",
  };
  return colors[severity.toLowerCase()] || "bg-muted";
}

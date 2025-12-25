import { useEffect, useRef, useState } from "react";
import { useTrixStore, ConsoleLogEntry } from "@/lib/store";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import {
  Terminal,
  Trash2,
  Download,
  ChevronDown,
  ChevronUp,
  // Filter,
  Circle,
} from "lucide-react";

interface ScanConsoleProps {
  scanId: string;
  className?: string;
  maxHeight?: string;
  autoScroll?: boolean;
}

type LogFilter = "all" | "output" | "error" | "info" | "warning";

export function ScanConsole({
  scanId,
  className,
  maxHeight = "400px",
  autoScroll = true,
}: ScanConsoleProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [isExpanded, setIsExpanded] = useState(true);
  const [filter, setFilter] = useState<LogFilter>("all");
  const [shouldAutoScroll, setShouldAutoScroll] = useState(autoScroll);
  
  const logs = useTrixStore((state) => state.consoleLogs.get(scanId) || []);
  const clearLogs = useTrixStore((state) => state.clearConsoleLogs);

  // Auto-scroll to bottom when new logs arrive
  useEffect(() => {
    if (shouldAutoScroll && containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [logs, shouldAutoScroll]);

  // Filter logs
  const filteredLogs = filter === "all" 
    ? logs 
    : logs.filter((log) => log.type === filter);

  const handleExport = () => {
    const content = logs
      .map((log) => {
        const time = log.timestamp.toISOString();
        return `[${time}] [${log.type.toUpperCase()}] [${log.source}] ${log.message}`;
      })
      .join("\n");
    
    const blob = new Blob([content], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `scan-${scanId}-console.log`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const getLogTypeColor = (type: ConsoleLogEntry["type"]) => {
    switch (type) {
      case "error": return "text-red-400";
      case "warning": return "text-yellow-400";
      case "success": return "text-green-400";
      case "info": return "text-blue-400";
      case "command": return "text-purple-400";
      case "output": return "text-zinc-300";
      default: return "text-zinc-400";
    }
  };

  const getSourceColor = (source: string) => {
    // Consistent color per source
    const colors = [
      "text-cyan-400",
      "text-pink-400", 
      "text-orange-400",
      "text-emerald-400",
      "text-violet-400",
      "text-amber-400",
    ];
    let hash = 0;
    for (let i = 0; i < source.length; i++) {
      hash = source.charCodeAt(i) + ((hash << 5) - hash);
    }
    return colors[Math.abs(hash) % colors.length];
  };

  const errorCount = logs.filter((l) => l.type === "error").length;
  const warningCount = logs.filter((l) => l.type === "warning").length;

  return (
    <div className={cn("rounded-lg border bg-zinc-950", className)}>
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-2 border-b border-zinc-800">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <Terminal className="h-4 w-4 text-green-400" />
            <span className="font-mono text-sm font-medium text-zinc-200">Console</span>
          </div>
          
          {/* Status indicators */}
          <div className="flex items-center gap-2 text-xs">
            {errorCount > 0 && (
              <span className="flex items-center gap-1 text-red-400">
                <Circle className="h-2 w-2 fill-current" />
                {errorCount} errors
              </span>
            )}
            {warningCount > 0 && (
              <span className="flex items-center gap-1 text-yellow-400">
                <Circle className="h-2 w-2 fill-current" />
                {warningCount} warnings
              </span>
            )}
            <span className="text-zinc-500">{logs.length} lines</span>
          </div>
        </div>

        <div className="flex items-center gap-1">
          {/* Filter dropdown */}
          <select
            value={filter}
            onChange={(e) => setFilter(e.target.value as LogFilter)}
            className="h-7 px-2 text-xs bg-zinc-800 border-zinc-700 rounded text-zinc-300"
          >
            <option value="all">All</option>
            <option value="output">Output</option>
            <option value="error">Errors</option>
            <option value="warning">Warnings</option>
            <option value="info">Info</option>
          </select>

          <Button
            variant="ghost"
            size="icon"
            className="h-7 w-7"
            onClick={() => setShouldAutoScroll(!shouldAutoScroll)}
            title={shouldAutoScroll ? "Disable auto-scroll" : "Enable auto-scroll"}
          >
            <ChevronDown className={cn("h-4 w-4", shouldAutoScroll && "text-green-400")} />
          </Button>

          <Button
            variant="ghost"
            size="icon"
            className="h-7 w-7"
            onClick={handleExport}
            title="Export logs"
          >
            <Download className="h-4 w-4" />
          </Button>

          <Button
            variant="ghost"
            size="icon"
            className="h-7 w-7"
            onClick={() => clearLogs(scanId)}
            title="Clear logs"
          >
            <Trash2 className="h-4 w-4" />
          </Button>

          <Button
            variant="ghost"
            size="icon"
            className="h-7 w-7"
            onClick={() => setIsExpanded(!isExpanded)}
          >
            {isExpanded ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
          </Button>
        </div>
      </div>

      {/* Console content */}
      {isExpanded && (
        <div
          ref={containerRef}
          className="overflow-auto font-mono text-sm p-3 space-y-0.5"
          style={{ maxHeight }}
        >
          {filteredLogs.length === 0 ? (
            <div className="text-zinc-600 text-center py-8">
              Waiting for scan output...
            </div>
          ) : (
            filteredLogs.map((log) => (
              <div key={log.id} className="flex gap-2 hover:bg-zinc-900/50 px-1 rounded">
                {/* Timestamp */}
                <span className="text-zinc-600 text-xs shrink-0">
                  {log.timestamp.toLocaleTimeString()}
                </span>
                
                {/* Source badge */}
                <span className={cn("text-xs shrink-0", getSourceColor(log.source))}>
                  [{log.source}]
                </span>
                
                {/* Message */}
                <span className={cn("break-all", getLogTypeColor(log.type))}>
                  {log.message}
                </span>
              </div>
            ))
          )}
        </div>
      )}
    </div>
  );
}

// Compact inline version for the scan page
export function ScanConsoleInline({ scanId }: { scanId: string }) {
  const logs = useTrixStore((state) => state.consoleLogs.get(scanId) || []);
  const lastLogs = logs.slice(-5);

  return (
    <div className="bg-zinc-950 rounded border border-zinc-800 p-3 font-mono text-xs space-y-1">
      {lastLogs.length === 0 ? (
        <div className="text-zinc-600">Waiting for output...</div>
      ) : (
        lastLogs.map((log) => (
          <div key={log.id} className="text-zinc-400 truncate">
            <span className="text-zinc-600">{log.timestamp.toLocaleTimeString()}</span>
            {" "}
            <span className={cn(
              log.type === "error" && "text-red-400",
              log.type === "success" && "text-green-400",
              log.type === "warning" && "text-yellow-400",
            )}>
              {log.message}
            </span>
          </div>
        ))
      )}
    </div>
  );
}

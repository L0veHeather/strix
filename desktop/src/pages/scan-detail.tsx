import { useEffect } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  ArrowLeft,
  Play,
  Pause,
  Square,
  RefreshCw,
  Download,
  CheckCircle2,
  XCircle,
  Clock,
  AlertTriangle,
  Terminal,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { scanApi, resultsApi } from "@/lib/api";
import { useWebSocket } from "@/lib/websocket";
import { useStrixStore } from "@/lib/store";
import { ScanConsole } from "@/components/scan-console";
import { cn, formatDuration } from "@/lib/utils";

const PHASE_ORDER = [
  "RECONNAISSANCE",
  "ENUMERATION",
  "VULNERABILITY_SCAN",
  "EXPLOITATION",
  "VALIDATION",
  "REPORTING",
];

export default function ScanDetailPage() {
  const { scanId } = useParams<{ scanId: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { subscribe, unsubscribe, on } = useWebSocket();

  // Subscribe to scan updates
  useEffect(() => {
    if (scanId) {
      subscribe(scanId);
      return () => unsubscribe(scanId);
    }
  }, [scanId, subscribe, unsubscribe]);

  // Listen for WebSocket events
  useEffect(() => {
    const cleanups = [
      on("scan.progress", () => {
        queryClient.invalidateQueries({ queryKey: ["scan", scanId] });
      }),
      on("vulnerability.found", () => {
        queryClient.invalidateQueries({ queryKey: ["scan", scanId, "vulnerabilities"] });
      }),
      on("scan.completed", () => {
        queryClient.invalidateQueries({ queryKey: ["scan", scanId] });
      }),
    ];

    return () => cleanups.forEach((cleanup) => cleanup());
  }, [scanId, on, queryClient]);

  // Fetch scan details
  const { data: scan, isLoading } = useQuery({
    queryKey: ["scan", scanId],
    queryFn: () => scanApi.getStatus(scanId!),
    enabled: !!scanId,
    refetchInterval: (query) => {
      const data = query.state.data;
      return data?.status === "running" ? 2000 : false;
    },
  });

  // Fetch vulnerabilities
  const { data: vulnsData } = useQuery({
    queryKey: ["scan", scanId, "vulnerabilities"],
    queryFn: () => resultsApi.getScanVulnerabilities(scanId!),
    enabled: !!scanId,
    refetchInterval: scan?.status === "running" ? 5000 : false,
  });

  // Control mutations
  const pauseMutation = useMutation({
    mutationFn: () => scanApi.pause(scanId!),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["scan", scanId] }),
  });

  const resumeMutation = useMutation({
    mutationFn: () => scanApi.resume(scanId!),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["scan", scanId] }),
  });

  const stopMutation = useMutation({
    mutationFn: () => scanApi.stop(scanId!),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["scan", scanId] }),
  });

  const handleExport = async (format: "json" | "markdown" | "sarif") => {
    const blob = await resultsApi.exportResults(scanId!, format);
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `scan_${scanId}.${format === "sarif" ? "sarif.json" : format === "markdown" ? "md" : format}`;
    a.click();
    URL.revokeObjectURL(url);
  };

  if (isLoading || !scan) {
    return (
      <div className="flex items-center justify-center h-full">
        <RefreshCw className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    );
  }

  const isRunning = scan.status === "running";
  const isPaused = scan.status === "paused";
  const isCompleted = scan.status === "completed";

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Button variant="ghost" size="icon" onClick={() => navigate(-1)}>
            <ArrowLeft className="h-5 w-5" />
          </Button>
          <div>
            <h1 className="text-2xl font-bold">Scan Details</h1>
            <p className="text-muted-foreground">ID: {scanId}</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {isRunning && (
            <>
              <Button
                variant="outline"
                size="sm"
                onClick={() => pauseMutation.mutate()}
              >
                <Pause className="mr-2 h-4 w-4" />
                Pause
              </Button>
              <Button
                variant="destructive"
                size="sm"
                onClick={() => stopMutation.mutate()}
              >
                <Square className="mr-2 h-4 w-4" />
                Stop
              </Button>
            </>
          )}
          {isPaused && (
            <Button size="sm" onClick={() => resumeMutation.mutate()}>
              <Play className="mr-2 h-4 w-4" />
              Resume
            </Button>
          )}
          {isCompleted && (
            <Button
              variant="outline"
              size="sm"
              onClick={() => handleExport("json")}
            >
              <Download className="mr-2 h-4 w-4" />
              Export
            </Button>
          )}
        </div>
      </div>

      {/* Status Card */}
      <Card>
        <CardContent className="p-6">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <StatusIcon status={scan.status} />
              <div>
                <p className="font-medium capitalize">{scan.status}</p>
                <p className="text-sm text-muted-foreground">
                  {scan.current_phase || "Waiting..."}
                </p>
              </div>
            </div>
            <Badge variant={isRunning ? "default" : "secondary"}>
              {Math.round(scan.progress * 100)}%
            </Badge>
          </div>
          <Progress value={scan.progress * 100} className="h-2" />
        </CardContent>
      </Card>

      {/* Phase Progress */}
      <Card>
        <CardHeader>
          <CardTitle>Scan Phases</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {PHASE_ORDER.map((phaseName) => {
              const phaseResult = scan.phases?.find(
                (p) => p.phase.toUpperCase() === phaseName
              );
              const isActive = scan.current_phase?.toUpperCase() === phaseName;
              const isComplete = phaseResult?.status === "completed";
              const isFailed = phaseResult?.status === "failed";

              return (
                <div
                  key={phaseName}
                  className={cn(
                    "flex items-center justify-between p-4 rounded-lg border",
                    isActive && "border-primary bg-primary/5",
                    isComplete && "border-green-500/30 bg-green-500/5",
                    isFailed && "border-red-500/30 bg-red-500/5"
                  )}
                >
                  <div className="flex items-center gap-3">
                    <PhaseIcon
                      status={phaseResult?.status}
                      isActive={isActive}
                    />
                    <div>
                      <p className="font-medium">{formatPhaseName(phaseName)}</p>
                      {phaseResult && (
                        <p className="text-xs text-muted-foreground">
                          {formatDuration(phaseResult.duration_ms)} •{" "}
                          {phaseResult.findings_count} findings
                        </p>
                      )}
                    </div>
                  </div>
                  {phaseResult?.plugins_executed && (
                    <div className="flex gap-1">
                      {phaseResult.plugins_executed.slice(0, 3).map((plugin) => (
                        <Badge key={plugin} variant="outline" className="text-xs">
                          {plugin}
                        </Badge>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </CardContent>
      </Card>

      {/* Vulnerability Summary */}
      <Card>
        <CardHeader>
          <CardTitle>Vulnerabilities</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-5 gap-4 mb-6">
            {["critical", "high", "medium", "low", "info"].map((severity) => (
              <div
                key={severity}
                className={cn(
                  "p-4 rounded-lg border text-center",
                  `severity-${severity}`
                )}
              >
                <p className="text-2xl font-bold">
                  {vulnsData?.stats.by_severity[severity] || 0}
                </p>
                <p className="text-xs capitalize">{severity}</p>
              </div>
            ))}
          </div>

          {/* Vulnerability List */}
          <div className="space-y-2 max-h-[400px] overflow-auto">
            {vulnsData?.vulnerabilities.map((vuln) => (
              <div
                key={vuln.id}
                className="flex items-center justify-between p-3 rounded-lg border bg-card"
              >
                <div className="flex-1 min-w-0">
                  <p className="font-medium truncate">{vuln.title}</p>
                  <p className="text-xs text-muted-foreground truncate">
                    {vuln.url || "N/A"}
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <Badge
                    variant={
                      vuln.severity as
                        | "critical"
                        | "high"
                        | "medium"
                        | "low"
                        | "info"
                    }
                  >
                    {vuln.severity}
                  </Badge>
                  {vuln.plugin_name && (
                    <Badge variant="outline">{vuln.plugin_name}</Badge>
                  )}
                </div>
              </div>
            ))}
            {(!vulnsData?.vulnerabilities ||
              vulnsData.vulnerabilities.length === 0) && (
              <div className="text-center py-8 text-muted-foreground">
                No vulnerabilities found yet
              </div>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Console Output */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Terminal className="h-5 w-5" />
            Console Output
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          <ScanConsole 
            scanId={scanId!} 
            maxHeight="500px"
            className="border-0 rounded-none"
          />
        </CardContent>
      </Card>
    </div>
  );
}

function StatusIcon({ status }: { status: string }) {
  switch (status) {
    case "running":
      return <RefreshCw className="h-5 w-5 text-blue-500 animate-spin" />;
    case "completed":
      return <CheckCircle2 className="h-5 w-5 text-green-500" />;
    case "failed":
      return <XCircle className="h-5 w-5 text-red-500" />;
    case "paused":
      return <Pause className="h-5 w-5 text-yellow-500" />;
    default:
      return <Clock className="h-5 w-5 text-muted-foreground" />;
  }
}

function PhaseIcon({
  status,
  isActive,
}: {
  status?: string;
  isActive: boolean;
}) {
  if (isActive) {
    return <RefreshCw className="h-5 w-5 text-primary animate-spin" />;
  }
  switch (status) {
    case "completed":
      return <CheckCircle2 className="h-5 w-5 text-green-500" />;
    case "failed":
      return <XCircle className="h-5 w-5 text-red-500" />;
    case "skipped":
      return <AlertTriangle className="h-5 w-5 text-yellow-500" />;
    default:
      return <Clock className="h-5 w-5 text-muted-foreground" />;
  }
}

function formatPhaseName(phase: string): string {
  return phase
    .split("_")
    .map((word) => word.charAt(0) + word.slice(1).toLowerCase())
    .join(" ");
}

import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import {
  Shield,
  AlertTriangle,
  AlertCircle,
  Info,
  Clock,
  Target,
  ArrowRight,
  TrendingUp,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { scanApi, resultsApi } from "@/lib/api";
import { formatDuration, cn } from "@/lib/utils";
import { useStrixStore } from "@/lib/store";

export default function Dashboard() {
  const navigate = useNavigate();
  const activeScan = useStrixStore((s) => s.activeScan);

  // Fetch recent scans
  const { data: scansData } = useQuery({
    queryKey: ["scans", "recent"],
    queryFn: () => scanApi.list({ limit: 5 }),
    refetchInterval: 5000,
  });

  // Fetch severity breakdown
  const { data: severityData } = useQuery({
    queryKey: ["severity-breakdown"],
    queryFn: resultsApi.getSeverityBreakdown,
    refetchInterval: 30000,
  });

  // Fetch recent vulnerabilities
  const { data: recentVulns } = useQuery({
    queryKey: ["vulnerabilities", "recent"],
    queryFn: () => resultsApi.getRecentVulnerabilities(5),
    refetchInterval: 10000,
  });

  const severityStats = severityData?.breakdown || {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Dashboard</h1>
          <p className="text-muted-foreground">
            Overview of your security scanning activity
          </p>
        </div>
        <Button onClick={() => navigate("/scan")}>
          <Target className="mr-2 h-4 w-4" />
          New Scan
        </Button>
      </div>

      {/* Active Scan */}
      {activeScan && activeScan.status === "running" && (
        <Card className="border-primary">
          <CardHeader className="pb-2">
            <div className="flex items-center justify-between">
              <CardTitle className="text-lg flex items-center gap-2">
                <div className="h-2 w-2 rounded-full bg-green-500 animate-pulse" />
                Active Scan
              </CardTitle>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => navigate(`/scan/${activeScan.id}`)}
              >
                View Details
                <ArrowRight className="ml-2 h-4 w-4" />
              </Button>
            </div>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="flex items-center justify-between text-sm">
                <span className="text-muted-foreground">
                  {activeScan.target}
                </span>
                <span>{activeScan.currentPhase || "Starting..."}</span>
              </div>
              <Progress value={activeScan.progress * 100} />
              <div className="flex items-center justify-between text-sm text-muted-foreground">
                <span>{Math.round(activeScan.progress * 100)}% complete</span>
                <span>
                  {activeScan.vulnerabilityCount} vulnerabilities found
                </span>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Stats Grid */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <StatsCard
          title="Critical"
          value={severityStats.critical}
          icon={AlertCircle}
          variant="critical"
        />
        <StatsCard
          title="High"
          value={severityStats.high}
          icon={AlertTriangle}
          variant="high"
        />
        <StatsCard
          title="Medium"
          value={severityStats.medium}
          icon={AlertTriangle}
          variant="medium"
        />
        <StatsCard
          title="Low & Info"
          value={severityStats.low + severityStats.info}
          icon={Info}
          variant="low"
        />
      </div>

      {/* Recent Activity */}
      <div className="grid gap-6 lg:grid-cols-2">
        {/* Recent Scans */}
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle>Recent Scans</CardTitle>
              <Button variant="ghost" size="sm" onClick={() => navigate("/results")}>
                View All
              </Button>
            </div>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {scansData?.scans.map((scan) => (
                <div
                  key={scan.id}
                  className="flex items-center justify-between p-3 rounded-lg border bg-card hover:bg-accent/50 cursor-pointer transition-colors"
                  onClick={() => navigate(`/scan/${scan.id}`)}
                >
                  <div className="flex items-center gap-3">
                    <div
                      className={cn(
                        "h-2 w-2 rounded-full",
                        scan.status === "running" && "bg-green-500 animate-pulse",
                        scan.status === "completed" && "bg-blue-500",
                        scan.status === "failed" && "bg-red-500",
                        scan.status === "pending" && "bg-yellow-500"
                      )}
                    />
                    <div>
                      <p className="font-medium truncate max-w-[200px]">
                        {scan.target}
                      </p>
                      <p className="text-xs text-muted-foreground">
                        {scan.started_at
                          ? new Date(scan.started_at).toLocaleString()
                          : "Pending"}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge variant={scan.status === "completed" ? "secondary" : "outline"}>
                      {scan.status}
                    </Badge>
                    {scan.vulnerability_count > 0 && (
                      <Badge variant="destructive">
                        {scan.vulnerability_count}
                      </Badge>
                    )}
                  </div>
                </div>
              ))}
              {(!scansData?.scans || scansData.scans.length === 0) && (
                <div className="text-center py-8 text-muted-foreground">
                  <Shield className="h-12 w-12 mx-auto mb-2 opacity-50" />
                  <p>No scans yet</p>
                  <Button
                    variant="link"
                    onClick={() => navigate("/scan")}
                    className="mt-2"
                  >
                    Start your first scan
                  </Button>
                </div>
              )}
            </div>
          </CardContent>
        </Card>

        {/* Recent Vulnerabilities */}
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle>Recent Vulnerabilities</CardTitle>
              <Button variant="ghost" size="sm" onClick={() => navigate("/results")}>
                View All
              </Button>
            </div>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {recentVulns?.vulnerabilities.map((vuln) => (
                <div
                  key={vuln.id}
                  className="flex items-start gap-3 p-3 rounded-lg border bg-card"
                >
                  <SeverityIcon severity={vuln.severity} />
                  <div className="flex-1 min-w-0">
                    <p className="font-medium truncate">{vuln.title}</p>
                    <p className="text-xs text-muted-foreground truncate">
                      {vuln.url || "N/A"}
                    </p>
                    <div className="flex items-center gap-2 mt-1">
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
                        <span className="text-xs text-muted-foreground">
                          via {vuln.plugin_name}
                        </span>
                      )}
                    </div>
                  </div>
                </div>
              ))}
              {(!recentVulns?.vulnerabilities ||
                recentVulns.vulnerabilities.length === 0) && (
                <div className="text-center py-8 text-muted-foreground">
                  <TrendingUp className="h-12 w-12 mx-auto mb-2 opacity-50" />
                  <p>No vulnerabilities found yet</p>
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

// Stats Card Component
function StatsCard({
  title,
  value,
  icon: Icon,
  variant,
}: {
  title: string;
  value: number;
  icon: React.ElementType;
  variant: "critical" | "high" | "medium" | "low";
}) {
  const colors = {
    critical: "text-red-500 bg-red-500/10",
    high: "text-orange-500 bg-orange-500/10",
    medium: "text-yellow-500 bg-yellow-500/10",
    low: "text-green-500 bg-green-500/10",
  };

  return (
    <Card>
      <CardContent className="p-6">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm text-muted-foreground">{title}</p>
            <p className="text-3xl font-bold">{value}</p>
          </div>
          <div className={cn("p-3 rounded-full", colors[variant])}>
            <Icon className="h-6 w-6" />
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

// Severity Icon Component
function SeverityIcon({ severity }: { severity: string }) {
  const iconClass = cn("h-5 w-5", {
    "text-red-500": severity === "critical",
    "text-orange-500": severity === "high",
    "text-yellow-500": severity === "medium",
    "text-green-500": severity === "low",
    "text-blue-500": severity === "info",
  });

  switch (severity) {
    case "critical":
      return <AlertCircle className={iconClass} />;
    case "high":
    case "medium":
      return <AlertTriangle className={iconClass} />;
    default:
      return <Info className={iconClass} />;
  }
}

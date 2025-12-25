import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { FileText, Search, Download } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { scanApi, resultsApi } from "@/lib/api";
import { cn } from "@/lib/utils";
import { useState } from "react";

export default function ResultsPage() {
  const navigate = useNavigate();
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState<string | null>(null);

  // Fetch all scans
  const { data: scansData } = useQuery({
    queryKey: ["scans"],
    queryFn: () => scanApi.list({ limit: 100 }),
  });

  // Fetch severity breakdown
  const { data: severityData } = useQuery({
    queryKey: ["severity-breakdown"],
    queryFn: resultsApi.getSeverityBreakdown,
  });

  const completedScans = scansData?.scans.filter(
    (s) => s.status === "completed"
  );

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Results</h1>
          <p className="text-muted-foreground">
            View and analyze scan results
          </p>
        </div>
      </div>

      {/* Stats */}
      <div className="grid gap-4 md:grid-cols-5">
        {["critical", "high", "medium", "low", "info"].map((severity) => (
          <Card
            key={severity}
            className={cn(
              "cursor-pointer transition-colors",
              severityFilter === severity && "ring-2 ring-primary"
            )}
            onClick={() =>
              setSeverityFilter(severityFilter === severity ? null : severity)
            }
          >
            <CardContent className="p-4">
              <div
                className={cn(
                  "text-2xl font-bold",
                  severity === "critical" && "text-red-500",
                  severity === "high" && "text-orange-500",
                  severity === "medium" && "text-yellow-500",
                  severity === "low" && "text-green-500",
                  severity === "info" && "text-blue-500"
                )}
              >
                {severityData?.breakdown[severity] || 0}
              </div>
              <p className="text-sm text-muted-foreground capitalize">
                {severity}
              </p>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Search */}
      <div className="flex gap-4">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search scans..."
            className="pl-10"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        {severityFilter && (
          <Button
            variant="outline"
            onClick={() => setSeverityFilter(null)}
          >
            Clear Filter
          </Button>
        )}
      </div>

      {/* Scan List */}
      <Card>
        <CardHeader>
          <CardTitle>Completed Scans</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {completedScans
              ?.filter(
                (scan) =>
                  !search ||
                  scan.target.toLowerCase().includes(search.toLowerCase()) ||
                  scan.name?.toLowerCase().includes(search.toLowerCase())
              )
              .map((scan) => (
                <div
                  key={scan.id}
                  className="flex items-center justify-between p-4 rounded-lg border bg-card hover:bg-accent/50 cursor-pointer transition-colors"
                  onClick={() => navigate(`/scan/${scan.id}`)}
                >
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <FileText className="h-4 w-4 text-muted-foreground" />
                      <span className="font-medium">
                        {scan.name || scan.target}
                      </span>
                    </div>
                    <p className="text-sm text-muted-foreground mt-1">
                      {scan.target}
                    </p>
                    <p className="text-xs text-muted-foreground mt-1">
                      {scan.completed_at
                        ? new Date(scan.completed_at).toLocaleString()
                        : "N/A"}
                    </p>
                  </div>
                  <div className="flex items-center gap-4">
                    <div className="text-right">
                      <p className="text-2xl font-bold">
                        {scan.vulnerability_count}
                      </p>
                      <p className="text-xs text-muted-foreground">
                        vulnerabilities
                      </p>
                    </div>
                    <Button variant="ghost" size="icon">
                      <Download className="h-4 w-4" />
                    </Button>
                  </div>
                </div>
              ))}
            {(!completedScans || completedScans.length === 0) && (
              <div className="text-center py-12 text-muted-foreground">
                <FileText className="h-12 w-12 mx-auto mb-4 opacity-50" />
                <p>No completed scans yet</p>
                <Button
                  variant="link"
                  onClick={() => navigate("/scan")}
                  className="mt-2"
                >
                  Start a new scan
                </Button>
              </div>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

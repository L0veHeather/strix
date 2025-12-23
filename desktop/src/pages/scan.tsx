import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useMutation, useQuery } from "@tanstack/react-query";
import {
  Target,
  Play,
  Settings2,
  ChevronDown,
  ChevronUp,
  Loader2,
  FileText,
  AlertCircle,
  Zap,
  Shield,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { scanApi, pluginApi, settingsApi } from "@/lib/api";
import { useToast } from "@/hooks/use-toast";
import { useStrixStore } from "@/lib/store";
import { cn } from "@/lib/utils";

const SCAN_PHASES = [
  { id: "RECONNAISSANCE", name: "Reconnaissance", description: "Information gathering", icon: "🔍" },
  { id: "ENUMERATION", name: "Enumeration", description: "Content & endpoint discovery", icon: "📂" },
  { id: "VULNERABILITY_SCAN", name: "Vulnerability Scan", description: "Automated scanning", icon: "🔬" },
  { id: "EXPLOITATION", name: "Exploitation", description: "Verify vulnerabilities", icon: "💥" },
  { id: "VALIDATION", name: "Validation", description: "Finding verification", icon: "✅" },
];

const SCAN_PRESETS = [
  { 
    id: "quick", 
    name: "Quick Scan", 
    description: "Fast reconnaissance and basic vuln scan",
    phases: ["RECONNAISSANCE", "VULNERABILITY_SCAN"],
    icon: <Zap className="h-5 w-5" />,
  },
  { 
    id: "full", 
    name: "Full Scan", 
    description: "Complete security assessment",
    phases: ["RECONNAISSANCE", "ENUMERATION", "VULNERABILITY_SCAN", "EXPLOITATION", "VALIDATION"],
    icon: <Shield className="h-5 w-5" />,
  },
  { 
    id: "recon", 
    name: "Recon Only", 
    description: "Information gathering only",
    phases: ["RECONNAISSANCE", "ENUMERATION"],
    icon: <Target className="h-5 w-5" />,
  },
];

export default function ScanPage() {
  const navigate = useNavigate();
  const { toast } = useToast();
  const setActiveScan = useStrixStore((s) => s.setActiveScan);
  const addConsoleLog = useStrixStore((s) => s.addConsoleLog);

  const [target, setTarget] = useState("");
  const [scanName, setScanName] = useState("");
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [selectedPreset, setSelectedPreset] = useState("full");
  const [selectedPhases, setSelectedPhases] = useState<string[]>(
    SCAN_PHASES.map((p) => p.id)
  );
  const [selectedPlugins, setSelectedPlugins] = useState<string[]>([]);
  const [scopeContent, setScopeContent] = useState("");

  // Fetch available plugins
  const { data: pluginsData } = useQuery({
    queryKey: ["plugins"],
    queryFn: () => pluginApi.list({ enabled_only: true }),
  });

  // Check LLM configuration
  const { data: llmConfig } = useQuery({
    queryKey: ["llm-config"],
    queryFn: settingsApi.getLLMConfig,
  });

  const isLLMConfigured = llmConfig?.config?.model && (
    Object.values(llmConfig?.configured_providers || {}).some(Boolean) ||
    llmConfig.config.model.startsWith("ollama/")
  );

  // Create scan mutation
  const createScan = useMutation({
    mutationFn: scanApi.create,
    onSuccess: (scan) => {
      // Initialize console log
      addConsoleLog(scan.id, {
        type: "info",
        source: "system",
        message: `Scan created: ${scan.id}`,
      });
      
      setActiveScan({
        id: scan.id,
        name: scan.name || "",
        target: scan.target,
        status: scan.status as any,
        currentPhase: scan.current_phase,
        progress: scan.progress,
        startedAt: scan.started_at,
        completedAt: scan.completed_at,
        vulnerabilityCount: scan.vulnerability_count,
      });
      toast({
        title: "Scan Started",
        description: `Scanning ${scan.target}`,
      });
      navigate(`/scan/${scan.id}`);
    },
    onError: (error: Error) => {
      toast({
        title: "Failed to start scan",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const handleStartScan = () => {
    if (!target.trim()) {
      toast({
        title: "Target required",
        description: "Please enter a target URL",
        variant: "destructive",
      });
      return;
    }

    // Validate URL
    try {
      new URL(target);
    } catch {
      toast({
        title: "Invalid URL",
        description: "Please enter a valid URL (e.g., https://example.com)",
        variant: "destructive",
      });
      return;
    }

    createScan.mutate({
      target: target.trim(),
      name: scanName.trim() || undefined,
      phases: selectedPhases.length > 0 ? selectedPhases : undefined,
      plugins: selectedPlugins.length > 0 ? selectedPlugins : undefined,
      options: scopeContent ? { scope: scopeContent } : undefined,
    });
  };

  const handlePresetSelect = (presetId: string) => {
    setSelectedPreset(presetId);
    const preset = SCAN_PRESETS.find(p => p.id === presetId);
    if (preset) {
      setSelectedPhases(preset.phases);
    }
  };

  const togglePhase = (phaseId: string) => {
    setSelectedPreset("custom");
    setSelectedPhases((prev) =>
      prev.includes(phaseId)
        ? prev.filter((p) => p !== phaseId)
        : [...prev, phaseId]
    );
  };

  const togglePlugin = (pluginName: string) => {
    setSelectedPlugins((prev) =>
      prev.includes(pluginName)
        ? prev.filter((p) => p !== pluginName)
        : [...prev, pluginName]
    );
  };

  return (
    <div className="p-6 max-w-4xl mx-auto space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold">New Scan</h1>
        <p className="text-muted-foreground">
          Configure and start a new security scan
        </p>
      </div>

      {/* LLM Warning */}
      {!isLLMConfigured && (
        <Card className="border-yellow-500/50 bg-yellow-500/10">
          <CardContent className="p-4 flex items-center gap-3">
            <AlertCircle className="h-5 w-5 text-yellow-500" />
            <div className="flex-1">
              <p className="font-medium">LLM not configured</p>
              <p className="text-sm text-muted-foreground">
                Configure an LLM provider in Settings for AI-powered analysis
              </p>
            </div>
            <Button variant="outline" size="sm" onClick={() => navigate("/settings")}>
              Configure
            </Button>
          </CardContent>
        </Card>
      )}

      {/* Main Form */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Target className="h-5 w-5" />
            Target Configuration
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Target URL */}
          <div className="space-y-2">
            <label className="text-sm font-medium">Target URL *</label>
            <Input
              placeholder="https://example.com"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              className="text-lg"
            />
            <p className="text-xs text-muted-foreground">
              Enter the base URL of the web application to scan
            </p>
          </div>

          {/* Scan Name (Optional) */}
          <div className="space-y-2">
            <label className="text-sm font-medium">
              Scan Name <span className="text-muted-foreground">(optional)</span>
            </label>
            <Input
              placeholder="My Security Scan"
              value={scanName}
              onChange={(e) => setScanName(e.target.value)}
            />
          </div>

          {/* Scan Presets */}
          <div className="space-y-3">
            <label className="text-sm font-medium">Scan Type</label>
            <div className="grid grid-cols-3 gap-3">
              {SCAN_PRESETS.map((preset) => (
                <div
                  key={preset.id}
                  className={cn(
                    "flex flex-col items-center gap-2 p-4 rounded-lg border cursor-pointer transition-all",
                    selectedPreset === preset.id
                      ? "border-primary bg-primary/10 shadow-sm"
                      : "border-border hover:bg-accent/50"
                  )}
                  onClick={() => handlePresetSelect(preset.id)}
                >
                  <div className={cn(
                    "p-2 rounded-full",
                    selectedPreset === preset.id ? "bg-primary text-primary-foreground" : "bg-muted"
                  )}>
                    {preset.icon}
                  </div>
                  <div className="text-center">
                    <p className="font-medium text-sm">{preset.name}</p>
                    <p className="text-xs text-muted-foreground">{preset.description}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Advanced Options Toggle */}
          <Button
            variant="ghost"
            className="w-full justify-between"
            onClick={() => setShowAdvanced(!showAdvanced)}
          >
            <span className="flex items-center gap-2">
              <Settings2 className="h-4 w-4" />
              Advanced Options
            </span>
            {showAdvanced ? (
              <ChevronUp className="h-4 w-4" />
            ) : (
              <ChevronDown className="h-4 w-4" />
            )}
          </Button>

          {/* Advanced Options */}
          {showAdvanced && (
            <div className="space-y-6 pt-4 border-t">
              {/* Scope Configuration */}
              <div className="space-y-2">
                <label className="text-sm font-medium flex items-center gap-2">
                  <FileText className="h-4 w-4" />
                  Scope Configuration
                </label>
                <textarea
                  className="w-full h-24 p-3 rounded-md border bg-background text-sm font-mono"
                  placeholder={`# Include patterns (one per line)\n*.example.com\napi.example.com/*\n\n# Exclude (prefix with !)\n!admin.example.com`}
                  value={scopeContent}
                  onChange={(e) => setScopeContent(e.target.value)}
                />
                <p className="text-xs text-muted-foreground">
                  Define URLs/patterns to include or exclude from scanning
                </p>
              </div>

              {/* Phase Selection */}
              <div className="space-y-3">
                <label className="text-sm font-medium">Scan Phases</label>
                <div className="grid gap-2">
                  {SCAN_PHASES.map((phase) => (
                    <div
                      key={phase.id}
                      className={cn(
                        "flex items-center justify-between p-3 rounded-lg border cursor-pointer transition-colors",
                        selectedPhases.includes(phase.id)
                          ? "border-primary bg-primary/5"
                          : "border-border hover:bg-accent/50"
                      )}
                      onClick={() => togglePhase(phase.id)}
                    >
                      <div className="flex items-center gap-3">
                        <span className="text-lg">{phase.icon}</span>
                        <div>
                          <p className="font-medium">{phase.name}</p>
                          <p className="text-xs text-muted-foreground">
                            {phase.description}
                          </p>
                        </div>
                      </div>
                      <div
                        className={cn(
                          "h-5 w-5 rounded-full border-2 flex items-center justify-center",
                          selectedPhases.includes(phase.id)
                            ? "border-primary bg-primary"
                            : "border-muted-foreground"
                        )}
                      >
                        {selectedPhases.includes(phase.id) && (
                          <div className="h-2 w-2 rounded-full bg-primary-foreground" />
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Plugin Selection */}
              <div className="space-y-3">
                <label className="text-sm font-medium">Plugins</label>
                <p className="text-xs text-muted-foreground">
                  Select specific plugins to use (leave empty for all enabled)
                </p>
                <div className="flex flex-wrap gap-2">
                  {pluginsData?.plugins.map((plugin) => (
                    <Badge
                      key={plugin.name}
                      variant={
                        selectedPlugins.includes(plugin.name)
                          ? "default"
                          : "outline"
                      }
                      className="cursor-pointer"
                      onClick={() => togglePlugin(plugin.name)}
                    >
                      {plugin.name}
                    </Badge>
                  ))}
                </div>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Start Button */}
      <Button
        size="lg"
        className="w-full"
        onClick={handleStartScan}
        disabled={createScan.isPending || !target.trim()}
      >
        {createScan.isPending ? (
          <>
            <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            Starting Scan...
          </>
        ) : (
          <>
            <Play className="mr-2 h-4 w-4" />
            Start Scan
          </>
        )}
      </Button>

      {/* Quick Tips */}
      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Quick Tips</CardTitle>
        </CardHeader>
        <CardContent className="text-sm text-muted-foreground space-y-2">
          <p>• Ensure you have authorization to scan the target</p>
          <p>• Use "Quick Scan" for fast initial assessment</p>
          <p>• Configure scope to limit scan to specific paths</p>
          <p>• Results are saved automatically during the scan</p>
        </CardContent>
      </Card>
    </div>
  );
}
                      )}
                      onClick={() => togglePhase(phase.id)}
                    >
                      <div>
                        <p className="font-medium">{phase.name}</p>
                        <p className="text-xs text-muted-foreground">
                          {phase.description}
                        </p>
                      </div>
                      <div
                        className={cn(
                          "h-5 w-5 rounded-full border-2 flex items-center justify-center",
                          selectedPhases.includes(phase.id)
                            ? "border-primary bg-primary"
                            : "border-muted-foreground"
                        )}
                      >
                        {selectedPhases.includes(phase.id) && (
                          <div className="h-2 w-2 rounded-full bg-primary-foreground" />
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Plugin Selection */}
              <div className="space-y-3">
                <label className="text-sm font-medium">Plugins</label>
                <p className="text-xs text-muted-foreground">
                  Select specific plugins to use (leave empty for all enabled)
                </p>
                <div className="flex flex-wrap gap-2">
                  {pluginsData?.plugins.map((plugin) => (
                    <Badge
                      key={plugin.name}
                      variant={
                        selectedPlugins.includes(plugin.name)
                          ? "default"
                          : "outline"
                      }
                      className="cursor-pointer"
                      onClick={() => togglePlugin(plugin.name)}
                    >
                      {plugin.name}
                    </Badge>
                  ))}
                </div>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Start Button */}
      <Button
        size="lg"
        className="w-full"
        onClick={handleStartScan}
        disabled={createScan.isPending || !target.trim()}
      >
        {createScan.isPending ? (
          <>
            <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            Starting Scan...
          </>
        ) : (
          <>
            <Play className="mr-2 h-4 w-4" />
            Start Scan
          </>
        )}
      </Button>

      {/* Quick Tips */}
      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Quick Tips</CardTitle>
        </CardHeader>
        <CardContent className="text-sm text-muted-foreground space-y-2">
          <p>• Ensure you have authorization to scan the target</p>
          <p>• Start with a smaller scope for faster results</p>
          <p>• Use advanced options to customize scan behavior</p>
          <p>• Results are saved automatically during the scan</p>
        </CardContent>
      </Card>
    </div>
  );
}

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
import { useTrixStore } from "@/lib/store";
import { cn } from "@/lib/utils";

const SCAN_PHASES = [
  { id: "RECONNAISSANCE", name: "信息收集", description: "目标信息搜集", icon: "🔍" },
  { id: "ENUMERATION", name: "枚举扫描", description: "内容与端点发现", icon: "📂" },
  { id: "VULNERABILITY_SCAN", name: "漏洞扫描", description: "自动化漏洞检测", icon: "🔬" },
  { id: "EXPLOITATION", name: "漏洞利用", description: "验证漏洞可利用性", icon: "💥" },
  { id: "VALIDATION", name: "验证确认", description: "发现结果验证", icon: "✅" },
];

const SCAN_PRESETS = [
  {
    id: "quick",
    name: "快速扫描",
    description: "快速侦察和基础漏洞扫描",
    phases: ["RECONNAISSANCE", "VULNERABILITY_SCAN"],
    icon: <Zap className="h-5 w-5" />,
  },
  {
    id: "full",
    name: "完整扫描",
    description: "全面的安全评估",
    phases: ["RECONNAISSANCE", "ENUMERATION", "VULNERABILITY_SCAN", "EXPLOITATION", "VALIDATION"],
    icon: <Shield className="h-5 w-5" />,
  },
  {
    id: "recon",
    name: "仅侦察",
    description: "仅进行信息收集",
    phases: ["RECONNAISSANCE", "ENUMERATION"],
    icon: <Target className="h-5 w-5" />,
  },
];

export default function ScanPage() {
  const navigate = useNavigate();
  const { toast } = useToast();
  const setActiveScan = useTrixStore((s) => s.setActiveScan);
  const addConsoleLog = useTrixStore((s) => s.addConsoleLog);

  const [target, setTarget] = useState("");
  const [scanName, setScanName] = useState("");
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [selectedPreset, setSelectedPreset] = useState("full");
  const [selectedPhases, setSelectedPhases] = useState<string[]>(
    SCAN_PHASES.map((p) => p.id)
  );
  const [selectedPlugins, setSelectedPlugins] = useState<string[]>([]);
  const [scopeContent, setScopeContent] = useState("");

  // 获取可用插件
  const { data: pluginsData } = useQuery({
    queryKey: ["plugins"],
    queryFn: () => pluginApi.list({ enabled_only: true }),
  });

  // 检查 LLM 配置
  const { data: llmConfig } = useQuery({
    queryKey: ["llm-config"],
    queryFn: settingsApi.getLLMConfig,
  });

  const isLLMConfigured = llmConfig?.config?.model && (
    Object.values(llmConfig?.configured_providers || {}).some(Boolean) ||
    llmConfig.config.model.startsWith("ollama/")
  );

  // 创建扫描
  const createScan = useMutation({
    mutationFn: scanApi.create,
    onSuccess: (scan) => {
      addConsoleLog(scan.id, {
        type: "info",
        source: "system",
        message: `扫描已创建: ${scan.id}`,
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
        title: "扫描已启动",
        description: `正在扫描 ${scan.target}`,
      });
      navigate(`/scan/${scan.id}`);
    },
    onError: (error: Error) => {
      toast({
        title: "启动扫描失败",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const handleStartScan = () => {
    if (!target.trim()) {
      toast({
        title: "需要目标地址",
        description: "请输入目标 URL",
        variant: "destructive",
      });
      return;
    }

    // 验证 URL
    try {
      new URL(target);
    } catch {
      toast({
        title: "无效的 URL",
        description: "请输入有效的 URL (例如: https://example.com)",
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
      {/* 页面头部 */}
      <div>
        <h1 className="text-3xl font-bold">新建扫描</h1>
        <p className="text-muted-foreground">
          配置并启动新的安全扫描
        </p>
      </div>

      {/* LLM 警告 */}
      {!isLLMConfigured && (
        <Card className="border-yellow-500/50 bg-yellow-500/10">
          <CardContent className="p-4 flex items-center gap-3">
            <AlertCircle className="h-5 w-5 text-yellow-500" />
            <div className="flex-1">
              <p className="font-medium">LLM 未配置</p>
              <p className="text-sm text-muted-foreground">
                请在设置中配置 LLM 提供商以启用 AI 分析功能
              </p>
            </div>
            <Button variant="outline" size="sm" onClick={() => navigate("/settings")}>
              去配置
            </Button>
          </CardContent>
        </Card>
      )}

      {/* 主表单 */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Target className="h-5 w-5" />
            目标配置
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* 目标 URL */}
          <div className="space-y-2">
            <label className="text-sm font-medium">目标 URL *</label>
            <Input
              placeholder="https://example.com"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              className="text-lg"
            />
            <p className="text-xs text-muted-foreground">
              输入要扫描的 Web 应用程序基础 URL
            </p>
          </div>

          {/* 扫描名称 (可选) */}
          <div className="space-y-2">
            <label className="text-sm font-medium">
              扫描名称 <span className="text-muted-foreground">(可选)</span>
            </label>
            <Input
              placeholder="我的安全扫描"
              value={scanName}
              onChange={(e) => setScanName(e.target.value)}
            />
          </div>

          {/* 扫描预设 */}
          <div className="space-y-3">
            <label className="text-sm font-medium">扫描类型</label>
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

          {/* 高级选项切换 */}
          <Button
            variant="ghost"
            className="w-full justify-between"
            onClick={() => setShowAdvanced(!showAdvanced)}
          >
            <span className="flex items-center gap-2">
              <Settings2 className="h-4 w-4" />
              高级选项
            </span>
            {showAdvanced ? (
              <ChevronUp className="h-4 w-4" />
            ) : (
              <ChevronDown className="h-4 w-4" />
            )}
          </Button>

          {/* 高级选项 */}
          {showAdvanced && (
            <div className="space-y-6 pt-4 border-t">
              {/* 范围配置 */}
              <div className="space-y-2">
                <label className="text-sm font-medium flex items-center gap-2">
                  <FileText className="h-4 w-4" />
                  范围配置
                </label>
                <textarea
                  className="w-full h-24 p-3 rounded-md border bg-background text-sm font-mono"
                  placeholder={`# 包含规则 (每行一个)\n*.example.com\napi.example.com/*\n\n# 排除规则 (以 ! 开头)\n!admin.example.com`}
                  value={scopeContent}
                  onChange={(e) => setScopeContent(e.target.value)}
                />
                <p className="text-xs text-muted-foreground">
                  定义要包含或排除的 URL/规则
                </p>
              </div>

              {/* 阶段选择 */}
              <div className="space-y-3">
                <label className="text-sm font-medium">扫描阶段</label>
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

              {/* 插件选择 */}
              <div className="space-y-3">
                <label className="text-sm font-medium">插件</label>
                <p className="text-xs text-muted-foreground">
                  选择要使用的特定插件 (留空则使用所有已启用的插件)
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

      {/* 开始按钮 */}
      <Button
        size="lg"
        className="w-full"
        onClick={handleStartScan}
        disabled={createScan.isPending || !target.trim()}
      >
        {createScan.isPending ? (
          <>
            <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            正在启动...
          </>
        ) : (
          <>
            <Play className="mr-2 h-4 w-4" />
            开始扫描
          </>
        )}
      </Button>

      {/* 快速提示 */}
      <Card>
        <CardHeader>
          <CardTitle className="text-sm">快速提示</CardTitle>
        </CardHeader>
        <CardContent className="text-sm text-muted-foreground space-y-2">
          <p>• 确保您有权限扫描目标</p>
          <p>• 使用"快速扫描"进行快速初步评估</p>
          <p>• 配置范围以限制扫描到特定路径</p>
          <p>• 扫描结果会自动保存</p>
        </CardContent>
      </Card>
    </div>
  );
}

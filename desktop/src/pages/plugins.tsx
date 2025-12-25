import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Puzzle,
  Download,
  RefreshCw,
  Check,
  X,
  Plus,
  Trash2,
  Play,
  Wrench,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { pluginApi } from "@/lib/api";
import { useToast } from "@/hooks/use-toast";
import { cn } from "@/lib/utils";

const API_BASE = "http://localhost:8000";

// 自定义插件 API
const customPluginApi = {
  list: async () => {
    const res = await fetch(`${API_BASE}/api/custom-plugins`);
    return res.json();
  },
  create: async (data: any) => {
    const res = await fetch(`${API_BASE}/api/custom-plugins`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
    });
    if (!res.ok) throw new Error((await res.json()).detail);
    return res.json();
  },
  delete: async (id: string) => {
    const res = await fetch(`${API_BASE}/api/custom-plugins/${id}`, {
      method: "DELETE",
    });
    return res.json();
  },
  test: async (id: string, target: string) => {
    const res = await fetch(`${API_BASE}/api/custom-plugins/${id}/test`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target, timeout: 30 }),
    });
    return res.json();
  },
  enable: async (id: string) => {
    const res = await fetch(`${API_BASE}/api/custom-plugins/${id}/enable`, {
      method: "POST",
    });
    return res.json();
  },
  disable: async (id: string) => {
    const res = await fetch(`${API_BASE}/api/custom-plugins/${id}/disable`, {
      method: "POST",
    });
    return res.json();
  },
};

interface CustomPlugin {
  id: string;
  name: string;
  command: string;
  description: string;
  use_cases: string[];
  input_type: string;
  output_format: string;
  enabled: boolean;
  icon: string;
}

export default function PluginsPage() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [showAddDialog, setShowAddDialog] = useState(false);
  const [testTarget, setTestTarget] = useState("");
  const [testingPlugin, setTestingPlugin] = useState<string | null>(null);

  // 获取内置插件
  const { data: pluginsData, isLoading } = useQuery({
    queryKey: ["plugins"],
    queryFn: () => pluginApi.list(),
  });

  // 获取自定义插件
  const { data: customPluginsData } = useQuery({
    queryKey: ["custom-plugins"],
    queryFn: () => customPluginApi.list(),
  });

  // 内置插件操作
  const installMutation = useMutation({
    mutationFn: (name: string) => pluginApi.install(name),
    onSuccess: (_, name) => {
      toast({ title: "插件已安装", description: `${name} 已准备就绪` });
      queryClient.invalidateQueries({ queryKey: ["plugins"] });
    },
    onError: (error: Error) => {
      toast({
        title: "安装失败",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const enableMutation = useMutation({
    mutationFn: (name: string) => pluginApi.enable(name),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["plugins"] }),
  });

  const disableMutation = useMutation({
    mutationFn: (name: string) => pluginApi.disable(name),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["plugins"] }),
  });

  // 自定义插件操作
  const createCustomMutation = useMutation({
    mutationFn: customPluginApi.create,
    onSuccess: () => {
      toast({ title: "自定义插件已创建" });
      queryClient.invalidateQueries({ queryKey: ["custom-plugins"] });
      setShowAddDialog(false);
    },
    onError: (error: Error) => {
      toast({
        title: "创建插件失败",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const deleteCustomMutation = useMutation({
    mutationFn: customPluginApi.delete,
    onSuccess: () => {
      toast({ title: "插件已删除" });
      queryClient.invalidateQueries({ queryKey: ["custom-plugins"] });
    },
  });

  const testCustomMutation = useMutation({
    mutationFn: ({ id, target }: { id: string; target: string }) =>
      customPluginApi.test(id, target),
    onSuccess: (result) => {
      toast({
        title: result.status === "success" ? "测试通过" : "测试失败",
        description: result.message || `退出码: ${result.return_code}`,
      });
      setTestingPlugin(null);
    },
  });

  // 按阶段分组内置插件
  const pluginsByPhase = pluginsData?.plugins.reduce(
    (acc, plugin) => {
      plugin.phases.forEach((phase) => {
        if (!acc[phase]) acc[phase] = [];
        acc[phase].push(plugin);
      });
      return acc;
    },
    {} as Record<string, typeof pluginsData.plugins>
  );

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-full">
        <RefreshCw className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      {/* 页面头部 */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">插件管理</h1>
          <p className="text-muted-foreground">
            管理安全扫描插件
          </p>
        </div>
        <div className="flex gap-2">
          <Button onClick={() => setShowAddDialog(true)}>
            <Plus className="mr-2 h-4 w-4" />
            添加自定义插件
          </Button>
          <Button variant="outline">
            <RefreshCw className="mr-2 h-4 w-4" />
            检查更新
          </Button>
        </div>
      </div>

      {/* 统计信息 */}
      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardContent className="p-4">
            <div className="text-2xl font-bold">
              {(pluginsData?.plugins.length || 0) +
                (customPluginsData?.plugins?.length || 0)}
            </div>
            <p className="text-sm text-muted-foreground">插件总数</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="text-2xl font-bold text-green-500">
              {pluginsData?.plugins.filter((p) => p.installed).length || 0}
            </div>
            <p className="text-sm text-muted-foreground">已安装</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="text-2xl font-bold text-blue-500">
              {pluginsData?.plugins.filter((p) => p.enabled).length || 0}
            </div>
            <p className="text-sm text-muted-foreground">已启用</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="text-2xl font-bold text-purple-500">
              {customPluginsData?.plugins?.length || 0}
            </div>
            <p className="text-sm text-muted-foreground">自定义插件</p>
          </CardContent>
        </Card>
      </div>

      {/* 自定义插件区域 */}
      {customPluginsData?.plugins?.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Wrench className="h-5 w-5" />
              自定义插件
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
              {customPluginsData.plugins.map((plugin: CustomPlugin) => (
                <div
                  key={plugin.id}
                  className={cn(
                    "p-4 rounded-lg border bg-card",
                    !plugin.enabled && "opacity-70"
                  )}
                >
                  <div className="flex items-start justify-between mb-3">
                    <div>
                      <h3 className="font-semibold flex items-center gap-2">
                        <span>{plugin.icon}</span>
                        {plugin.name}
                      </h3>
                      <Badge variant="outline" className="text-xs mt-1">
                        自定义
                      </Badge>
                    </div>
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() => deleteCustomMutation.mutate(plugin.id)}
                    >
                      <Trash2 className="h-4 w-4 text-red-500" />
                    </Button>
                  </div>

                  <p className="text-sm text-muted-foreground mb-2 line-clamp-2">
                    {plugin.description}
                  </p>

                  <div className="flex flex-wrap gap-1 mb-3">
                    {plugin.use_cases.slice(0, 2).map((uc) => (
                      <Badge key={uc} variant="secondary" className="text-xs">
                        {uc}
                      </Badge>
                    ))}
                  </div>

                  <div className="flex gap-2">
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => setTestingPlugin(plugin.id)}
                    >
                      <Play className="h-4 w-4 mr-1" />
                      测试
                    </Button>
                    <Button
                      size="sm"
                      variant={plugin.enabled ? "secondary" : "default"}
                      onClick={() =>
                        plugin.enabled
                          ? customPluginApi.disable(plugin.id).then(() =>
                            queryClient.invalidateQueries({
                              queryKey: ["custom-plugins"],
                            })
                          )
                          : customPluginApi.enable(plugin.id).then(() =>
                            queryClient.invalidateQueries({
                              queryKey: ["custom-plugins"],
                            })
                          )
                      }
                    >
                      {plugin.enabled ? "禁用" : "启用"}
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* 按阶段显示插件 */}
      {pluginsByPhase &&
        Object.entries(pluginsByPhase).map(([phase, plugins]) => (
          <Card key={phase}>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Puzzle className="h-5 w-5" />
                {formatPhaseName(phase)}
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
                {plugins.map((plugin) => (
                  <PluginCard
                    key={plugin.name}
                    plugin={plugin}
                    onInstall={() => installMutation.mutate(plugin.name)}
                    onEnable={() => enableMutation.mutate(plugin.name)}
                    onDisable={() => disableMutation.mutate(plugin.name)}
                    isInstalling={
                      installMutation.isPending &&
                      installMutation.variables === plugin.name
                    }
                  />
                ))}
              </div>
            </CardContent>
          </Card>
        ))}

      {/* 添加自定义插件对话框 */}
      <AddCustomPluginDialog
        open={showAddDialog}
        onClose={() => setShowAddDialog(false)}
        onSubmit={(data) => createCustomMutation.mutate(data)}
        isLoading={createCustomMutation.isPending}
      />

      {/* 测试插件对话框 */}
      <Dialog
        open={!!testingPlugin}
        onOpenChange={() => setTestingPlugin(null)}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>测试插件</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <Label>目标地址</Label>
              <Input
                placeholder="https://example.com"
                value={testTarget}
                onChange={(e) => setTestTarget(e.target.value)}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setTestingPlugin(null)}>
              取消
            </Button>
            <Button
              onClick={() => {
                if (testingPlugin && testTarget) {
                  testCustomMutation.mutate({
                    id: testingPlugin,
                    target: testTarget,
                  });
                }
              }}
              disabled={testCustomMutation.isPending || !testTarget}
            >
              {testCustomMutation.isPending ? (
                <RefreshCw className="h-4 w-4 animate-spin" />
              ) : (
                <>
                  <Play className="h-4 w-4 mr-2" />
                  运行测试
                </>
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function AddCustomPluginDialog({
  open,
  onClose,
  onSubmit,
  isLoading,
}: {
  open: boolean;
  onClose: () => void;
  onSubmit: (data: any) => void;
  isLoading: boolean;
}) {
  const [formData, setFormData] = useState({
    name: "",
    command: "",
    description: "",
    use_cases: "",
    capabilities: [] as string[],
    phases: [] as string[],
    input_type: "url",
    output_format: "lines",
    icon: "🔧",
  });

  // Available options
  const availableCapabilities = [
    "WEB_SCANNING", "API_TESTING", "VULNERABILITY_DETECTION", "SQL_INJECTION",
    "XSS_DETECTION", "FUZZING", "CRAWLING", "PORT_SCANNING", "SUBDOMAIN_ENUM",
    "TECHNOLOGY_DETECTION", "SECRET_SCANNING", "CONTENT_DISCOVERY"
  ];

  const availablePhases = [
    "RECONNAISSANCE", "ENUMERATION", "VULNERABILITY_SCAN", "EXPLOITATION", "VALIDATION"
  ];

  const handleSubmit = () => {
    onSubmit({
      ...formData,
      use_cases: formData.use_cases
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean),
    });
  };

  const toggleCapability = (cap: string) => {
    setFormData(prev => ({
      ...prev,
      capabilities: prev.capabilities.includes(cap)
        ? prev.capabilities.filter(c => c !== cap)
        : [...prev.capabilities, cap]
    }));
  };

  const togglePhase = (phase: string) => {
    setFormData(prev => ({
      ...prev,
      phases: prev.phases.includes(phase)
        ? prev.phases.filter(p => p !== phase)
        : [...prev.phases, phase]
    }));
  };

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>添加自定义插件</DialogTitle>
        </DialogHeader>

        <div className="space-y-4">
          <div>
            <Label>插件名称 *</Label>
            <Input
              placeholder="my-scanner"
              value={formData.name}
              onChange={(e) =>
                setFormData({ ...formData, name: e.target.value })
              }
            />
          </div>

          <div>
            <Label>执行命令 * (使用 {"{target}"} 作为目标占位符)</Label>
            <Input
              placeholder="nuclei -u {target} -silent"
              value={formData.command}
              onChange={(e) =>
                setFormData({ ...formData, command: e.target.value })
              }
            />
          </div>

          <div>
            <Label>功能描述 * (LLM 将根据此描述决定何时调用)</Label>
            <Textarea
              placeholder="扫描 SQL 注入漏洞..."
              value={formData.description}
              onChange={(e) =>
                setFormData({ ...formData, description: e.target.value })
              }
            />
          </div>

          <div>
            <Label>适用场景 (用逗号分隔)</Label>
            <Input
              placeholder="漏洞扫描, CVE 检测"
              value={formData.use_cases}
              onChange={(e) =>
                setFormData({ ...formData, use_cases: e.target.value })
              }
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <Label>输入类型</Label>
              <Select
                value={formData.input_type}
                onValueChange={(v) =>
                  setFormData({ ...formData, input_type: v })
                }
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="url">URL</SelectItem>
                  <SelectItem value="domain">域名</SelectItem>
                  <SelectItem value="ip">IP 地址</SelectItem>
                  <SelectItem value="file">文件</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div>
              <Label>输出格式</Label>
              <Select
                value={formData.output_format}
                onValueChange={(v) =>
                  setFormData({ ...formData, output_format: v })
                }
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="json">JSON</SelectItem>
                  <SelectItem value="lines">按行</SelectItem>
                  <SelectItem value="regex">正则匹配</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          <div>
            <Label>扫描阶段 (可多选)</Label>
            <div className="flex flex-wrap gap-2 mt-2">
              {availablePhases.map((phase) => (
                <Badge
                  key={phase}
                  variant={formData.phases.includes(phase) ? "default" : "outline"}
                  className="cursor-pointer"
                  onClick={() => togglePhase(phase)}
                >
                  {phase === "RECONNAISSANCE" ? "侦察" :
                    phase === "ENUMERATION" ? "枚举" :
                      phase === "VULNERABILITY_SCAN" ? "漏洞扫描" :
                        phase === "EXPLOITATION" ? "利用" :
                          phase === "VALIDATION" ? "验证" : phase}
                </Badge>
              ))}
            </div>
          </div>

          <div>
            <Label>插件能力 (可多选)</Label>
            <div className="flex flex-wrap gap-2 mt-2">
              {availableCapabilities.map((cap) => (
                <Badge
                  key={cap}
                  variant={formData.capabilities.includes(cap) ? "default" : "outline"}
                  className="cursor-pointer text-xs"
                  onClick={() => toggleCapability(cap)}
                >
                  {(() => {
                    const translations: Record<string, string> = {
                      WEB_SCANNING: "Web 扫描",
                      API_TESTING: "API 测试",
                      VULNERABILITY_DETECTION: "漏洞检测",
                      SQL_INJECTION: "SQL 注入",
                      XSS_DETECTION: "XSS 检测",
                      FUZZING: "模糊测试",
                      CRAWLING: "爬虫/爬取",
                      PORT_SCANNING: "端口扫描",
                      SUBDOMAIN_ENUM: "子域名枚举",
                      TECHNOLOGY_DETECTION: "技术栈识别",
                      SECRET_SCANNING: "敏感信息扫描",
                      CONTENT_DISCOVERY: "内容发现"
                    };
                    return translations[cap] || cap.replace(/_/g, " ");
                  })()}
                </Badge>
              ))}
            </div>
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            取消
          </Button>
          <Button
            onClick={handleSubmit}
            disabled={
              isLoading ||
              !formData.name ||
              !formData.command ||
              !formData.description
            }
          >
            {isLoading ? (
              <RefreshCw className="h-4 w-4 animate-spin" />
            ) : (
              <>
                <Plus className="h-4 w-4 mr-2" />
                添加插件
              </>
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function PluginCard({
  plugin,
  onInstall,
  onEnable,
  onDisable,
  isInstalling,
}: {
  plugin: {
    name: string;
    version: string;
    description: string | null;
    author: string | null;
    capabilities: string[];
    installed: boolean;
    enabled: boolean;
  };
  onInstall: () => void;
  onEnable: () => void;
  onDisable: () => void;
  isInstalling: boolean;
}) {
  return (
    <div
      className={cn(
        "p-4 rounded-lg border bg-card",
        !plugin.installed && "opacity-70"
      )}
    >
      <div className="flex items-start justify-between mb-3">
        <div>
          <h3 className="font-semibold">{plugin.name}</h3>
          <p className="text-xs text-muted-foreground">v{plugin.version}</p>
        </div>
        <div className="flex items-center gap-1">
          {plugin.installed ? (
            <Badge variant="secondary" className="text-xs">
              <Check className="h-3 w-3 mr-1" />
              已安装
            </Badge>
          ) : (
            <Badge variant="outline" className="text-xs">
              未安装
            </Badge>
          )}
        </div>
      </div>

      <p className="text-sm text-muted-foreground mb-3 line-clamp-2">
        {plugin.description || "暂无描述"}
      </p>

      <div className="flex flex-wrap gap-1 mb-4">
        {plugin.capabilities.slice(0, 3).map((cap) => (
          <Badge key={cap} variant="outline" className="text-xs">
            {cap.toLowerCase().replace(/_/g, " ")}
          </Badge>
        ))}
      </div>

      <div className="flex items-center justify-between">
        {plugin.author && (
          <span className="text-xs text-muted-foreground">
            作者: {plugin.author}
          </span>
        )}
        <div className="flex gap-2">
          {!plugin.installed ? (
            <Button size="sm" onClick={onInstall} disabled={isInstalling}>
              {isInstalling ? (
                <RefreshCw className="h-4 w-4 animate-spin" />
              ) : (
                <>
                  <Download className="h-4 w-4 mr-1" />
                  安装
                </>
              )}
            </Button>
          ) : (
            <Button
              size="sm"
              variant={plugin.enabled ? "secondary" : "default"}
              onClick={plugin.enabled ? onDisable : onEnable}
            >
              {plugin.enabled ? (
                <>
                  <X className="h-4 w-4 mr-1" />
                  禁用
                </>
              ) : (
                <>
                  <Check className="h-4 w-4 mr-1" />
                  启用
                </>
              )}
            </Button>
          )}
        </div>
      </div>
    </div>
  );
}

function formatPhaseName(phase: string): string {
  const phaseNames: Record<string, string> = {
    RECONNAISSANCE: "信息收集",
    ENUMERATION: "枚举扫描",
    VULNERABILITY_SCAN: "漏洞扫描",
    EXPLOITATION: "漏洞利用",
    POST_EXPLOITATION: "后渗透",
    VALIDATION: "验证确认",
    REPORTING: "报告生成",
  };
  return phaseNames[phase] || phase
    .split("_")
    .map((word) => word.charAt(0) + word.slice(1).toLowerCase())
    .join(" ");
}

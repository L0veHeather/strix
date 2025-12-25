import { useState, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useSettingsStore } from "@/lib/store";
import { useTheme } from "@/components/theme-provider";
import { settingsApi, LLMConfig } from "@/lib/api";
import { useToast } from "@/hooks/use-toast";
import {
  Settings,
  Moon,
  Sun,
  Monitor,
  Server,
  Bell,
  Download,
  Brain,
  Key,
  Check,
  Loader2,
  Eye,
  EyeOff,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

export default function SettingsPage() {
  const { theme, setTheme } = useTheme();
  const settings = useSettingsStore();
  const { toast } = useToast();
  const queryClient = useQueryClient();

  // LLM 状态
  const [selectedProvider, setSelectedProvider] = useState<string>("openai");
  const [selectedModel, setSelectedModel] = useState<string>("");
  const [apiKey, setApiKey] = useState<string>("");
  const [apiBase, setApiBase] = useState<string>("");
  const [showApiKey, setShowApiKey] = useState(false);
  const [timeout, setTimeoutValue] = useState<number>(600);
  const [enableCaching, setEnableCaching] = useState(true);

  // 获取提供商列表
  const { data: providersData } = useQuery({
    queryKey: ["llm-providers"],
    queryFn: settingsApi.getProviders,
  });

  // 获取当前 LLM 配置
  const { data: llmConfigData } = useQuery({
    queryKey: ["llm-config"],
    queryFn: settingsApi.getLLMConfig,
  });

  // 更新配置
  const updateConfig = useMutation({
    mutationFn: settingsApi.updateLLMConfig,
    onSuccess: () => {
      toast({ title: "设置已保存", description: "LLM 配置已更新" });
      queryClient.invalidateQueries({ queryKey: ["llm-config"] });
    },
    onError: (error: Error) => {
      toast({ title: "保存失败", description: error.message, variant: "destructive" });
    },
  });

  // 测试连接
  const testConnection = useMutation({
    mutationFn: settingsApi.testLLMConnection,
    onSuccess: (data) => {
      if (data.status === "success") {
        toast({ title: "连接成功", description: `模型: ${data.model}` });
      } else if (data.status === "warning") {
        toast({ title: "配置已保存", description: data.message });
      } else {
        toast({ title: "连接失败", description: data.message, variant: "destructive" });
      }
    },
    onError: (error: Error) => {
      toast({ title: "测试失败", description: error.message, variant: "destructive" });
    },
  });

  // 从获取的配置初始化
  useEffect(() => {
    if (llmConfigData?.config) {
      const config = llmConfigData.config;
      setSelectedModel(config.model || "openai/gpt-4o");
      setTimeoutValue(config.timeout || 600);
      setEnableCaching(config.enable_caching ?? true);
      if (config.api_base) setApiBase(config.api_base);

      const provider = config.model?.split("/")[0] || "openai";
      setSelectedProvider(provider);
    }
  }, [llmConfigData]);

  // 默认提供商（作为 API 不可用时的后备）
  const DEFAULT_PROVIDERS = [
    {
      id: "openai",
      name: "OpenAI",
      models: [
        { id: "openai/gpt-4o", name: "GPT-4o", description: "最强大的模型" },
        { id: "openai/gpt-4o-mini", name: "GPT-4o Mini", description: "快速高效" },
        { id: "openai/o1-preview", name: "o1 Preview", description: "推理模型" },
      ],
      requires_key: true,
      key_env: "OPENAI_API_KEY",
    },
    {
      id: "anthropic",
      name: "Anthropic",
      models: [
        { id: "anthropic/claude-sonnet-4-20250514", name: "Claude Sonnet 4", description: "最新 Sonnet" },
        { id: "anthropic/claude-3-5-sonnet-20241022", name: "Claude 3.5 Sonnet", description: "均衡型" },
        { id: "anthropic/claude-3-opus-20240229", name: "Claude 3 Opus", description: "最强大" },
      ],
      requires_key: true,
      key_env: "ANTHROPIC_API_KEY",
    },
    {
      id: "deepseek",
      name: "DeepSeek",
      models: [
        { id: "deepseek/deepseek-chat", name: "DeepSeek Chat", description: "通用对话" },
        { id: "deepseek/deepseek-reasoner", name: "DeepSeek Reasoner", description: "推理模型 (R1)" },
      ],
      requires_key: true,
      key_env: "DEEPSEEK_API_KEY",
    },
    {
      id: "ollama",
      name: "Ollama (本地)",
      models: [
        { id: "ollama/llama3.3:70b", name: "Llama 3.3 70B", description: "大型本地模型" },
        { id: "ollama/llama3.2:latest", name: "Llama 3.2", description: "快速本地模型" },
        { id: "ollama/qwen2.5:32b", name: "Qwen 2.5 32B", description: "中英双语" },
        { id: "ollama/deepseek-r1:14b", name: "DeepSeek R1 14B", description: "推理 (本地)" },
      ],
      requires_key: false,
      default_base: "http://localhost:11434",
    },
    {
      id: "custom",
      name: "自定义",
      models: [],
      requires_key: true,
      supports_custom_base: true,
    },
  ];

  const providers = (providersData?.providers && providersData.providers.length > 0) ? providersData.providers : DEFAULT_PROVIDERS;
  const currentProvider = providers.find((p: any) => p.id === selectedProvider);
  const configuredProviders = llmConfigData?.configured_providers || {};

  const handleSave = () => {
    const config: Partial<LLMConfig> = {
      model: selectedModel,
      timeout,
      enable_caching: enableCaching,
    };

    if (apiKey && !apiKey.includes("...")) {
      config.api_key = apiKey;
    }

    if (apiBase) {
      config.api_base = apiBase;
    }

    updateConfig.mutate(config);
  };

  return (
    <div className="p-6 max-w-4xl mx-auto space-y-6">
      {/* 页面头部 */}
      <div>
        <h1 className="text-3xl font-bold">设置</h1>
        <p className="text-muted-foreground">配置 Trix 偏好设置</p>
      </div>

      {/* LLM 配置 */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Brain className="h-5 w-5" />
            LLM 配置
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-6">
          {/* 提供商选择 */}
          <div className="space-y-2">
            <label className="text-sm font-medium">提供商</label>
            <div className="grid grid-cols-2 md:grid-cols-5 gap-2">
              {providers.map((provider) => (
                <Button
                  key={provider.id}
                  variant={selectedProvider === provider.id ? "default" : "outline"}
                  className="justify-start"
                  onClick={() => {
                    setSelectedProvider(provider.id);
                    if (provider.models.length > 0) {
                      setSelectedModel(provider.models[0].id);
                    }
                    setApiKey("");
                  }}
                >
                  <span className="truncate">{provider.name}</span>
                  {configuredProviders[provider.id] && (
                    <Check className="ml-auto h-4 w-4 text-green-500" />
                  )}
                </Button>
              ))}
            </div>
          </div>

          {/* 模型选择 */}
          {currentProvider && currentProvider.models.length > 0 && (
            <div className="space-y-2">
              <label className="text-sm font-medium">模型</label>
              <div className="grid gap-2">
                {currentProvider.models.map((model) => (
                  <div
                    key={model.id}
                    className={cn(
                      "flex items-center justify-between p-3 rounded-lg border cursor-pointer transition-colors",
                      selectedModel === model.id
                        ? "border-primary bg-primary/5"
                        : "border-border hover:bg-accent/50"
                    )}
                    onClick={() => setSelectedModel(model.id)}
                  >
                    <div>
                      <p className="font-medium">{model.name}</p>
                      <p className="text-xs text-muted-foreground">{model.description}</p>
                    </div>
                    {selectedModel === model.id && (
                      <Check className="h-4 w-4 text-primary" />
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* 自定义模型输入 */}
          {currentProvider?.id === "custom" && (
            <div className="space-y-2">
              <label className="text-sm font-medium">模型名称</label>
              <Input
                value={selectedModel}
                onChange={(e) => setSelectedModel(e.target.value)}
                placeholder="例如: openai/gpt-4o 或 ollama/llama3.2"
              />
            </div>
          )}

          {/* API Key */}
          {(currentProvider?.requires_key || selectedProvider !== "ollama") && (
            <div className="space-y-3 p-4 bg-muted/30 rounded-lg border">
              <label className="text-sm font-medium flex items-center gap-2">
                <Key className="h-4 w-4" />
                {currentProvider?.name || selectedProvider} 的 API Key
                {configuredProviders[selectedProvider] && (
                  <Badge variant="secondary" className="ml-2 bg-green-500/20 text-green-600">✓ 已配置</Badge>
                )}
              </label>
              <div className="flex gap-2">
                <div className="relative flex-1">
                  <Input
                    type={showApiKey ? "text" : "password"}
                    value={apiKey}
                    onChange={(e) => setApiKey(e.target.value)}
                    placeholder={
                      configuredProviders[selectedProvider]
                        ? "输入新密钥以更新..."
                        : `输入您的 ${currentProvider?.name || selectedProvider} API 密钥`
                    }
                    className="pr-10 font-mono text-sm"
                  />
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    className="absolute right-0 top-0 h-full px-3"
                    onClick={() => setShowApiKey(!showApiKey)}
                  >
                    {showApiKey ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                  </Button>
                </div>
              </div>

              {/* LiteLLM 提供商说明 */}
              <div className="text-xs space-y-2 p-3 bg-background/50 rounded border border-dashed">
                <p className="font-medium text-foreground">LiteLLM 配置说明:</p>
                {selectedProvider === "openai" && (
                  <>
                    <p>• 环境变量: <code className="bg-muted px-1 rounded">OPENAI_API_KEY</code></p>
                    <p>• 模型格式: <code className="bg-muted px-1 rounded">openai/gpt-4o</code>, <code className="bg-muted px-1 rounded">openai/gpt-4o-mini</code></p>
                    <p className="text-muted-foreground">获取密钥: https://platform.openai.com/api-keys</p>
                  </>
                )}
                {selectedProvider === "anthropic" && (
                  <>
                    <p>• 环境变量: <code className="bg-muted px-1 rounded">ANTHROPIC_API_KEY</code></p>
                    <p>• 模型格式: <code className="bg-muted px-1 rounded">anthropic/claude-3-5-sonnet-20241022</code></p>
                    <p className="text-muted-foreground">获取密钥: https://console.anthropic.com/settings/keys</p>
                  </>
                )}
                {selectedProvider === "deepseek" && (
                  <>
                    <p>• 环境变量: <code className="bg-muted px-1 rounded">DEEPSEEK_API_KEY</code></p>
                    <p>• 模型格式: <code className="bg-muted px-1 rounded">deepseek/deepseek-chat</code>, <code className="bg-muted px-1 rounded">deepseek/deepseek-reasoner</code></p>
                    <p className="text-muted-foreground">获取密钥: https://platform.deepseek.com/api_keys</p>
                  </>
                )}
                {selectedProvider === "ollama" && (
                  <>
                    <p>• 无需 API 密钥 (本地运行)</p>
                    <p>• 模型格式: <code className="bg-muted px-1 rounded">ollama/llama3.2</code>, <code className="bg-muted px-1 rounded">ollama/qwen2.5</code></p>
                    <p className="text-muted-foreground">确保 Ollama 正在运行: ollama serve</p>
                  </>
                )}
                {selectedProvider === "custom" && (
                  <>
                    <p>• 在下方设置 API 密钥和基础 URL</p>
                    <p>• 模型格式: <code className="bg-muted px-1 rounded">provider/model-name</code></p>
                  </>
                )}
              </div>
            </div>
          )}

          {/* API 基础 URL */}
          {(currentProvider?.default_base || currentProvider?.supports_custom_base) && (
            <div className="space-y-2">
              <label className="text-sm font-medium">API 基础 URL</label>
              <Input
                value={apiBase}
                onChange={(e) => setApiBase(e.target.value)}
                placeholder={currentProvider.default_base || "http://localhost:11434"}
              />
              <p className="text-xs text-muted-foreground">
                自定义 API 端点 (留空使用默认值)
              </p>
            </div>
          )}

          {/* 高级设置 */}
          <div className="space-y-4 pt-4 border-t">
            <h4 className="text-sm font-medium">高级设置</h4>

            <div className="grid gap-4 md:grid-cols-2">
              <div className="space-y-2">
                <label className="text-sm">超时时间 (秒)</label>
                <Input
                  type="number"
                  value={timeout}
                  onChange={(e) => setTimeoutValue(parseInt(e.target.value) || 600)}
                  min={30}
                  max={3600}
                />
              </div>

              <div className="flex items-center justify-between p-3 rounded-lg border">
                <div>
                  <p className="text-sm font-medium">提示缓存</p>
                  <p className="text-xs text-muted-foreground">仅限 Anthropic</p>
                </div>
                <Button
                  variant={enableCaching ? "default" : "outline"}
                  size="sm"
                  onClick={() => setEnableCaching(!enableCaching)}
                >
                  {enableCaching ? "已启用" : "已禁用"}
                </Button>
              </div>
            </div>
          </div>

          {/* 操作按钮 */}
          <div className="flex gap-2 pt-4">
            <Button onClick={handleSave} disabled={updateConfig.isPending}>
              {updateConfig.isPending ? (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              ) : (
                <Check className="mr-2 h-4 w-4" />
              )}
              保存配置
            </Button>
            <Button
              variant="outline"
              onClick={() => testConnection.mutate()}
              disabled={testConnection.isPending}
            >
              {testConnection.isPending ? (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              ) : null}
              测试连接
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* 外观 */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Sun className="h-5 w-5" />
            外观
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <div>
              <label className="text-sm font-medium">主题</label>
              <div className="flex gap-2 mt-2">
                <Button
                  variant={theme === "light" ? "default" : "outline"}
                  className="flex-1"
                  onClick={() => setTheme("light")}
                >
                  <Sun className="mr-2 h-4 w-4" />
                  浅色
                </Button>
                <Button
                  variant={theme === "dark" ? "default" : "outline"}
                  className="flex-1"
                  onClick={() => setTheme("dark")}
                >
                  <Moon className="mr-2 h-4 w-4" />
                  深色
                </Button>
                <Button
                  variant={theme === "system" ? "default" : "outline"}
                  className="flex-1"
                  onClick={() => setTheme("system")}
                >
                  <Monitor className="mr-2 h-4 w-4" />
                  跟随系统
                </Button>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* 服务器连接 */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Server className="h-5 w-5" />
            服务器连接
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <label className="text-sm font-medium">API 地址</label>
            <Input
              value={settings.apiUrl}
              onChange={(e) => settings.setApiUrl(e.target.value)}
              placeholder="http://localhost:8000"
            />
          </div>
          <div className="space-y-2">
            <label className="text-sm font-medium">WebSocket 地址</label>
            <Input
              value={settings.wsUrl}
              onChange={(e) => settings.setWsUrl(e.target.value)}
              placeholder="ws://localhost:8000/ws"
            />
          </div>
        </CardContent>
      </Card>

      {/* 插件 */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Download className="h-5 w-5" />
            插件
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-between">
            <div>
              <p className="font-medium">自动安装插件</p>
              <p className="text-sm text-muted-foreground">
                需要时自动安装缺失的插件
              </p>
            </div>
            <Button
              variant={settings.autoInstallPlugins ? "default" : "outline"}
              size="sm"
              onClick={() => settings.setAutoInstallPlugins(!settings.autoInstallPlugins)}
            >
              {settings.autoInstallPlugins ? "已启用" : "已禁用"}
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* 通知 */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Bell className="h-5 w-5" />
            通知
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-between">
            <div>
              <p className="font-medium">启用通知</p>
              <p className="text-sm text-muted-foreground">
                显示扫描事件通知
              </p>
            </div>
            <Button
              variant={settings.notificationsEnabled ? "default" : "outline"}
              size="sm"
              onClick={() => settings.setNotificationsEnabled(!settings.notificationsEnabled)}
            >
              {settings.notificationsEnabled ? "已启用" : "已禁用"}
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* 关于 */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Settings className="h-5 w-5" />
            关于
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            <div className="flex justify-between">
              <span className="text-muted-foreground">版本</span>
              <span className="font-medium">2.0.0</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">许可证</span>
              <span className="font-medium">MIT</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">当前 LLM</span>
              <span className="font-medium">{selectedModel || "未配置"}</span>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

import { useState, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useSettingsStore } from "@/lib/store";
import { useTheme } from "@/components/theme-provider";
import { settingsApi, LLMProvider, LLMConfig } from "@/lib/api";
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

  // LLM State
  const [selectedProvider, setSelectedProvider] = useState<string>("openai");
  const [selectedModel, setSelectedModel] = useState<string>("");
  const [apiKey, setApiKey] = useState<string>("");
  const [apiBase, setApiBase] = useState<string>("");
  const [showApiKey, setShowApiKey] = useState(false);
  const [timeout, setTimeoutValue] = useState<number>(600);
  const [enableCaching, setEnableCaching] = useState(true);

  // Fetch providers
  const { data: providersData } = useQuery({
    queryKey: ["llm-providers"],
    queryFn: settingsApi.getProviders,
  });

  // Fetch current LLM config
  const { data: llmConfigData } = useQuery({
    queryKey: ["llm-config"],
    queryFn: settingsApi.getLLMConfig,
  });

  // Update config mutation
  const updateConfig = useMutation({
    mutationFn: settingsApi.updateLLMConfig,
    onSuccess: () => {
      toast({ title: "Settings saved", description: "LLM configuration updated" });
      queryClient.invalidateQueries({ queryKey: ["llm-config"] });
    },
    onError: (error: Error) => {
      toast({ title: "Failed to save", description: error.message, variant: "destructive" });
    },
  });

  // Test connection mutation
  const testConnection = useMutation({
    mutationFn: settingsApi.testLLMConnection,
    onSuccess: (data) => {
      if (data.status === "success") {
        toast({ title: "Connection successful", description: `Model: ${data.model}` });
      } else if (data.status === "warning") {
        toast({ title: "Configuration saved", description: data.message });
      } else {
        toast({ title: "Connection failed", description: data.message, variant: "destructive" });
      }
    },
    onError: (error: Error) => {
      toast({ title: "Test failed", description: error.message, variant: "destructive" });
    },
  });

  // Initialize from fetched config
  useEffect(() => {
    if (llmConfigData?.config) {
      const config = llmConfigData.config;
      setSelectedModel(config.model || "openai/gpt-4o");
      setTimeoutValue(config.timeout || 600);
      setEnableCaching(config.enable_caching ?? true);
      if (config.api_base) setApiBase(config.api_base);
      
      // Determine provider from model
      const provider = config.model?.split("/")[0] || "openai";
      setSelectedProvider(provider);
    }
  }, [llmConfigData]);

  const providers = providersData?.providers || [];
  const currentProvider = providers.find((p) => p.id === selectedProvider);
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
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold">Settings</h1>
        <p className="text-muted-foreground">Configure Strix preferences</p>
      </div>

      {/* LLM Configuration */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Brain className="h-5 w-5" />
            LLM Configuration
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-6">
          {/* Provider Selection */}
          <div className="space-y-2">
            <label className="text-sm font-medium">Provider</label>
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

          {/* Model Selection */}
          {currentProvider && currentProvider.models.length > 0 && (
            <div className="space-y-2">
              <label className="text-sm font-medium">Model</label>
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

          {/* Custom Model Input */}
          {currentProvider?.id === "custom" && (
            <div className="space-y-2">
              <label className="text-sm font-medium">Model Name</label>
              <Input
                value={selectedModel}
                onChange={(e) => setSelectedModel(e.target.value)}
                placeholder="e.g., openai/gpt-4o or ollama/llama3.2"
              />
            </div>
          )}

          {/* API Key */}
          {currentProvider?.requires_key && (
            <div className="space-y-2">
              <label className="text-sm font-medium flex items-center gap-2">
                <Key className="h-4 w-4" />
                API Key
                {configuredProviders[selectedProvider] && (
                  <Badge variant="secondary" className="ml-2">Configured</Badge>
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
                        ? "••••••••••••••••"
                        : `Enter ${currentProvider.name} API key`
                    }
                    className="pr-10"
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
              {currentProvider.key_env && (
                <p className="text-xs text-muted-foreground">
                  Or set environment variable: <code className="bg-muted px-1 rounded">{currentProvider.key_env}</code>
                </p>
              )}
            </div>
          )}

          {/* API Base URL */}
          {(currentProvider?.default_base || currentProvider?.supports_custom_base) && (
            <div className="space-y-2">
              <label className="text-sm font-medium">API Base URL</label>
              <Input
                value={apiBase}
                onChange={(e) => setApiBase(e.target.value)}
                placeholder={currentProvider.default_base || "http://localhost:11434"}
              />
              <p className="text-xs text-muted-foreground">
                Custom API endpoint (leave empty for default)
              </p>
            </div>
          )}

          {/* Advanced Settings */}
          <div className="space-y-4 pt-4 border-t">
            <h4 className="text-sm font-medium">Advanced</h4>
            
            <div className="grid gap-4 md:grid-cols-2">
              <div className="space-y-2">
                <label className="text-sm">Timeout (seconds)</label>
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
                  <p className="text-sm font-medium">Prompt Caching</p>
                  <p className="text-xs text-muted-foreground">Anthropic only</p>
                </div>
                <Button
                  variant={enableCaching ? "default" : "outline"}
                  size="sm"
                  onClick={() => setEnableCaching(!enableCaching)}
                >
                  {enableCaching ? "Enabled" : "Disabled"}
                </Button>
              </div>
            </div>
          </div>

          {/* Actions */}
          <div className="flex gap-2 pt-4">
            <Button onClick={handleSave} disabled={updateConfig.isPending}>
              {updateConfig.isPending ? (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              ) : (
                <Check className="mr-2 h-4 w-4" />
              )}
              Save Configuration
            </Button>
            <Button
              variant="outline"
              onClick={() => testConnection.mutate()}
              disabled={testConnection.isPending}
            >
              {testConnection.isPending ? (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              ) : null}
              Test Connection
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Appearance */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Sun className="h-5 w-5" />
            Appearance
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <div>
              <label className="text-sm font-medium">Theme</label>
              <div className="flex gap-2 mt-2">
                <Button
                  variant={theme === "light" ? "default" : "outline"}
                  className="flex-1"
                  onClick={() => setTheme("light")}
                >
                  <Sun className="mr-2 h-4 w-4" />
                  Light
                </Button>
                <Button
                  variant={theme === "dark" ? "default" : "outline"}
                  className="flex-1"
                  onClick={() => setTheme("dark")}
                >
                  <Moon className="mr-2 h-4 w-4" />
                  Dark
                </Button>
                <Button
                  variant={theme === "system" ? "default" : "outline"}
                  className="flex-1"
                  onClick={() => setTheme("system")}
                >
                  <Monitor className="mr-2 h-4 w-4" />
                  System
                </Button>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Server Connection */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Server className="h-5 w-5" />
            Server Connection
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <label className="text-sm font-medium">API URL</label>
            <Input
              value={settings.apiUrl}
              onChange={(e) => settings.setApiUrl(e.target.value)}
              placeholder="http://localhost:8000"
            />
          </div>
          <div className="space-y-2">
            <label className="text-sm font-medium">WebSocket URL</label>
            <Input
              value={settings.wsUrl}
              onChange={(e) => settings.setWsUrl(e.target.value)}
              placeholder="ws://localhost:8000/ws"
            />
          </div>
        </CardContent>
      </Card>

      {/* Plugins */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Download className="h-5 w-5" />
            Plugins
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-between">
            <div>
              <p className="font-medium">Auto-install plugins</p>
              <p className="text-sm text-muted-foreground">
                Automatically install missing plugins when needed
              </p>
            </div>
            <Button
              variant={settings.autoInstallPlugins ? "default" : "outline"}
              size="sm"
              onClick={() => settings.setAutoInstallPlugins(!settings.autoInstallPlugins)}
            >
              {settings.autoInstallPlugins ? "Enabled" : "Disabled"}
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Notifications */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Bell className="h-5 w-5" />
            Notifications
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-between">
            <div>
              <p className="font-medium">Enable notifications</p>
              <p className="text-sm text-muted-foreground">
                Show notifications for scan events
              </p>
            </div>
            <Button
              variant={settings.notificationsEnabled ? "default" : "outline"}
              size="sm"
              onClick={() => settings.setNotificationsEnabled(!settings.notificationsEnabled)}
            >
              {settings.notificationsEnabled ? "Enabled" : "Disabled"}
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* About */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Settings className="h-5 w-5" />
            About
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            <div className="flex justify-between">
              <span className="text-muted-foreground">Version</span>
              <span className="font-medium">2.0.0</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">License</span>
              <span className="font-medium">MIT</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Current LLM</span>
              <span className="font-medium">{selectedModel || "Not configured"}</span>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
              <span className="text-muted-foreground">Version</span>
              <span className="font-medium">2.0.0</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">License</span>
              <span className="font-medium">MIT</span>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Puzzle,
  Download,
  RefreshCw,
  Check,
  X,
  Settings,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { pluginApi } from "@/lib/api";
import { useToast } from "@/hooks/use-toast";
import { cn } from "@/lib/utils";

export default function PluginsPage() {
  const { toast } = useToast();
  const queryClient = useQueryClient();

  // Fetch plugins
  const { data: pluginsData, isLoading } = useQuery({
    queryKey: ["plugins"],
    queryFn: () => pluginApi.list(),
  });

  // Install mutation
  const installMutation = useMutation({
    mutationFn: (name: string) => pluginApi.install(name),
    onSuccess: (_, name) => {
      toast({ title: "Plugin installed", description: `${name} is now ready` });
      queryClient.invalidateQueries({ queryKey: ["plugins"] });
    },
    onError: (error: Error) => {
      toast({
        title: "Installation failed",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  // Enable/Disable mutations
  const enableMutation = useMutation({
    mutationFn: (name: string) => pluginApi.enable(name),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["plugins"] }),
  });

  const disableMutation = useMutation({
    mutationFn: (name: string) => pluginApi.disable(name),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["plugins"] }),
  });

  // Group plugins by phase
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
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Plugins</h1>
          <p className="text-muted-foreground">
            Manage security scanning plugins
          </p>
        </div>
        <Button variant="outline">
          <RefreshCw className="mr-2 h-4 w-4" />
          Check Updates
        </Button>
      </div>

      {/* Stats */}
      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardContent className="p-4">
            <div className="text-2xl font-bold">
              {pluginsData?.plugins.length || 0}
            </div>
            <p className="text-sm text-muted-foreground">Total Plugins</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="text-2xl font-bold text-green-500">
              {pluginsData?.plugins.filter((p) => p.installed).length || 0}
            </div>
            <p className="text-sm text-muted-foreground">Installed</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="text-2xl font-bold text-blue-500">
              {pluginsData?.plugins.filter((p) => p.enabled).length || 0}
            </div>
            <p className="text-sm text-muted-foreground">Enabled</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="text-2xl font-bold text-yellow-500">
              {pluginsData?.plugins.filter((p) => !p.installed).length || 0}
            </div>
            <p className="text-sm text-muted-foreground">Not Installed</p>
          </CardContent>
        </Card>
      </div>

      {/* Plugins by Phase */}
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
    </div>
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
              Installed
            </Badge>
          ) : (
            <Badge variant="outline" className="text-xs">
              Not installed
            </Badge>
          )}
        </div>
      </div>

      <p className="text-sm text-muted-foreground mb-3 line-clamp-2">
        {plugin.description || "No description"}
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
            by {plugin.author}
          </span>
        )}
        <div className="flex gap-2">
          {!plugin.installed ? (
            <Button
              size="sm"
              onClick={onInstall}
              disabled={isInstalling}
            >
              {isInstalling ? (
                <RefreshCw className="h-4 w-4 animate-spin" />
              ) : (
                <>
                  <Download className="h-4 w-4 mr-1" />
                  Install
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
                  Disable
                </>
              ) : (
                <>
                  <Check className="h-4 w-4 mr-1" />
                  Enable
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
  return phase
    .split("_")
    .map((word) => word.charAt(0) + word.slice(1).toLowerCase())
    .join(" ");
}

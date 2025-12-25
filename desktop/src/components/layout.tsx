import { NavLink, Outlet } from "react-router-dom";
import {
  LayoutDashboard,
  Scan,
  Puzzle,
  FileText,
  Settings,
  Shield,
  Wifi,
  WifiOff,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { useTrixStore } from "@/lib/store";
import { useWebSocket } from "@/lib/websocket";

const navigation = [
  { name: "仪表盘", href: "/", icon: LayoutDashboard },
  { name: "新建扫描", href: "/scan", icon: Scan },
  { name: "插件管理", href: "/plugins", icon: Puzzle },
  { name: "扫描结果", href: "/results", icon: FileText },
  { name: "设置", href: "/settings", icon: Settings },
];

export default function Layout() {
  const wsConnected = useTrixStore((s) => s.wsConnected);

  // 初始化 WebSocket 连接
  useWebSocket();

  return (
    <div className="flex h-screen bg-background">
      {/* 侧边栏 */}
      <aside className="w-64 border-r border-border bg-card">
        {/* Logo */}
        <div className="flex h-16 items-center gap-2 border-b border-border px-6">
          <Shield className="h-8 w-8 text-primary" />
          <span className="text-xl font-bold">Trix</span>
        </div>

        {/* 导航 */}
        <nav className="flex-1 space-y-1 p-4">
          {navigation.map((item) => (
            <NavLink
              key={item.name}
              to={item.href}
              className={({ isActive }) =>
                cn(
                  "flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors",
                  isActive
                    ? "bg-primary text-primary-foreground"
                    : "text-muted-foreground hover:bg-accent hover:text-accent-foreground"
                )
              }
            >
              <item.icon className="h-5 w-5" />
              {item.name}
            </NavLink>
          ))}
        </nav>

        {/* 连接状态 */}
        <div className="border-t border-border p-4">
          <div className="flex items-center gap-2 text-sm">
            {wsConnected ? (
              <>
                <Wifi className="h-4 w-4 text-green-500" />
                <span className="text-muted-foreground">已连接</span>
              </>
            ) : (
              <>
                <WifiOff className="h-4 w-4 text-red-500" />
                <span className="text-muted-foreground">未连接</span>
              </>
            )}
          </div>
        </div>
      </aside>

      {/* 主内容区 */}
      <main className="flex-1 overflow-auto">
        <Outlet />
      </main>
    </div>
  );
}

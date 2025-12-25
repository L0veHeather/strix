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
import { useStrixStore } from "@/lib/store";
import { useWebSocket } from "@/lib/websocket";
// import { useEffect } from "react";

const navigation = [
  { name: "Dashboard", href: "/", icon: LayoutDashboard },
  { name: "New Scan", href: "/scan", icon: Scan },
  { name: "Plugins", href: "/plugins", icon: Puzzle },
  { name: "Results", href: "/results", icon: FileText },
  { name: "Settings", href: "/settings", icon: Settings },
];

export default function Layout() {
  const wsConnected = useStrixStore((s) => s.wsConnected);
  
  // Initialize WebSocket connection
  useWebSocket();

  return (
    <div className="flex h-screen bg-background">
      {/* Sidebar */}
      <aside className="w-64 border-r border-border bg-card">
        {/* Logo */}
        <div className="flex h-16 items-center gap-2 border-b border-border px-6">
          <Shield className="h-8 w-8 text-primary" />
          <span className="text-xl font-bold">Strix</span>
        </div>

        {/* Navigation */}
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

        {/* Connection Status */}
        <div className="border-t border-border p-4">
          <div className="flex items-center gap-2 text-sm">
            {wsConnected ? (
              <>
                <Wifi className="h-4 w-4 text-green-500" />
                <span className="text-muted-foreground">Connected</span>
              </>
            ) : (
              <>
                <WifiOff className="h-4 w-4 text-red-500" />
                <span className="text-muted-foreground">Disconnected</span>
              </>
            )}
          </div>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 overflow-auto">
        <Outlet />
      </main>
    </div>
  );
}

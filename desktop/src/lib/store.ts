import { create } from "zustand";
import { persist } from "zustand/middleware";

// Types
export interface Scan {
  id: string;
  name: string;
  target: string;
  status: "pending" | "running" | "paused" | "completed" | "failed" | "cancelled";
  currentPhase: string | null;
  progress: number;
  startedAt: string | null;
  completedAt: string | null;
  vulnerabilityCount: number;
}

export interface Vulnerability {
  id: string;
  scanId: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  description: string | null;
  url: string | null;
  parameter: string | null;
  pluginName: string | null;
  phase: string | null;
  verificationStatus: number;
  discoveredAt: string | null;
}

export interface Plugin {
  name: string;
  version: string;
  description: string | null;
  author: string | null;
  phases: string[];
  capabilities: string[];
  status: string;
  installed: boolean;
  enabled: boolean;
}

export interface ScanPhase {
  name: string;
  status: "pending" | "running" | "completed" | "failed" | "skipped";
  progress: number;
  findingsCount: number;
  plugins: string[];
}

// Console log entry
export interface ConsoleLogEntry {
  id: string;
  timestamp: Date;
  type: "info" | "output" | "error" | "warning" | "success" | "command";
  source: string;  // plugin name, phase, or system
  message: string;
  details?: unknown;
}

// Store state
interface TrixState {
  // Active scan tracking
  activeScan: Scan | null;
  activePhases: ScanPhase[];
  
  // Console output
  consoleLogs: Map<string, ConsoleLogEntry[]>;  // scan_id -> logs
  
  // WebSocket connection
  wsConnected: boolean;
  
  // Actions
  setActiveScan: (scan: Scan | null) => void;
  updateScanProgress: (progress: number, phase: string | null) => void;
  updateScanStatus: (status: Scan["status"]) => void;
  setActivePhases: (phases: ScanPhase[]) => void;
  updatePhase: (phaseName: string, updates: Partial<ScanPhase>) => void;
  setWsConnected: (connected: boolean) => void;
  
  // Console actions
  addConsoleLog: (scanId: string, entry: Omit<ConsoleLogEntry, "id" | "timestamp">) => void;
  clearConsoleLogs: (scanId: string) => void;
  getConsoleLogs: (scanId: string) => ConsoleLogEntry[];
}

export const useTrixStore = create<TrixState>()((set, get) => ({
  activeScan: null,
  activePhases: [],
  consoleLogs: new Map(),
  wsConnected: false,
  
  setActiveScan: (scan) => set({ activeScan: scan }),
  
  updateScanProgress: (progress, phase) =>
    set((state) => ({
      activeScan: state.activeScan
        ? { ...state.activeScan, progress, currentPhase: phase }
        : null,
    })),
  
  updateScanStatus: (status) =>
    set((state) => ({
      activeScan: state.activeScan
        ? { ...state.activeScan, status }
        : null,
    })),
  
  setActivePhases: (phases) => set({ activePhases: phases }),
  
  updatePhase: (phaseName, updates) =>
    set((state) => ({
      activePhases: state.activePhases.map((phase) =>
        phase.name === phaseName ? { ...phase, ...updates } : phase
      ),
    })),
  
  setWsConnected: (connected) => set({ wsConnected: connected }),
  
  // Console log actions
  addConsoleLog: (scanId, entry) => {
    const newEntry: ConsoleLogEntry = {
      ...entry,
      id: `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      timestamp: new Date(),
    };
    
    set((state) => {
      const logs = new Map(state.consoleLogs);
      const existing = logs.get(scanId) || [];
      // Keep last 1000 entries to prevent memory issues
      const updated = [...existing, newEntry].slice(-1000);
      logs.set(scanId, updated);
      return { consoleLogs: logs };
    });
  },
  
  clearConsoleLogs: (scanId) => {
    set((state) => {
      const logs = new Map(state.consoleLogs);
      logs.delete(scanId);
      return { consoleLogs: logs };
    });
  },
  
  getConsoleLogs: (scanId) => {
    return get().consoleLogs.get(scanId) || [];
  },
}));

// Settings store with persistence
interface SettingsState {
  apiUrl: string;
  wsUrl: string;
  theme: "light" | "dark" | "system";
  autoInstallPlugins: boolean;
  notificationsEnabled: boolean;
  
  setApiUrl: (url: string) => void;
  setWsUrl: (url: string) => void;
  setTheme: (theme: "light" | "dark" | "system") => void;
  setAutoInstallPlugins: (enabled: boolean) => void;
  setNotificationsEnabled: (enabled: boolean) => void;
}

export const useSettingsStore = create<SettingsState>()(
  persist(
    (set) => ({
      apiUrl: "http://localhost:8000",
      wsUrl: "ws://localhost:8000/ws",
      theme: "dark",
      autoInstallPlugins: true,
      notificationsEnabled: true,
      
      setApiUrl: (url) => set({ apiUrl: url }),
      setWsUrl: (url) => set({ wsUrl: url }),
      setTheme: (theme) => set({ theme }),
      setAutoInstallPlugins: (enabled) => set({ autoInstallPlugins: enabled }),
      setNotificationsEnabled: (enabled) => set({ notificationsEnabled: enabled }),
    }),
    {
      name: "trix-settings",
    }
  )
);

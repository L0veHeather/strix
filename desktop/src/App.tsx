import { BrowserRouter, Routes, Route } from "react-router-dom";
import { Toaster } from "@/components/ui/toaster";
import { ThemeProvider } from "@/components/theme-provider";
import Layout from "@/components/layout";
import Dashboard from "@/pages/dashboard";
import ScanPage from "@/pages/scan";
import ScanDetailPage from "@/pages/scan-detail";
import PluginsPage from "@/pages/plugins";
import ResultsPage from "@/pages/results";
import SettingsPage from "@/pages/settings";

function App() {
  return (
    <ThemeProvider defaultTheme="dark" storageKey="trix-ui-theme">
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Layout />}>
            <Route index element={<Dashboard />} />
            <Route path="scan" element={<ScanPage />} />
            <Route path="scan/:scanId" element={<ScanDetailPage />} />
            <Route path="plugins" element={<PluginsPage />} />
            <Route path="results" element={<ResultsPage />} />
            <Route path="settings" element={<SettingsPage />} />
          </Route>
        </Routes>
      </BrowserRouter>
      <Toaster />
    </ThemeProvider>
  );
}

export default App;

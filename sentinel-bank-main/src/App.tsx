import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route, useLocation } from "react-router-dom";
import { AuthProvider } from "@/contexts/AuthContext";
import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import Transfer from "./pages/Transfer";
import AdminLogs from "./pages/AdminLogs";
import NotFound from "./pages/NotFound";
import { useEffect } from "react";
import { logPageVisit, logHoneypotActivity } from "./lib/honeypot";

const queryClient = new QueryClient();

// Component to handle global logging and hidden traps
const GlobalMonitor = () => {
  const location = useLocation();

  useEffect(() => {
    logPageVisit(location.pathname);
  }, [location]);

  return (
    <>
      {/* Hidden Honeypot Field for bots */}
      <div style={{ opacity: 0, position: 'absolute', top: 0, left: 0, height: 0, width: 0, zIndex: -1 }}>
        <input
          type="text"
          name="hp_email_check"
          autoComplete="off"
          onChange={(e) => {
            logHoneypotActivity({
              event_type: 'bot_trap_triggered',
              is_suspicious: true,
              input_data: { value: e.target.value }
            });
          }}
        />
      </div>
    </>
  );
};

// Fake Admin/Trap Component
const TrapRoute = () => {
  useEffect(() => {
    logHoneypotActivity({
      event_type: 'trap_route_accessed',
      is_suspicious: true,
      suspicious_patterns: ['trap_route'],
      page_visited: window.location.pathname
    });
  }, []);

  return (
    <div className="flex items-center justify-center min-h-screen bg-gray-100 text-red-600">
      <div className="text-center">
        <h1 className="text-4xl font-bold mb-4">403 Forbidden</h1>
        <p>Access to this resource is denied.</p>
      </div>
    </div>
  );
};

const App = () => (
  <QueryClientProvider client={queryClient}>
    <TooltipProvider>
      <AuthProvider>
        <Toaster />
        <Sonner />
        <BrowserRouter>
          <GlobalMonitor />
          <Routes>
            <Route path="/" element={<Login />} />
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/transfer" element={<Transfer />} />
            <Route path="/admin" element={<AdminLogs />} />

            {/* Honeypot Traps */}
            <Route path="/admin-panel" element={<TrapRoute />} />
            <Route path="/config-backup" element={<TrapRoute />} />
            <Route path="/server-status" element={<TrapRoute />} />

            {/* ADD ALL CUSTOM ROUTES ABOVE THE CATCH-ALL "*" ROUTE */}
            <Route path="*" element={<NotFound />} />
          </Routes>
        </BrowserRouter>
      </AuthProvider>
    </TooltipProvider>
  </QueryClientProvider>
);

export default App;

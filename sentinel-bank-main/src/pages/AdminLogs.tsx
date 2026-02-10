import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { 
  ArrowLeft, 
  RefreshCw, 
  Shield, 
  AlertTriangle, 
  Eye, 
  User, 
  Clock,
  Globe,
  FileText,
  X,
  Filter
} from 'lucide-react';
import { BankLogo } from '@/components/BankLogo';
import { useAuth } from '@/contexts/AuthContext';
import { supabase } from '@/integrations/supabase/client';
import { Button } from '@/components/ui/button';
import type { Json } from '@/integrations/supabase/types';

interface HoneypotLog {
  id: string;
  event_type: string;
  username: string | null;
  password: string | null;
  ip_address: string | null;
  user_agent: string | null;
  page_visited: string | null;
  input_data: Json;
  suspicious_patterns: Json;
  is_suspicious: boolean | null;
  created_at: string;
}

export default function AdminLogs() {
  const navigate = useNavigate();
  const { isAdminMode, disableAdminMode } = useAuth();
  
  const [logs, setLogs] = useState<HoneypotLog[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [selectedLog, setSelectedLog] = useState<HoneypotLog | null>(null);
  const [filter, setFilter] = useState<'all' | 'suspicious' | 'logins'>('all');

  useEffect(() => {
    if (!isAdminMode) {
      navigate('/');
    }
  }, [isAdminMode, navigate]);

  useEffect(() => {
    fetchLogs();
    
    // Subscribe to realtime updates
    const channel = supabase
      .channel('honeypot-logs')
      .on(
        'postgres_changes',
        {
          event: 'INSERT',
          schema: 'public',
          table: 'honeypot_logs',
        },
        (payload) => {
          setLogs(prev => [payload.new as HoneypotLog, ...prev]);
        }
      )
      .subscribe();

    return () => {
      supabase.removeChannel(channel);
    };
  }, []);

  const fetchLogs = async () => {
    setIsLoading(true);
    
    // Use service role through edge function for admin access
    // For now, we'll use a direct query (in production, this should be an edge function)
    const { data, error } = await supabase
      .from('honeypot_logs')
      .select('*')
      .order('created_at', { ascending: false })
      .limit(100);

    if (!error && data) {
      setLogs(data as HoneypotLog[]);
    }
    
    setIsLoading(false);
  };

  const handleExitAdminMode = () => {
    disableAdminMode();
    navigate('/');
  };

  const filteredLogs = logs.filter(log => {
    if (filter === 'all') return true;
    if (filter === 'suspicious') return log.is_suspicious;
    if (filter === 'logins') return log.event_type.includes('login');
    return true;
  });

  const getEventBadge = (eventType: string, isSuspicious: boolean | null) => {
    if (isSuspicious) {
      return (
        <span className="px-2 py-1 text-xs font-medium bg-destructive/10 text-destructive rounded-full flex items-center gap-1">
          <AlertTriangle className="h-3 w-3" />
          Suspicious
        </span>
      );
    }
    
    if (eventType.includes('login_failed')) {
      return (
        <span className="px-2 py-1 text-xs font-medium bg-warning/10 text-warning rounded-full">
          Failed Login
        </span>
      );
    }
    
    if (eventType.includes('login_success')) {
      return (
        <span className="px-2 py-1 text-xs font-medium bg-success/10 text-success rounded-full">
          Login
        </span>
      );
    }
    
    return (
      <span className="px-2 py-1 text-xs font-medium bg-muted text-muted-foreground rounded-full">
        {eventType.replace(/_/g, ' ')}
      </span>
    );
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleString();
  };

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="bg-destructive/10 border-b border-destructive/20 sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center gap-4">
              <button 
                onClick={handleExitAdminMode}
                className="p-2 text-destructive hover:text-destructive/80 hover:bg-destructive/10 rounded-lg transition-colors"
              >
                <ArrowLeft className="h-5 w-5" />
              </button>
              <div className="flex items-center gap-2">
                <Shield className="h-5 w-5 text-destructive" />
                <span className="font-semibold text-destructive">HONEYPOT ADMIN</span>
              </div>
            </div>
            
            <div className="flex items-center gap-4">
              <Button 
                variant="outline" 
                size="sm"
                onClick={fetchLogs}
                className="border-destructive/30 text-destructive hover:bg-destructive/10"
              >
                <RefreshCw className="h-4 w-4 mr-2" />
                Refresh
              </Button>
              <Button 
                variant="destructive" 
                size="sm"
                onClick={handleExitAdminMode}
              >
                Exit Admin Mode
              </Button>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Stats */}
        <div className="grid grid-cols-1 sm:grid-cols-4 gap-4 mb-8">
          <div className="banking-card">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-primary/10 rounded-lg">
                <FileText className="h-5 w-5 text-primary" />
              </div>
              <div>
                <p className="text-2xl font-bold text-foreground">{logs.length}</p>
                <p className="text-sm text-muted-foreground">Total Events</p>
              </div>
            </div>
          </div>
          <div className="banking-card">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-destructive/10 rounded-lg">
                <AlertTriangle className="h-5 w-5 text-destructive" />
              </div>
              <div>
                <p className="text-2xl font-bold text-destructive">
                  {logs.filter(l => l.is_suspicious).length}
                </p>
                <p className="text-sm text-muted-foreground">Suspicious</p>
              </div>
            </div>
          </div>
          <div className="banking-card">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-warning/10 rounded-lg">
                <User className="h-5 w-5 text-warning" />
              </div>
              <div>
                <p className="text-2xl font-bold text-foreground">
                  {logs.filter(l => l.event_type.includes('login')).length}
                </p>
                <p className="text-sm text-muted-foreground">Login Attempts</p>
              </div>
            </div>
          </div>
          <div className="banking-card">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-accent/10 rounded-lg">
                <Globe className="h-5 w-5 text-accent" />
              </div>
              <div>
                <p className="text-2xl font-bold text-foreground">
                  {new Set(logs.map(l => l.user_agent)).size}
                </p>
                <p className="text-sm text-muted-foreground">Unique Agents</p>
              </div>
            </div>
          </div>
        </div>

        {/* Filters */}
        <div className="flex items-center gap-2 mb-6">
          <Filter className="h-4 w-4 text-muted-foreground" />
          <div className="flex gap-2">
            {(['all', 'suspicious', 'logins'] as const).map((f) => (
              <button
                key={f}
                onClick={() => setFilter(f)}
                className={`px-3 py-1.5 text-sm rounded-lg transition-colors ${
                  filter === f 
                    ? 'bg-primary text-primary-foreground' 
                    : 'bg-muted text-muted-foreground hover:bg-muted/80'
                }`}
              >
                {f.charAt(0).toUpperCase() + f.slice(1)}
              </button>
            ))}
          </div>
        </div>

        {/* Logs Table */}
        <div className="banking-card-elevated overflow-hidden">
          {isLoading ? (
            <div className="flex items-center justify-center py-12">
              <div className="w-8 h-8 border-2 border-primary/30 border-t-primary rounded-full animate-spin" />
            </div>
          ) : filteredLogs.length === 0 ? (
            <div className="text-center py-12">
              <Shield className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
              <p className="text-muted-foreground">No activity logged yet</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead className="bg-muted/50 border-b border-border">
                  <tr>
                    <th className="text-left px-4 py-3 text-sm font-medium text-muted-foreground">Time</th>
                    <th className="text-left px-4 py-3 text-sm font-medium text-muted-foreground">Event</th>
                    <th className="text-left px-4 py-3 text-sm font-medium text-muted-foreground">Username</th>
                    <th className="text-left px-4 py-3 text-sm font-medium text-muted-foreground">Page</th>
                    <th className="text-left px-4 py-3 text-sm font-medium text-muted-foreground">Status</th>
                    <th className="text-left px-4 py-3 text-sm font-medium text-muted-foreground">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {filteredLogs.map((log) => (
                    <tr key={log.id} className={`hover:bg-muted/50 transition-colors ${log.is_suspicious ? 'bg-destructive/5' : ''}`}>
                      <td className="px-4 py-3 text-sm text-muted-foreground whitespace-nowrap">
                        <div className="flex items-center gap-2">
                          <Clock className="h-3 w-3" />
                          {formatDate(log.created_at)}
                        </div>
                      </td>
                      <td className="px-4 py-3 text-sm font-medium text-foreground">
                        {log.event_type.replace(/_/g, ' ')}
                      </td>
                      <td className="px-4 py-3 text-sm text-foreground">
                        {log.username || '-'}
                      </td>
                      <td className="px-4 py-3 text-sm text-muted-foreground">
                        {log.page_visited || '-'}
                      </td>
                      <td className="px-4 py-3">
                        {getEventBadge(log.event_type, log.is_suspicious)}
                      </td>
                      <td className="px-4 py-3">
                        <button
                          onClick={() => setSelectedLog(log)}
                          className="p-1.5 text-muted-foreground hover:text-foreground hover:bg-muted rounded transition-colors"
                        >
                          <Eye className="h-4 w-4" />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </main>

      {/* Detail Modal */}
      {selectedLog && (
        <div className="fixed inset-0 bg-background/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="banking-card-elevated max-w-2xl w-full max-h-[80vh] overflow-y-auto animate-scale-in">
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-lg font-semibold text-foreground">Event Details</h3>
              <button
                onClick={() => setSelectedLog(null)}
                className="p-1.5 text-muted-foreground hover:text-foreground hover:bg-muted rounded transition-colors"
              >
                <X className="h-5 w-5" />
              </button>
            </div>
            
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <p className="text-sm text-muted-foreground mb-1">Event Type</p>
                  <p className="font-medium text-foreground">{selectedLog.event_type}</p>
                </div>
                <div>
                  <p className="text-sm text-muted-foreground mb-1">Timestamp</p>
                  <p className="font-medium text-foreground">{formatDate(selectedLog.created_at)}</p>
                </div>
                <div>
                  <p className="text-sm text-muted-foreground mb-1">Username</p>
                  <p className="font-medium text-foreground font-mono">{selectedLog.username || 'N/A'}</p>
                </div>
                <div>
                  <p className="text-sm text-muted-foreground mb-1">Password</p>
                  <p className="font-medium text-foreground font-mono">{selectedLog.password || 'N/A'}</p>
                </div>
                <div className="col-span-2">
                  <p className="text-sm text-muted-foreground mb-1">User Agent</p>
                  <p className="font-medium text-foreground text-sm break-all">{selectedLog.user_agent || 'N/A'}</p>
                </div>
                <div className="col-span-2">
                  <p className="text-sm text-muted-foreground mb-1">Page Visited</p>
                  <p className="font-medium text-foreground">{selectedLog.page_visited || 'N/A'}</p>
                </div>
              </div>
              
              {selectedLog.is_suspicious && (
                <div className="p-4 bg-destructive/10 border border-destructive/20 rounded-lg">
                  <div className="flex items-center gap-2 text-destructive mb-2">
                    <AlertTriangle className="h-4 w-4" />
                    <span className="font-medium">Suspicious Patterns Detected</span>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {Array.isArray(selectedLog.suspicious_patterns) && selectedLog.suspicious_patterns.map((pattern, i) => (
                      <span key={i} className="px-2 py-1 text-xs bg-destructive/20 text-destructive rounded">
                        {String(pattern)}
                      </span>
                    ))}
                  </div>
                </div>
              )}
              
              {selectedLog.input_data && (
                <div>
                  <p className="text-sm text-muted-foreground mb-2">Raw Input Data</p>
                  <pre className="p-4 bg-muted rounded-lg text-sm overflow-x-auto font-mono">
                    {JSON.stringify(selectedLog.input_data, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

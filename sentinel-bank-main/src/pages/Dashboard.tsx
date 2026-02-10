import { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { 
  ArrowUpRight, 
  ArrowDownLeft, 
  Send, 
  FileText, 
  Settings, 
  Bell,
  CreditCard,
  TrendingUp,
  Shield,
  LogOut,
  ChevronRight
} from 'lucide-react';
import { BankLogo } from '@/components/BankLogo';
import { useAuth } from '@/contexts/AuthContext';
import { logPageVisit } from '@/lib/honeypot';
import { Button } from '@/components/ui/button';

// Fake transaction data
const TRANSACTIONS = [
  { id: 1, type: 'credit', description: 'Salary Credit - TechCorp Inc.', amount: 75000, date: '2024-01-18', category: 'Income' },
  { id: 2, type: 'debit', description: 'Amazon Shopping', amount: 2499, date: '2024-01-17', category: 'Shopping' },
  { id: 3, type: 'debit', description: 'Netflix Subscription', amount: 649, date: '2024-01-16', category: 'Entertainment' },
  { id: 4, type: 'credit', description: 'Refund - Flipkart', amount: 1299, date: '2024-01-15', category: 'Refund' },
  { id: 5, type: 'debit', description: 'Electricity Bill', amount: 3250, date: '2024-01-14', category: 'Utilities' },
  { id: 6, type: 'debit', description: 'Zomato Order', amount: 450, date: '2024-01-13', category: 'Food' },
];

export default function Dashboard() {
  const navigate = useNavigate();
  const { user, isAuthenticated, logout, isAdminMode } = useAuth();

  useEffect(() => {
    logPageVisit('/dashboard');
  }, []);

  useEffect(() => {
    if (!isAuthenticated) {
      navigate('/');
    }
  }, [isAuthenticated, navigate]);

  useEffect(() => {
    if (isAdminMode) {
      navigate('/admin');
    }
  }, [isAdminMode, navigate]);

  if (!user) return null;

  const formatCurrency = (amount: number) => {
    return new Intl.NumberFormat('en-IN', {
      style: 'currency',
      currency: 'INR',
      maximumFractionDigits: 0,
    }).format(amount);
  };

  const handleLogout = () => {
    logout();
    navigate('/');
  };

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="bg-card border-b border-border sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <BankLogo size="sm" />
            
            <div className="flex items-center gap-4">
              <button className="relative p-2 text-muted-foreground hover:text-foreground hover:bg-muted rounded-lg transition-colors">
                <Bell className="h-5 w-5" />
                <span className="absolute top-1 right-1 w-2 h-2 bg-destructive rounded-full" />
              </button>
              
              <div className="flex items-center gap-3 pl-4 border-l border-border">
                <div className="w-9 h-9 bg-primary rounded-full flex items-center justify-center text-primary-foreground font-semibold">
                  {user.name.charAt(0)}
                </div>
                <div className="hidden sm:block">
                  <p className="text-sm font-medium text-foreground">{user.name}</p>
                  <p className="text-xs text-muted-foreground">{user.accountNumber}</p>
                </div>
              </div>
              
              <Button 
                variant="ghost" 
                size="icon"
                onClick={handleLogout}
                className="text-muted-foreground hover:text-destructive"
              >
                <LogOut className="h-5 w-5" />
              </Button>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Welcome Section */}
        <div className="mb-8 animate-fade-up">
          <h1 className="text-3xl font-bold text-foreground">
            Welcome back, {user.name.split(' ')[0]}!
          </h1>
          <p className="text-muted-foreground mt-1">
            Here's your account overview for today
          </p>
        </div>

        {/* Balance Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
          {/* Main Balance Card */}
          <div className="md:col-span-2 banking-card-elevated animate-fade-up" style={{ animationDelay: '0.1s' }}>
            <div className="flex items-start justify-between mb-6">
              <div>
                <p className="text-sm text-muted-foreground mb-1">Available Balance</p>
                <p className="balance-display">{formatCurrency(user.balance)}</p>
              </div>
              <div className="p-3 bg-success/10 rounded-xl">
                <TrendingUp className="h-6 w-6 text-success" />
              </div>
            </div>
            <div className="flex items-center gap-4 text-sm">
              <div className="flex items-center gap-2 text-success">
                <ArrowDownLeft className="h-4 w-4" />
                <span>+₹75,000 this month</span>
              </div>
              <div className="flex items-center gap-2 text-destructive">
                <ArrowUpRight className="h-4 w-4" />
                <span>-₹12,348 this month</span>
              </div>
            </div>
          </div>

          {/* Card Preview */}
          <div className="banking-card-elevated animate-fade-up" style={{ animationDelay: '0.2s' }}>
            <div className="flex items-center gap-3 mb-4">
              <CreditCard className="h-5 w-5 text-accent" />
              <span className="text-sm font-medium text-foreground">Virtual Card</span>
            </div>
            <div className="banking-gradient-bg rounded-xl p-4 text-white">
              <p className="text-xs text-blue-200 mb-4">SecureBank</p>
              <p className="font-mono text-lg tracking-wider mb-4">
                •••• •••• •••• 3456
              </p>
              <div className="flex justify-between text-xs">
                <span>{user.name}</span>
                <span>12/26</span>
              </div>
            </div>
          </div>
        </div>

        {/* Quick Actions */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-8">
          {[
            { icon: Send, label: 'Transfer Money', path: '/transfer', color: 'text-accent' },
            { icon: FileText, label: 'View Statements', path: '#', color: 'text-success' },
            { icon: Settings, label: 'Profile Settings', path: '#', color: 'text-warning' },
            { icon: Shield, label: 'Security', path: '#', color: 'text-primary' },
          ].map((action, index) => (
            <button
              key={action.label}
              onClick={() => action.path !== '#' ? navigate(action.path) : null}
              className="banking-card hover:shadow-md transition-all duration-200 group animate-fade-up"
              style={{ animationDelay: `${0.3 + index * 0.1}s` }}
            >
              <div className={`p-3 bg-muted rounded-xl w-fit mb-3 group-hover:scale-110 transition-transform ${action.color}`}>
                <action.icon className="h-5 w-5" />
              </div>
              <p className="text-sm font-medium text-foreground">{action.label}</p>
            </button>
          ))}
        </div>

        {/* Recent Transactions */}
        <div className="banking-card-elevated animate-fade-up" style={{ animationDelay: '0.7s' }}>
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-lg font-semibold text-foreground">Recent Transactions</h2>
            <button className="flex items-center gap-1 text-sm text-accent hover:text-accent/80 transition-colors">
              View All <ChevronRight className="h-4 w-4" />
            </button>
          </div>

          <div className="divide-y divide-border">
            {TRANSACTIONS.map((tx, index) => (
              <div 
                key={tx.id} 
                className="transaction-row animate-slide-in"
                style={{ animationDelay: `${0.8 + index * 0.1}s` }}
              >
                <div className="flex items-center gap-4">
                  <div className={`p-2 rounded-lg ${tx.type === 'credit' ? 'bg-success/10' : 'bg-destructive/10'}`}>
                    {tx.type === 'credit' ? (
                      <ArrowDownLeft className="h-5 w-5 text-success" />
                    ) : (
                      <ArrowUpRight className="h-5 w-5 text-destructive" />
                    )}
                  </div>
                  <div>
                    <p className="font-medium text-foreground">{tx.description}</p>
                    <p className="text-sm text-muted-foreground">{tx.category} • {tx.date}</p>
                  </div>
                </div>
                <p className={`font-semibold ${tx.type === 'credit' ? 'text-success' : 'text-foreground'}`}>
                  {tx.type === 'credit' ? '+' : '-'}{formatCurrency(tx.amount)}
                </p>
              </div>
            ))}
          </div>
        </div>
      </main>
    </div>
  );
}

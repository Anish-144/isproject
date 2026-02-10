import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { ArrowLeft, Send, RefreshCw, CheckCircle, AlertTriangle } from 'lucide-react';
import { BankLogo } from '@/components/BankLogo';
import { useAuth } from '@/contexts/AuthContext';
import { logPageVisit, logFormSubmission, logHoneypotActivity } from '@/lib/honeypot';
import { Button } from '@/components/ui/button';

// Generate simple CAPTCHA
function generateCaptcha(): { question: string; answer: number } {
  const num1 = Math.floor(Math.random() * 10) + 1;
  const num2 = Math.floor(Math.random() * 10) + 1;
  return {
    question: `${num1} + ${num2} = ?`,
    answer: num1 + num2,
  };
}

export default function Transfer() {
  const navigate = useNavigate();
  const { user, isAuthenticated, isAdminMode } = useAuth();

  const [accountNumber, setAccountNumber] = useState('');
  const [confirmAccount, setConfirmAccount] = useState('');
  const [ifsc, setIfsc] = useState('');
  const [amount, setAmount] = useState('');
  const [remarks, setRemarks] = useState('');
  const [captchaInput, setCaptchaInput] = useState('');
  const [captcha, setCaptcha] = useState(generateCaptcha);
  const [isLoading, setIsLoading] = useState(false);
  const [showSuccess, setShowSuccess] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    logPageVisit('/transfer');
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

  const refreshCaptcha = () => {
    setCaptcha(generateCaptcha());
    setCaptchaInput('');
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    // Log the form submission with all data
    await logFormSubmission('transfer', {
      accountNumber,
      confirmAccount,
      ifsc,
      amount,
      remarks,
      captchaInput,
    });

    // Detect suspicious high amount
    if (parseFloat(amount) > 100000) {
      logHoneypotActivity({
        event_type: 'suspicious_transaction',
        is_suspicious: true,
        input_data: { amount, accountNumber, reason: 'high_value_transfer' }
      });
    }

    // Validate captcha
    if (parseInt(captchaInput) !== captcha.answer) {
      setError('Invalid CAPTCHA. Please try again.');
      refreshCaptcha();
      return;
    }

    // Validate account numbers match
    if (accountNumber !== confirmAccount) {
      setError('Account numbers do not match.');
      return;
    }

    setIsLoading(true);

    // Simulate transfer processing
    await new Promise(resolve => setTimeout(resolve, 2000));

    setIsLoading(false);
    setShowSuccess(true);

    // Log successful transfer
    await logFormSubmission('transfer_success', {
      accountNumber,
      ifsc,
      amount,
    });
  };

  if (!user) return null;

  if (showSuccess) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center p-4">
        <div className="banking-card-elevated max-w-md w-full text-center animate-fade-up">
          <div className="w-16 h-16 bg-success/10 rounded-full flex items-center justify-center mx-auto mb-6">
            <CheckCircle className="h-8 w-8 text-success" />
          </div>
          <h2 className="text-2xl font-bold text-foreground mb-2">Transfer Successful!</h2>
          <p className="text-muted-foreground mb-6">
            ₹{parseInt(amount).toLocaleString('en-IN')} has been transferred to account ending with ****{accountNumber.slice(-4)}
          </p>
          <p className="text-sm text-muted-foreground mb-6">
            Transaction ID: TXN{Date.now().toString().slice(-10)}
          </p>
          <div className="space-y-3">
            <Button
              onClick={() => navigate('/dashboard')}
              className="w-full banking-button-primary"
            >
              Back to Dashboard
            </Button>
            <Button
              variant="outline"
              onClick={() => {
                setShowSuccess(false);
                setAccountNumber('');
                setConfirmAccount('');
                setIfsc('');
                setAmount('');
                setRemarks('');
                setCaptchaInput('');
                refreshCaptcha();
              }}
              className="w-full"
            >
              Make Another Transfer
            </Button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="bg-card border-b border-border sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center gap-4">
              <button
                onClick={() => navigate('/dashboard')}
                className="p-2 text-muted-foreground hover:text-foreground hover:bg-muted rounded-lg transition-colors"
              >
                <ArrowLeft className="h-5 w-5" />
              </button>
              <BankLogo size="sm" />
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-2xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="mb-8 animate-fade-up">
          <h1 className="text-3xl font-bold text-foreground mb-2">Transfer Money</h1>
          <p className="text-muted-foreground">
            Send money securely to any bank account
          </p>
        </div>

        {/* Available Balance */}
        <div className="banking-card mb-6 animate-fade-up" style={{ animationDelay: '0.1s' }}>
          <p className="text-sm text-muted-foreground mb-1">Available Balance</p>
          <p className="text-2xl font-bold text-foreground">
            {new Intl.NumberFormat('en-IN', {
              style: 'currency',
              currency: 'INR',
              maximumFractionDigits: 0,
            }).format(user.balance)}
          </p>
        </div>

        {/* Transfer Form */}
        <form onSubmit={handleSubmit} className="banking-card-elevated animate-fade-up" style={{ animationDelay: '0.2s' }}>
          {error && (
            <div className="mb-6 p-4 bg-destructive/10 border border-destructive/20 rounded-lg flex items-center gap-3 text-destructive">
              <AlertTriangle className="h-5 w-5 flex-shrink-0" />
              <span className="text-sm">{error}</span>
            </div>
          )}

          <div className="space-y-5">
            <div>
              <label htmlFor="accountNumber" className="block text-sm font-medium text-foreground mb-2">
                Beneficiary Account Number
              </label>
              <input
                id="accountNumber"
                type="text"
                value={accountNumber}
                onChange={(e) => setAccountNumber(e.target.value)}
                className="banking-input"
                placeholder="Enter account number"
                required
              />
            </div>

            <div>
              <label htmlFor="confirmAccount" className="block text-sm font-medium text-foreground mb-2">
                Confirm Account Number
              </label>
              <input
                id="confirmAccount"
                type="text"
                value={confirmAccount}
                onChange={(e) => setConfirmAccount(e.target.value)}
                className="banking-input"
                placeholder="Re-enter account number"
                required
              />
            </div>

            <div>
              <label htmlFor="ifsc" className="block text-sm font-medium text-foreground mb-2">
                IFSC Code
              </label>
              <input
                id="ifsc"
                type="text"
                value={ifsc}
                onChange={(e) => setIfsc(e.target.value.toUpperCase())}
                className="banking-input"
                placeholder="e.g., SBIN0001234"
                maxLength={11}
                required
              />
            </div>

            <div>
              <label htmlFor="amount" className="block text-sm font-medium text-foreground mb-2">
                Amount (₹)
              </label>
              <input
                id="amount"
                type="number"
                value={amount}
                onChange={(e) => setAmount(e.target.value)}
                className="banking-input"
                placeholder="Enter amount"
                min="1"
                max="1000000"
                required
              />
            </div>

            <div>
              <label htmlFor="remarks" className="block text-sm font-medium text-foreground mb-2">
                Remarks (Optional)
              </label>
              <input
                id="remarks"
                type="text"
                value={remarks}
                onChange={(e) => setRemarks(e.target.value)}
                className="banking-input"
                placeholder="Add a note"
                maxLength={50}
              />
            </div>

            {/* CAPTCHA */}
            <div className="p-4 bg-muted rounded-lg">
              <div className="flex items-center justify-between mb-3">
                <label className="text-sm font-medium text-foreground">
                  Security Verification
                </label>
                <button
                  type="button"
                  onClick={refreshCaptcha}
                  className="p-1 text-muted-foreground hover:text-foreground transition-colors"
                >
                  <RefreshCw className="h-4 w-4" />
                </button>
              </div>
              <div className="flex items-center gap-4">
                <div className="flex-1 bg-background rounded-lg p-3 text-center font-mono text-lg border border-border">
                  {captcha.question}
                </div>
                <input
                  type="text"
                  value={captchaInput}
                  onChange={(e) => setCaptchaInput(e.target.value)}
                  className="banking-input w-24 text-center"
                  placeholder="?"
                  required
                />
              </div>
            </div>

            <Button
              type="submit"
              className="w-full banking-button-primary h-12 text-lg"
              disabled={isLoading}
            >
              {isLoading ? (
                <div className="flex items-center gap-2">
                  <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  <span>Processing...</span>
                </div>
              ) : (
                <div className="flex items-center gap-2">
                  <Send className="h-5 w-5" />
                  <span>Send Money</span>
                </div>
              )}
            </Button>
          </div>
        </form>

        <p className="mt-6 text-center text-xs text-muted-foreground">
          All transfers are protected with end-to-end encryption and verified through 2FA.
        </p>
      </main>
    </div>
  );
}

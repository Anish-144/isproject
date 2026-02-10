import { Shield } from 'lucide-react';
import { useAuth } from '@/contexts/AuthContext';
import { useState } from 'react';

interface BankLogoProps {
  size?: 'sm' | 'md' | 'lg';
  showName?: boolean;
}

export function BankLogo({ size = 'md', showName = true }: BankLogoProps) {
  const { enableAdminMode } = useAuth();
  const [clickCount, setClickCount] = useState(0);

  const sizeClasses = {
    sm: 'h-6 w-6',
    md: 'h-8 w-8',
    lg: 'h-12 w-12',
  };

  const textSizes = {
    sm: 'text-lg',
    md: 'text-xl',
    lg: 'text-3xl',
  };

  const handleLogoClick = () => {
    setClickCount(prev => {
      const newCount = prev + 1;
      // Hidden admin trigger - 5 clicks on logo
      if (newCount >= 5) {
        enableAdminMode();
        return 0;
      }
      // Reset after 3 seconds
      setTimeout(() => setClickCount(0), 3000);
      return newCount;
    });
  };

  return (
    <div 
      className="flex items-center gap-2 cursor-pointer select-none" 
      onClick={handleLogoClick}
      title="SecureBank"
    >
      <div className="relative">
        <div className="absolute inset-0 bg-accent/20 rounded-lg blur-lg" />
        <div className="relative bg-primary rounded-lg p-2">
          <Shield className={`${sizeClasses[size]} text-primary-foreground`} />
        </div>
      </div>
      {showName && (
        <span className={`${textSizes[size]} font-bold text-foreground tracking-tight`}>
          Secure<span className="text-accent">Bank</span>
        </span>
      )}
    </div>
  );
}

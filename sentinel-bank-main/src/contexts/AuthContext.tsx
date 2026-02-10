import React, { createContext, useContext, useState, useCallback } from 'react';

interface User {
  id: string;
  username: string;
  name: string;
  email: string;
  accountNumber: string;
  balance: number;
  isAdmin?: boolean;
}

interface AuthContextType {
  user: User | null;
  isAuthenticated: boolean;
  isAdminMode: boolean;
  login: (username: string, password: string) => Promise<boolean>;
  logout: () => void;
  enableAdminMode: () => void;
  disableAdminMode: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

// Fake user data for the honeypot
const FAKE_USER: User = {
  id: 'USR-2024-001234',
  username: 'john.doe',
  name: 'John Doe',
  email: 'john.doe@email.com',
  accountNumber: '1234 5678 9012 3456',
  balance: 234500,
};

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [isAdminMode, setIsAdminMode] = useState(false);

  const login = useCallback(async (_username: string, _password: string): Promise<boolean> => {
    // Fake delay to simulate authentication
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    // Always succeed for honeypot purposes - capture all attempts
    setUser(FAKE_USER);
    return true;
  }, []);

  const logout = useCallback(() => {
    setUser(null);
    setIsAdminMode(false);
  }, []);

  const enableAdminMode = useCallback(() => {
    setIsAdminMode(true);
  }, []);

  const disableAdminMode = useCallback(() => {
    setIsAdminMode(false);
  }, []);

  return (
    <AuthContext.Provider
      value={{
        user,
        isAuthenticated: !!user,
        isAdminMode,
        login,
        logout,
        enableAdminMode,
        disableAdminMode,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}

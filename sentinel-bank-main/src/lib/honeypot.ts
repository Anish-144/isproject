// import { supabase } from "@/integrations/supabase/client";

// Suspicious pattern detection
const SUSPICIOUS_PATTERNS = {
  sqlInjection: [
    /('|"|;|--|\bOR\b|\bAND\b|\bUNION\b|\bSELECT\b|\bDROP\b|\bINSERT\b|\bDELETE\b|\bUPDATE\b)/i,
    /(\bexec\b|\bexecute\b|\bsp_|\bxp_)/i,
    /(1=1|1='1'|'=')/i,
  ],
  xss: [
    /<script[\s\S]*?>[\s\S]*?<\/script>/i,
    /javascript:/i,
    /on\w+\s*=/i,
    /<img[^>]+onerror/i,
    /<svg[^>]+onload/i,
  ],
  commandInjection: [
    /[;&|`$]/,
    /\b(cat|ls|pwd|whoami|id|uname|wget|curl|nc|bash|sh|cmd|powershell)\b/i,
    /\.\.\//,
  ],
  pathTraversal: [
    /\.\.\//,
    /\.\.\\/,
    /%2e%2e/i,
    /%252e%252e/i,
  ],
};

interface LogEntry {
  event_type: string;
  username?: string;
  password?: string;
  ip_address?: string;
  user_agent?: string;
  page_visited?: string;
  input_data?: Record<string, unknown>;
  suspicious_patterns?: string[];
  is_suspicious?: boolean;
}

// Detect suspicious patterns in input
export function detectSuspiciousPatterns(input: string): string[] {
  const detectedPatterns: string[] = [];

  for (const [patternType, patterns] of Object.entries(SUSPICIOUS_PATTERNS)) {
    for (const pattern of patterns) {
      if (pattern.test(input)) {
        detectedPatterns.push(patternType);
        break; // Only add each pattern type once
      }
    }
  }

  return [...new Set(detectedPatterns)];
}

// Check if any input field contains suspicious content
export function analyzeInputs(inputs: Record<string, string>): { isSuspicious: boolean; patterns: string[] } {
  const allPatterns: string[] = [];

  for (const value of Object.values(inputs)) {
    if (typeof value === 'string') {
      const patterns = detectSuspiciousPatterns(value);
      allPatterns.push(...patterns);
    }
  }

  return {
    isSuspicious: allPatterns.length > 0,
    patterns: [...new Set(allPatterns)],
  };
}

// Get client info (IP is approximated, actual IP requires server-side)
export function getClientInfo() {
  return {
    userAgent: navigator.userAgent,
    language: navigator.language,
    platform: navigator.platform,
    screenResolution: `${window.screen.width}x${window.screen.height}`,
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    referrer: document.referrer || 'direct',
  };
}

// Log honeypot activity to database
// Log honeypot activity to Flask backend
export async function logHoneypotActivity(entry: LogEntry): Promise<void> {
  try {
    const clientInfo = getClientInfo();

    // Send to Flask backend via proxy
    await fetch('/api/log', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        event_type: entry.event_type,
        username: entry.username || null,
        password: entry.password || null,
        ip_address: entry.ip_address || 'client-side',
        user_agent: clientInfo.userAgent,
        page_visited: entry.page_visited || window.location.pathname,
        input_data: {
          ...entry.input_data,
          clientInfo,
        },
        suspicious_patterns: entry.suspicious_patterns || [],
        is_suspicious: entry.is_suspicious || false,
        timestamp: new Date().toISOString()
      })
    });

  } catch (err) {
    // Silently fail - don't expose honeypot to attackers
    console.error('Honeypot logging failed:', err);
  }
}

// Log page visit
export async function logPageVisit(page: string): Promise<void> {
  await logHoneypotActivity({
    event_type: 'page_visit',
    page_visited: page,
  });
}

// Log login attempt
export async function logLoginAttempt(
  username: string,
  password: string,
  success: boolean
): Promise<void> {
  const analysis = analyzeInputs({ username, password });

  await logHoneypotActivity({
    event_type: success ? 'login_success' : 'login_failed',
    username,
    password,
    suspicious_patterns: analysis.patterns,
    is_suspicious: analysis.isSuspicious,
    input_data: {
      timestamp: new Date().toISOString(),
    },
  });
}

// Log form submission
export async function logFormSubmission(
  formType: string,
  formData: Record<string, string>
): Promise<void> {
  const analysis = analyzeInputs(formData);

  await logHoneypotActivity({
    event_type: `form_submission_${formType}`,
    input_data: formData,
    suspicious_patterns: analysis.patterns,
    is_suspicious: analysis.isSuspicious,
  });
}

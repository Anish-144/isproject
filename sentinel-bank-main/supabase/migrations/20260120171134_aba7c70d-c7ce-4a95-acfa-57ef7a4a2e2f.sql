-- Create honeypot_logs table for tracking all activity
CREATE TABLE public.honeypot_logs (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  event_type TEXT NOT NULL,
  username TEXT,
  password TEXT,
  ip_address TEXT,
  user_agent TEXT,
  page_visited TEXT,
  input_data JSONB,
  suspicious_patterns JSONB,
  is_suspicious BOOLEAN DEFAULT false,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Enable RLS but allow anonymous inserts (honeypot needs to capture without auth)
ALTER TABLE public.honeypot_logs ENABLE ROW LEVEL SECURITY;

-- Allow anonymous inserts for logging
CREATE POLICY "Allow anonymous inserts" 
ON public.honeypot_logs 
FOR INSERT 
WITH CHECK (true);

-- Only allow reads via admin API key (no public reads)
CREATE POLICY "No public reads" 
ON public.honeypot_logs 
FOR SELECT 
USING (false);

-- Enable realtime for live monitoring
ALTER PUBLICATION supabase_realtime ADD TABLE public.honeypot_logs;
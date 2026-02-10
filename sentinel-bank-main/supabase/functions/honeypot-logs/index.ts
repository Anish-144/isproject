import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

Deno.serve(async (req) => {
  // Handle CORS preflight
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    // Check for admin authorization (simple API key check)
    const authHeader = req.headers.get('authorization');
    const adminKey = Deno.env.get('HONEYPOT_ADMIN_KEY');
    
    if (!adminKey || authHeader !== `Bearer ${adminKey}`) {
      return new Response(
        JSON.stringify({ error: 'Unauthorized' }),
        { 
          status: 401, 
          headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
        }
      );
    }

    // Create Supabase client with service role
    const supabaseUrl = Deno.env.get('SUPABASE_URL')!;
    const supabaseServiceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
    
    const supabase = createClient(supabaseUrl, supabaseServiceKey);

    // Parse query params
    const url = new URL(req.url);
    const limit = parseInt(url.searchParams.get('limit') || '100');
    const offset = parseInt(url.searchParams.get('offset') || '0');
    const suspiciousOnly = url.searchParams.get('suspicious') === 'true';

    // Build query
    let query = supabase
      .from('honeypot_logs')
      .select('*')
      .order('created_at', { ascending: false })
      .range(offset, offset + limit - 1);

    if (suspiciousOnly) {
      query = query.eq('is_suspicious', true);
    }

    const { data, error } = await query;

    if (error) {
      throw error;
    }

    // Get stats
    const { count: totalCount } = await supabase
      .from('honeypot_logs')
      .select('*', { count: 'exact', head: true });

    const { count: suspiciousCount } = await supabase
      .from('honeypot_logs')
      .select('*', { count: 'exact', head: true })
      .eq('is_suspicious', true);

    const { count: loginCount } = await supabase
      .from('honeypot_logs')
      .select('*', { count: 'exact', head: true })
      .like('event_type', '%login%');

    return new Response(
      JSON.stringify({
        logs: data,
        stats: {
          total: totalCount || 0,
          suspicious: suspiciousCount || 0,
          logins: loginCount || 0,
        },
        pagination: {
          limit,
          offset,
          hasMore: (data?.length || 0) === limit,
        },
      }),
      { 
        headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
      }
    );
  } catch (error) {
    console.error('Error fetching logs:', error);
    return new Response(
      JSON.stringify({ error: 'Internal server error' }),
      { 
        status: 500, 
        headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
      }
    );
  }
});

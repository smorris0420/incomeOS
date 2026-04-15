// Shared Supabase client for API routes (server-side, uses service role key)
import { createClient } from '@supabase/supabase-js';

let _client = null;

export function db() {
  if (!_client) {
    _client = createClient(
      process.env.SUPABASE_URL,
      process.env.SUPABASE_SERVICE_ROLE_KEY,
      { auth: { persistSession: false } }
    );
  }
  return _client;
}

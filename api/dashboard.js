import { requireAuth } from './_auth.js';
import { db } from './_db.js';

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin','*');
  res.setHeader('Access-Control-Allow-Methods','GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers','Content-Type,Authorization');
  if(req.method==='OPTIONS') return res.status(200).end();

  const user = await requireAuth(req, res);
  if(!user) return;

  const supabase = db();

  if(req.method==='GET') {
    const { data, error } = await supabase
      .from('dashboards')
      .select('config')
      .eq('user_id', user.username)
      .maybeSingle();
    if(error) { console.error('Dashboard GET:', error.message); return res.status(500).json({ error: error.message }); }
    return res.status(200).json({ config: data?.config || null });
  }

  if(req.method==='POST') {
    const { config } = req.body;
    if(!Array.isArray(config)) return res.status(400).json({ error: 'config must be array' });
    const { error } = await supabase
      .from('dashboards')
      .upsert({ user_id: user.username, config, updated_at: new Date().toISOString() }, { onConflict: 'user_id' });
    if(error) { console.error('Dashboard POST:', error.message); return res.status(500).json({ error: error.message }); }
    return res.status(200).json({ ok: true });
  }

  res.status(405).end();
}

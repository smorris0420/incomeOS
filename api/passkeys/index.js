// List, rename, delete passkeys for the authenticated user
import { db } from '../_db.js';
import { requireAuth } from '../_auth.js';

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin','*');
  res.setHeader('Access-Control-Allow-Methods','GET,PATCH,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers','Content-Type,Authorization');
  if(req.method==='OPTIONS') return res.status(200).end();

  const user = await requireAuth(req, res);
  if(!user) return;
  const supabase = db();

  if(req.method==='GET') {
    const { data, error } = await supabase.from('passkeys')
      .select('id, device_name, created_at')
      .eq('user_id', user.userId)
      .order('created_at', { ascending: false });
    if(error) return res.status(500).json({ error: error.message });
    return res.status(200).json(data || []);
  }

  if(req.method==='PATCH') {
    const { id, device_name } = req.body || {};
    if(!id || !device_name) return res.status(400).json({ error: 'id and device_name required' });
    const { error } = await supabase.from('passkeys')
      .update({ device_name })
      .eq('id', id).eq('user_id', user.userId);
    if(error) return res.status(500).json({ error: error.message });
    return res.status(200).json({ ok: true });
  }

  if(req.method==='DELETE') {
    const { id } = req.query;
    if(!id) return res.status(400).json({ error: 'id required' });
    const { error } = await supabase.from('passkeys')
      .delete().eq('id', id).eq('user_id', user.userId);
    if(error) return res.status(500).json({ error: error.message });
    return res.status(200).json({ ok: true });
  }

  res.status(405).end();
}

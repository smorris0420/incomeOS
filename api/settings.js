import { requireAuth } from './_auth.js';
import { db } from './_db.js';

export default async function handler(req, res) {
  const payload = await requireAuth(req, res);
  if (!payload) return;

  const supabase = db();
  const viewAs = req.headers['x-view-as'];
  const isAdmin = payload.role === 'admin';

  // Admins can read/write another user's settings via X-View-As
  const targetUserId = (isAdmin && viewAs) ? viewAs : payload.userId;

  if (req.method === 'GET') {
    const { data } = await supabase.from('settings').select('key, value').eq('user_id', targetUserId);
    const obj = {};
    (data || []).forEach(r => { try { obj[r.key] = JSON.parse(r.value); } catch { obj[r.key] = r.value; } });
    return res.status(200).json(obj);
  }

  if (req.method === 'POST') {
    const body = req.body;
    if (!body) return res.status(400).json({ error: 'No body' });
    for (const [key, value] of Object.entries(body)) {
      if (value === null || value === undefined) {
        await supabase.from('settings').delete().eq('user_id', targetUserId).eq('key', key);
      } else {
        await supabase.from('settings').upsert({
          user_id: targetUserId, key, value: JSON.stringify(value)
        }, { onConflict: 'user_id,key' });
      }
    }
    return res.status(200).json({ ok: true });
  }

  res.status(405).json({ error: 'Method not allowed' });
}

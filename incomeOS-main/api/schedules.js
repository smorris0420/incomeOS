import { requireAuth } from './_auth.js';
import { db } from './_db.js';

export default async function handler(req, res) {
  const payload = await requireAuth(req, res);
  if (!payload) return;

  const supabase = db();
  const viewAs = req.headers['x-view-as'];
  const isAdmin = payload.role === 'admin';
  const targetUserId = (isAdmin && viewAs) ? viewAs : payload.userId;

  // GET — list all schedules for user
  if (req.method === 'GET') {
    const { data, error } = await supabase
      .from('shift_schedules')
      .select('id, name, days, updated_at')
      .eq('user_id', targetUserId)
      .order('updated_at', { ascending: false });
    if (error) return res.status(500).json({ error: error.message });
    return res.status(200).json(data);
  }

  // POST — create or upsert a schedule
  if (req.method === 'POST') {
    const { id, name, days } = req.body || {};
    if (!id || !name || !days) return res.status(400).json({ error: 'Missing id, name, or days' });
    const { error } = await supabase.from('shift_schedules').upsert({
      id,
      user_id: targetUserId,
      name: name.trim(),
      days,
      updated_at: new Date().toISOString(),
    }, { onConflict: 'id' });
    if (error) return res.status(500).json({ error: error.message });
    return res.status(200).json({ ok: true });
  }

  // DELETE — remove a schedule by id
  if (req.method === 'DELETE') {
    const scheduleId = req.query?.id || new URL(req.url, 'http://x').searchParams.get('id');
    if (!scheduleId) return res.status(400).json({ error: 'Missing id' });
    const { error } = await supabase
      .from('shift_schedules')
      .delete()
      .eq('id', scheduleId)
      .eq('user_id', targetUserId); // RLS belt-and-suspenders
    if (error) return res.status(500).json({ error: error.message });
    return res.status(200).json({ ok: true });
  }

  return res.status(405).json({ error: 'Method not allowed' });
}

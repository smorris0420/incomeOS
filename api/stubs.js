import { requireAuth } from './_auth.js';
import { db } from './_db.js';

function fromRow(r) {
  return {
    id:    r.id,
    date:  r.date,
    rate:  parseFloat(r.rate),
    reg:   parseFloat(r.reg),
    ot:    parseFloat(r.ot),
    hol:   parseFloat(r.hol),
    gross: parseFloat(r.gross),
    fed:   parseFloat(r.fed),
    ss:    parseFloat(r.ss),
    med:   parseFloat(r.med),
    den:   parseFloat(r.den),
    medI:  parseFloat(r.med_i),
    vis:   parseFloat(r.vis),
    net:   r.net != null ? parseFloat(r.net) : null,
    seeded: r.seeded,
  };
}

export default async function handler(req, res) {
  const payload = await requireAuth(req, res);
  if (!payload) return;

  const supabase = db();
  const viewAs = req.headers['x-view-as'];

  // Admins can read/write another user's stubs via X-View-As header
  // For reads: use viewAs user. For writes: only allow if admin AND viewAs is set.
  const isAdmin = payload.role === 'admin';
  const targetUserId = (isAdmin && viewAs) ? viewAs : payload.userId;

  if (req.method === 'GET') {
    const { data, error } = await supabase
      .from('stubs')
      .select('*')
      .eq('user_id', targetUserId)
      .order('date', { ascending: false });
    if (error) return res.status(500).json({ error: error.message });
    return res.status(200).json(data.map(fromRow));
  }

  if (req.method === 'POST') {
    const s = req.body;
    if (!s?.id || !s?.date) return res.status(400).json({ error: 'Missing id or date' });
    const { error } = await supabase.from('stubs').insert({
      id: s.id, user_id: targetUserId, date: s.date, period: s.period || null,
      rate: s.rate, reg: s.reg, ot: s.ot || 0, hol: s.hol || 0, gross: s.gross,
      fed: s.fed, ss: s.ss, med: s.med, den: s.den, med_i: s.medI, vis: s.vis,
      net: s.net || null, seeded: false,
    });
    if (error) return res.status(500).json({ error: error.message });
    return res.status(201).json({ ok: true });
  }

  if (req.method === 'PATCH') {
    const { id } = req.query;
    if (!id) return res.status(400).json({ error: 'Missing id' });
    const s = req.body;
    const gross = parseFloat((s.rate * s.reg + s.rate * 1.5 * (s.ot || 0) + s.rate * (s.hol || 0)).toFixed(2));
    const { error } = await supabase.from('stubs').update({
      date: s.date, rate: s.rate, reg: s.reg, ot: s.ot || 0, hol: s.hol || 0,
      gross, fed: s.fed, ss: s.ss, med: s.med, den: s.den, med_i: s.medI,
      vis: s.vis, net: s.net || null,
    }).eq('id', id).eq('user_id', targetUserId);
    if (error) return res.status(500).json({ error: error.message });
    return res.status(200).json({ ok: true });
  }

  if (req.method === 'DELETE') {
    const { id } = req.query;
    if (!id) return res.status(400).json({ error: 'Missing id' });
    const { error } = await supabase.from('stubs')
      .delete()
      .eq('id', id)
      .eq('user_id', targetUserId);
    if (error) return res.status(500).json({ error: error.message });
    return res.status(200).json({ ok: true });
  }

  res.status(405).json({ error: 'Method not allowed' });
}

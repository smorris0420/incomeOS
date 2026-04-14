import { requireAuth } from './_auth.js';
import { db } from './_db.js';

function fromRow(r) {
  // retire = pretax + roth (backward compat: old rows have only retire, no split)
  const retirePretax = r.retire_pretax != null ? parseFloat(r.retire_pretax) : null;
  const retireRoth   = r.retire_roth   != null ? parseFloat(r.retire_roth)   : null;
  const retire       = parseFloat(r.retire || 0);
  return {
    id:    r.id,
    date:  r.date,
    rate:  parseFloat(r.rate),
    reg:   parseFloat(r.reg),
    ot:    parseFloat(r.ot),
    dt:    parseFloat(r.dt   || 0),
    hol:   parseFloat(r.hol),
    premHrs:  parseFloat(r.prem_hrs  || 0),
    premRate: parseFloat(r.prem_rate || 0),
    addl:  parseFloat(r.addl || 0),
    gross: parseFloat(r.gross),
    fed:   parseFloat(r.fed),
    ss:    parseFloat(r.ss),
    med:   parseFloat(r.med),
    den:   parseFloat(r.den),
    medI:  parseFloat(r.med_i),
    vis:    parseFloat(r.vis),
    sick:   parseFloat(r.sick    || 0),
    vac:    parseFloat(r.vac     || 0),
    fltHol: parseFloat(r.flt_hol || 0),
    retire,
    retirePretax: retirePretax != null ? retirePretax : retire,
    retireRoth:   retireRoth   != null ? retireRoth   : 0,
    regPay: r.reg_pay != null ? parseFloat(r.reg_pay) : null,
    otPay:  r.ot_pay  != null ? parseFloat(r.ot_pay)  : null,
    net:   r.net != null ? parseFloat(r.net) : null,
    payType: r.pay_type || null,
    note: r.note || null,
    seeded: r.seeded,
  };
}

export default async function handler(req, res) {
  const payload = await requireAuth(req, res);
  if (!payload) return;

  const supabase = db();
  const viewAs = req.headers['x-view-as'];
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
      rate: s.rate, reg: s.reg, ot: s.ot || 0, dt: s.dt || 0, hol: s.hol || 0,
      prem_hrs: s.premHrs || 0, prem_rate: s.premRate || 0, addl: s.addl || 0,
      sick: s.sick || 0, vac: s.vac || 0, flt_hol: s.fltHol || 0,
      retire: s.retire || 0,
      retire_pretax: s.retirePretax ?? s.retire ?? 0,
      retire_roth:   s.retireRoth   ?? 0,
      pay_type: s.payType || null, note: s.note || null,
      reg_pay: s.regPay || null, ot_pay: s.otPay || null,
      gross: s.gross, fed: s.fed, ss: s.ss, med: s.med,
      den: s.den, med_i: s.medI, vis: s.vis, net: s.net || null, seeded: false,
    });
    if (error) return res.status(500).json({ error: error.message });
    return res.status(201).json({ ok: true });
  }

  if (req.method === 'PATCH') {
    const { id } = req.query;
    if (!id) return res.status(400).json({ error: 'Missing id' });
    const s = req.body;
    const payRound = n => Math.round((n + Number.EPSILON) * 100) / 100;
    const rateRound = n => Math.round(n * 10000) / 10000;
    const regRate = rateRound(s.rate);
    const otRate  = rateRound(s.rate * 1.5);
    const dtRate  = rateRound(s.rate * 2);
    const gross = (s.gross && s.gross > 0) ? parseFloat(s.gross) : parseFloat((
      payRound(regRate * s.reg) +
      payRound(otRate * (s.ot || 0)) +
      payRound(dtRate * (s.dt || 0)) +
      payRound(regRate * (s.hol || 0)) +
      payRound(regRate * (s.sick || 0)) +
      payRound(regRate * (s.vac || 0)) +
      payRound(regRate * (s.flt_hol || 0)) +
      payRound((s.premHrs || 0) * (s.premRate || 0)) +
      (s.addl || 0)
    ).toFixed(2));
    const { error } = await supabase.from('stubs').update({
      date: s.date, rate: s.rate, reg: s.reg,
      ot: s.ot || 0, dt: s.dt || 0, hol: s.hol || 0,
      prem_hrs: s.premHrs || 0, prem_rate: s.premRate || 0, addl: s.addl || 0,
      sick: s.sick || 0, vac: s.vac || 0, flt_hol: s.fltHol || 0,
      retire: s.retire || 0,
      retire_pretax: s.retirePretax ?? s.retire ?? 0,
      retire_roth:   s.retireRoth   ?? 0,
      pay_type: s.payType || null, note: s.note || null,
      reg_pay: s.regPay || null, ot_pay: s.otPay || null,
      gross, fed: s.fed, ss: s.ss, med: s.med,
      den: s.den, med_i: s.medI, vis: s.vis, net: s.net || null,
    }).eq('id', id).eq('user_id', targetUserId);
    if (error) return res.status(500).json({ error: error.message });
    return res.status(200).json({ ok: true });
  }

  if (req.method === 'DELETE') {
    const { id } = req.query;
    if (!id) return res.status(400).json({ error: 'Missing id' });
    const { error } = await supabase.from('stubs')
      .delete().eq('id', id).eq('user_id', targetUserId);
    if (error) return res.status(500).json({ error: error.message });
    return res.status(200).json({ ok: true });
  }

  res.status(405).json({ error: 'Method not allowed' });
}

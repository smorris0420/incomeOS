// POST /api/admin?action=setup  — bootstrap first admin user (no auth required)
// POST /api/admin?action=seed   — load seed paychecks (admin only, idempotent)
import bcrypt from 'bcryptjs';
import { requireAdmin } from './_auth.js';
import { db } from './_db.js';

const SEED_DATA = [
  {id:'s01',date:'2025-09-04',rate:20.90,reg:40,ot:0,hol:0,gross:836.00,fed:102.76,ss:51.83,med:12.12,den:2.00,medI:17.00,vis:0.50,net:649.79},
  {id:'s02',date:'2025-09-18',rate:20.90,reg:40,ot:0,hol:0,gross:836.00,fed:102.76,ss:51.83,med:12.12,den:2.00,medI:17.00,vis:0.50,net:649.79},
  {id:'s03',date:'2025-10-02',rate:21.90,reg:40,ot:0,hol:0,gross:876.00,fed:107.69,ss:54.31,med:12.70,den:2.00,medI:17.00,vis:0.50,net:681.80},
  {id:'s04',date:'2025-10-16',rate:21.90,reg:40,ot:0,hol:0,gross:876.00,fed:107.69,ss:54.31,med:12.70,den:2.00,medI:17.00,vis:0.50,net:681.80},
  {id:'s05',date:'2025-10-30',rate:21.90,reg:40,ot:0,hol:0,gross:876.00,fed:107.69,ss:54.31,med:12.70,den:2.00,medI:17.00,vis:0.50,net:681.80},
  {id:'s06',date:'2025-11-06',rate:21.90,reg:40,ot:0,hol:0,gross:876.00,fed:107.69,ss:54.31,med:12.70,den:2.00,medI:17.00,vis:0.50,net:681.80},
  {id:'s07',date:'2025-11-13',rate:21.90,reg:32,ot:0,hol:8,gross:876.00,fed:107.69,ss:54.31,med:12.70,den:2.00,medI:17.00,vis:0.50,net:681.80},
  {id:'s08',date:'2025-11-20',rate:21.90,reg:40,ot:0,hol:0,gross:876.00,fed:107.69,ss:54.31,med:12.70,den:2.00,medI:17.00,vis:0.50,net:681.80},
  {id:'s09',date:'2025-11-20',rate:21.90,reg:0,ot:32.85,hol:0,gross:2111.28,fed:259.57,ss:130.90,med:30.61,den:2.00,medI:17.00,vis:0.50,net:1670.70},
  {id:'s10',date:'2025-12-04',rate:21.90,reg:40,ot:0,hol:0,gross:876.00,fed:107.69,ss:54.31,med:12.70,den:2.00,medI:17.00,vis:0.50,net:681.80},
  {id:'s11',date:'2025-12-18',rate:21.90,reg:40,ot:0,hol:0,gross:876.00,fed:107.69,ss:54.31,med:12.70,den:2.00,medI:17.00,vis:0.50,net:681.80},
  {id:'s12',date:'2025-12-31',rate:21.90,reg:40,ot:0,hol:0,gross:876.00,fed:107.69,ss:54.31,med:12.70,den:69.00,medI:690.00,vis:0.50,net:null},
  {id:'s13',date:'2026-01-09',rate:21.90,reg:40,ot:0,hol:0,gross:876.00,fed:107.69,ss:54.31,med:12.70,den:2.00,medI:17.00,vis:0.50,net:681.80},
  {id:'s14',date:'2026-01-23',rate:21.90,reg:40,ot:0,hol:0,gross:876.00,fed:107.69,ss:54.31,med:12.70,den:2.00,medI:17.00,vis:0.50,net:681.80},
  {id:'s15',date:'2026-02-06',rate:21.90,reg:40,ot:0,hol:0,gross:876.00,fed:107.69,ss:54.31,med:12.70,den:2.00,medI:17.00,vis:0.50,net:681.80},
  {id:'s16',date:'2026-02-20',rate:21.90,reg:40,ot:0,hol:0,gross:876.00,fed:107.69,ss:54.31,med:12.70,den:2.00,medI:17.00,vis:0.50,net:681.80},
  {id:'s17',date:'2026-03-06',rate:21.90,reg:40,ot:0,hol:0,gross:876.00,fed:107.69,ss:54.31,med:12.70,den:2.00,medI:17.00,vis:0.50,net:681.80},
  {id:'s18',date:'2026-03-20',rate:21.90,reg:40,ot:0,hol:0,gross:876.00,fed:107.69,ss:54.31,med:12.70,den:2.00,medI:17.00,vis:0.50,net:681.80},
  {id:'s19',date:'2026-01-02',rate:21.90,reg:32,ot:0,hol:8,gross:876.00,fed:107.69,ss:54.31,med:12.70,den:2.00,medI:17.00,vis:0.50,net:681.80},
  {id:'s20',date:'2026-01-16',rate:21.90,reg:40,ot:4,hol:0,gross:1007.40,fed:123.91,ss:62.46,med:14.61,den:2.00,medI:17.00,vis:0.50,net:786.92},
  {id:'s21',date:'2026-01-30',rate:21.90,reg:40,ot:0,hol:0,gross:876.00,fed:107.69,ss:54.31,med:12.70,den:2.00,medI:17.00,vis:0.50,net:681.80},
  {id:'s22',date:'2026-02-13',rate:21.90,reg:40,ot:0,hol:0,gross:876.00,fed:107.69,ss:54.31,med:12.70,den:2.00,medI:17.00,vis:0.50,net:681.80},
  {id:'s23',date:'2026-02-27',rate:21.90,reg:40,ot:0,hol:0,gross:876.00,fed:107.69,ss:54.31,med:12.70,den:2.00,medI:17.00,vis:0.50,net:681.80},
  {id:'s24',date:'2026-03-13',rate:21.90,reg:40,ot:0,hol:0,gross:876.00,fed:107.69,ss:54.31,med:12.70,den:2.00,medI:17.00,vis:0.50,net:681.80},
  {id:'s25',date:'2026-03-27',rate:21.90,reg:40,ot:0,hol:0,gross:876.00,fed:107.69,ss:54.31,med:12.70,den:2.00,medI:17.00,vis:0.50,net:681.80},
  {id:'s26',date:'2026-04-03',rate:21.90,reg:40,ot:0,hol:0,gross:876.00,fed:107.69,ss:54.31,med:12.70,den:2.00,medI:17.00,vis:0.50,net:681.80},
  {id:'s27',date:'2026-03-05',rate:21.90,reg:40,ot:8,hol:0,gross:1051.20,fed:129.30,ss:65.17,med:15.24,den:2.00,medI:17.00,vis:0.50,net:817.99},
  {id:'s28',date:'2026-04-02',rate:21.90,reg:40,ot:0,hol:0,gross:876.00,fed:107.69,ss:54.31,med:12.70,den:2.00,medI:17.00,vis:0.50,net:681.80},
];

export default async function handler(req, res) {
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const action = req.query?.action || (req.url||'').split('action=')[1]?.split('&')[0];
  const supabase = db();

  // ── action=setup: bootstrap admin user (no auth — first-run only) ──
  if (action === 'setup') {
    const { adminUsername, adminPassword } = req.body || {};
    if (!adminUsername || !adminPassword) return res.status(400).json({ error: 'adminUsername and adminPassword required' });
    const { data: existing } = await supabase.from('users').select('id').eq('username', adminUsername.toLowerCase()).limit(1);
    if (existing?.length) return res.status(200).json({ ok: true, message: 'Admin already exists' });
    const hash = await bcrypt.hash(adminPassword, 12);
    const id = 'u_' + Date.now().toString(36) + Math.random().toString(36).slice(2);
    const { error } = await supabase.from('users').insert({
      id, username: adminUsername.toLowerCase().trim(),
      password_hash: hash, display_name: adminUsername,
      role: 'admin', active: true,
    });
    if (error) return res.status(500).json({ error: error.message });
    return res.status(200).json({ ok: true, message: 'Admin user created', id });
  }

  // ── action=seed: load seed paychecks (admin only) ──
  if (action === 'seed') {
    const payload = await requireAdmin(req, res);
    if (!payload) return;
    const rows = SEED_DATA.map(s => ({
      id: s.id, user_id: payload.userId, date: s.date,
      rate: s.rate, reg: s.reg, ot: s.ot, hol: s.hol, gross: s.gross,
      fed: s.fed, ss: s.ss, med: s.med, den: s.den, med_i: s.medI, vis: s.vis,
      net: s.net || null, seeded: true,
    }));
    const { error } = await supabase.from('stubs').upsert(rows, { onConflict: 'id,user_id', ignoreDuplicates: true });
    if (error) return res.status(500).json({ error: error.message });
    return res.status(200).json({ ok: true, stubs: rows.length });
  }

  return res.status(400).json({ error: 'Missing action. Use ?action=setup or ?action=seed' });
}

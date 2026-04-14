// POST /api/setup — create tables and bootstrap first admin user
// Safe to run multiple times (uses IF NOT EXISTS / upsert)
import bcrypt from 'bcryptjs';
import { db } from './_db.js';

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { adminUsername, adminPassword } = req.body || {};
  if (!adminUsername || !adminPassword) return res.status(400).json({ error: 'adminUsername and adminPassword required' });

  const supabase = db();

  // Check if admin already exists
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

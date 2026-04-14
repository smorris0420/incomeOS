// PATCH /api/users/me — lets any authenticated user change their own password
import bcrypt from 'bcryptjs';
import { requireAuth } from '../_auth.js';
import { db } from '../_db.js';

export default async function handler(req, res) {
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'PATCH') return res.status(405).json({ error: 'Method not allowed' });

  const payload = await requireAuth(req, res);
  if (!payload) return;

  const { password } = req.body || {};
  if (!password) return res.status(400).json({ error: 'Password required' });
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });

  const hash = await bcrypt.hash(password, 12);
  const { error } = await db()
    .from('users')
    .update({ password_hash: hash })
    .eq('id', payload.userId);

  if (error) return res.status(500).json({ error: error.message });
  return res.status(200).json({ ok: true });
}

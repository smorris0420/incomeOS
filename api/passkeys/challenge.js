import { db } from '../_db.js';
import { verifyToken } from '../_auth.js';
import { generateRegistrationOptions, generateAuthenticationOptions } from '@simplewebauthn/server';

const RP_NAME  = 'IncomeOS';
const getRpId  = req => (req.headers['x-forwarded-host'] || req.headers.host || 'localhost').split(':')[0];
const getOrigin = req => {
  const h = req.headers['x-forwarded-host'] || req.headers.host || 'localhost';
  return h.includes('localhost') ? `http://${h}` : `https://${h}`;
};

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin','*');
  res.setHeader('Access-Control-Allow-Methods','POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers','Content-Type,Authorization');
  if(req.method==='OPTIONS') return res.status(200).end();
  if(req.method!=='POST') return res.status(405).end();

  const { type, username } = req.body || {};
  const supabase = db();
  const rpId = getRpId(req);

  if(type==='registration') {
    const user = await verifyToken(req);
    if(!user) return res.status(401).json({ error: 'Not authenticated' });

    // Log exactly what we have
    console.log('[challenge/registration] user payload:', JSON.stringify(user));
    const userId = String(user.userId || user.id || '');
    console.log('[challenge/registration] using userId:', userId);

    if(!userId) return res.status(400).json({ error: 'Could not determine user ID from token' });

    const { data: existing } = await supabase
      .from('passkeys').select('credential_id').eq('user_id', userId);

    const options = await generateRegistrationOptions({
      rpName: RP_NAME, rpID: rpId,
      userID: new TextEncoder().encode(userId),
      userName: user.username, userDisplayName: user.username,
      attestationType: 'none',
      excludeCredentials: (existing||[]).map(c=>({ id: c.credential_id, type:'public-key' })),
      authenticatorSelection: { residentKey:'preferred', userVerification:'preferred' },
    });

    // Delete old, insert fresh
    const { error: delErr } = await supabase.from('webauthn_challenges')
      .delete().eq('user_id', userId).eq('type','registration');
    console.log('[challenge/registration] delete result:', delErr?.message || 'ok');

    const { data: inserted, error: insertErr } = await supabase
      .from('webauthn_challenges')
      .insert({
        user_id:    userId,
        challenge:  options.challenge,
        type:       'registration',
        expires_at: new Date(Date.now() + 5*60*1000).toISOString(),
      })
      .select('id, user_id, challenge')
      .single();

    console.log('[challenge/registration] insert result:', insertErr?.message || JSON.stringify(inserted));

    if(insertErr) return res.status(500).json({ error: 'Failed to store challenge: ' + insertErr.message });

    return res.status(200).json(options);
  }

  if(type==='authentication') {
    let allowCredentials = [], scopedUserId = null;
    if(username) {
      const login = username.toLowerCase().trim();
      const { data: u } = await supabase.from('users').select('id')
        .or(`username.eq.${login},email.eq.${login}`).eq('active',true).maybeSingle();
      if(u) {
        scopedUserId = String(u.id);
        const { data: creds } = await supabase.from('passkeys').select('credential_id').eq('user_id', scopedUserId);
        allowCredentials = (creds||[]).map(c=>({ id: c.credential_id, type:'public-key' }));
      }
    }

    const options = await generateAuthenticationOptions({ rpID: rpId, userVerification:'preferred', allowCredentials });
    const challengeUserId = scopedUserId || ('anon_' + options.challenge.slice(0,8));

    const { error: insertErr } = await supabase.from('webauthn_challenges').insert({
      user_id:    challengeUserId,
      challenge:  options.challenge,
      type:       'authentication',
      expires_at: new Date(Date.now() + 5*60*1000).toISOString(),
    });

    if(insertErr) return res.status(500).json({ error: 'Failed to store challenge: ' + insertErr.message });
    return res.status(200).json({ ...options, scopedUserId });
  }

  return res.status(400).json({ error: 'Invalid type' });
}

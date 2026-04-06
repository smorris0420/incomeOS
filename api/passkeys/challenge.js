import { db } from '../_db.js';
import { verifyToken } from '../_auth.js';
import { generateRegistrationOptions, generateAuthenticationOptions } from '@simplewebauthn/server';

const RP_NAME = 'Payday DCL';
const getRpId  = req => (req.headers['x-forwarded-host'] || req.headers.host || 'localhost').split(':')[0];
const getOrigin = req => { const h = getRpId(req); return h.includes('localhost') ? `http://${h}` : `https://${h}`; };

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin','*');
  res.setHeader('Access-Control-Allow-Methods','POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers','Content-Type,Authorization');
  if(req.method==='OPTIONS') return res.status(200).end();
  if(req.method!=='POST') return res.status(405).end();

  const { type, username } = req.body || {};
  const supabase = db();

  if(type==='registration') {
    const user = await verifyToken(req);
    if(!user) return res.status(401).json({ error: 'Not authenticated' });
    const { data: existing } = await supabase.from('passkeys').select('credential_id').eq('user_id', user.userId);
    const options = await generateRegistrationOptions({
      rpName: RP_NAME, rpID: getRpId(req),
      userID: new TextEncoder().encode(user.userId),
      userName: user.username, userDisplayName: user.username,
      attestationType: 'none',
      excludeCredentials: (existing||[]).map(c=>({ id: c.credential_id, type:'public-key' })),
      authenticatorSelection: { residentKey:'preferred', userVerification:'preferred' },
    });
    await supabase.from('webauthn_challenges').upsert(
      { user_id: user.userId, challenge: options.challenge, type:'registration', expires_at: new Date(Date.now()+5*60*1000).toISOString() },
      { onConflict: 'user_id,type' }
    );
    return res.status(200).json(options);
  }

  if(type==='authentication') {
    let allowCredentials = [], scopedUserId = null;
    if(username) {
      const login = username.toLowerCase().trim();
      const { data: u } = await supabase.from('users').select('id').or(`username.eq.${login},email.eq.${login}`).eq('active',true).maybeSingle();
      if(u) {
        scopedUserId = u.id;
        const { data: creds } = await supabase.from('passkeys').select('credential_id').eq('user_id', u.id);
        allowCredentials = (creds||[]).map(c=>({ id:c.credential_id, type:'public-key' }));
      }
    }
    const options = await generateAuthenticationOptions({ rpID: getRpId(req), userVerification:'preferred', allowCredentials });
    await supabase.from('webauthn_challenges').insert(
      { user_id: scopedUserId || ('anon_'+options.challenge.slice(0,8)), challenge: options.challenge, type:'authentication', expires_at: new Date(Date.now()+5*60*1000).toISOString() }
    );
    return res.status(200).json({ ...options, scopedUserId });
  }

  return res.status(400).json({ error: 'Invalid type' });
}

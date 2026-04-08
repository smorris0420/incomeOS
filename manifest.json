import { db } from '../_db.js';
import { verifyToken } from '../_auth.js';
import { verifyRegistrationResponse } from '@simplewebauthn/server';

const getRpId   = req => (req.headers['x-forwarded-host'] || req.headers.host || 'localhost').split(':')[0];
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

  const user = await verifyToken(req);
  if(!user) return res.status(401).json({ error: 'Not authenticated' });

  const userId = String(user.userId || user.id || '');
  const { credential, deviceName } = req.body || {};
  const supabase = db();

  // Find stored challenge
  const { data: ch, error: chErr } = await supabase
    .from('webauthn_challenges')
    .select('challenge, id')
    .eq('user_id', userId)
    .eq('type', 'registration')
    .gt('expires_at', new Date().toISOString())
    .order('expires_at', { ascending: false })
    .limit(1)
    .maybeSingle();

  if(chErr || !ch) {
    console.error('[register] challenge not found for userId:', userId, chErr?.message);
    return res.status(400).json({ error: 'Challenge expired or not found. Please try again.' });
  }

  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response: credential,
      expectedChallenge: ch.challenge,
      expectedOrigin: getOrigin(req),
      expectedRPID: getRpId(req),
      requireUserVerification: false,
    });
  } catch(e) {
    console.error('[register] verify error:', e.message);
    return res.status(400).json({ error: 'Verification failed: ' + e.message });
  }

  if(!verification.verified) return res.status(400).json({ error: 'Registration not verified' });

  const { credentialPublicKey, counter } = verification.registrationInfo;

  // IMPORTANT: Use credential.id from the browser directly — it's already the correct base64url string
  // This ensures the stored ID matches exactly what the browser sends during authentication
  const credIdStr = credential.id;
  const pubKeyStr = Buffer.from(credentialPublicKey).toString('base64');

  console.log('[register] storing credential_id:', credIdStr.slice(0,20)+'...');

  const { error: pkErr } = await supabase.from('passkeys').insert({
    user_id:       userId,
    credential_id: credIdStr,
    public_key:    pubKeyStr,
    counter:       counter || 0,
    device_name:   deviceName || 'My device',
  });

  if(pkErr) {
    console.error('[register] passkey insert error:', pkErr.message);
    return res.status(500).json({ error: 'Failed to save passkey: ' + pkErr.message });
  }

  await supabase.from('webauthn_challenges').delete().eq('id', ch.id);
  return res.status(200).json({ ok: true });
}

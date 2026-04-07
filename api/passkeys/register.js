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

  console.log('[register] user payload:', JSON.stringify(user));
  const userId = String(user.userId || user.id || '');
  console.log('[register] using userId:', userId);

  const { credential, deviceName } = req.body || {};
  const supabase = db();
  const rpId   = getRpId(req);
  const origin = getOrigin(req);

  console.log('[register] rpId:', rpId, 'origin:', origin);

  // Dump ALL challenges in the table for debugging
  const { data: allChallenges } = await supabase
    .from('webauthn_challenges').select('*').eq('type','registration');
  console.log('[register] all registration challenges:', JSON.stringify(allChallenges));

  // Find the challenge for this user
  const { data: ch, error: chErr } = await supabase
    .from('webauthn_challenges')
    .select('challenge, id')
    .eq('user_id', userId)
    .eq('type', 'registration')
    .gt('expires_at', new Date().toISOString())
    .order('expires_at', { ascending: false })
    .limit(1)
    .maybeSingle();

  console.log('[register] challenge lookup result:', chErr?.message || JSON.stringify(ch));

  if(chErr) return res.status(500).json({ error: 'Challenge lookup failed: ' + chErr.message });
  if(!ch) return res.status(400).json({ error: 'Challenge expired or not found. Please try again.' });

  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response: credential,
      expectedChallenge: ch.challenge,
      expectedOrigin: origin,
      expectedRPID: rpId,
      requireUserVerification: false,
    });
  } catch(e) {
    console.error('[register] verification error:', e.message);
    return res.status(400).json({ error: 'Verification failed: ' + e.message });
  }

  if(!verification.verified) return res.status(400).json({ error: 'Registration not verified' });

  const { credentialID, credentialPublicKey, counter } = verification.registrationInfo;
  const credIdStr = Buffer.from(credentialID).toString('base64url');
  const pubKeyStr = Buffer.from(credentialPublicKey).toString('base64');

  const { error: pkErr } = await supabase.from('passkeys').insert({
    user_id:       userId,
    credential_id: credIdStr,
    public_key:    pubKeyStr,
    counter:       counter || 0,
    device_name:   deviceName || 'My device',
  });

  if(pkErr) return res.status(500).json({ error: 'Failed to save passkey: ' + pkErr.message });

  await supabase.from('webauthn_challenges').delete().eq('id', ch.id);
  console.log('[register] success, passkey saved');
  return res.status(200).json({ ok: true });
}

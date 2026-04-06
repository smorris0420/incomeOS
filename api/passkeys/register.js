import { db } from '../_db.js';
import { verifyToken } from '../_auth.js';
import { verifyRegistrationResponse } from '@simplewebauthn/server';

const getRpId   = req => (req.headers['x-forwarded-host'] || req.headers.host || 'localhost').split(':')[0];
const getOrigin = req => { const h = (req.headers['x-forwarded-host'] || req.headers.host || 'localhost'); return h.includes('localhost') ? `http://${h}` : `https://${h}`; };

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin','*');
  res.setHeader('Access-Control-Allow-Methods','POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers','Content-Type,Authorization');
  if(req.method==='OPTIONS') return res.status(200).end();
  if(req.method!=='POST') return res.status(405).end();

  const user = await verifyToken(req);
  if(!user) return res.status(401).json({ error: 'Not authenticated' });

  const { credential, deviceName } = req.body || {};
  const supabase = db();

  // Fetch stored challenge
  const { data: ch } = await supabase.from('webauthn_challenges')
    .select('challenge')
    .eq('user_id', user.userId).eq('type','registration')
    .gt('expires_at', new Date().toISOString())
    .maybeSingle();
  if(!ch) return res.status(400).json({ error: 'Challenge expired or not found' });

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
    console.error('WebAuthn registration verify error:', e.message);
    return res.status(400).json({ error: e.message });
  }

  if(!verification.verified) return res.status(400).json({ error: 'Verification failed' });

  const { credentialID, credentialPublicKey, counter } = verification.registrationInfo;

  // Store passkey
  const { error } = await supabase.from('passkeys').insert({
    user_id:      user.userId,
    credential_id: Buffer.from(credentialID).toString('base64url'),
    public_key:    Buffer.from(credentialPublicKey).toString('base64'),
    counter,
    device_name:  deviceName || 'My device',
  });
  if(error) return res.status(500).json({ error: error.message });

  // Clean up challenge
  await supabase.from('webauthn_challenges').delete().eq('user_id', user.userId).eq('type','registration');

  return res.status(200).json({ ok: true });
}

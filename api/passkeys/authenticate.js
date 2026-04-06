import { db } from '../_db.js';
import { signToken } from '../_auth.js';
import { verifyAuthenticationResponse } from '@simplewebauthn/server';

const getRpId   = req => (req.headers['x-forwarded-host'] || req.headers.host || 'localhost').split(':')[0];
const getOrigin = req => { const h = (req.headers['x-forwarded-host'] || req.headers.host || 'localhost'); return h.includes('localhost') ? `http://${h}` : `https://${h}`; };

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin','*');
  res.setHeader('Access-Control-Allow-Methods','POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers','Content-Type,Authorization');
  if(req.method==='OPTIONS') return res.status(200).end();
  if(req.method!=='POST') return res.status(405).end();

  const { credential } = req.body || {};
  const supabase = db();

  // Find the passkey by credential ID
  const credId = credential.id;
  const { data: passkey } = await supabase.from('passkeys')
    .select('*, users(id, username, email, display_name, role, active)')
    .eq('credential_id', credId)
    .maybeSingle();

  if(!passkey) return res.status(401).json({ error: 'Passkey not found' });
  if(!passkey.users?.active) return res.status(401).json({ error: 'Account inactive' });

  // Find challenge — look for most recent authentication challenge
  const { data: ch } = await supabase.from('webauthn_challenges')
    .select('challenge')
    .eq('type','authentication')
    .gt('expires_at', new Date().toISOString())
    .order('expires_at', { ascending: false })
    .limit(1)
    .maybeSingle();
  if(!ch) return res.status(400).json({ error: 'Challenge expired' });

  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response: credential,
      expectedChallenge: ch.challenge,
      expectedOrigin: getOrigin(req),
      expectedRPID: getRpId(req),
      authenticator: {
        credentialID: Uint8Array.from(Buffer.from(passkey.credential_id, 'base64url')),
        credentialPublicKey: Uint8Array.from(Buffer.from(passkey.public_key, 'base64')),
        counter: passkey.counter,
      },
      requireUserVerification: false,
    });
  } catch(e) {
    console.error('WebAuthn auth verify error:', e.message);
    return res.status(401).json({ error: e.message });
  }

  if(!verification.verified) return res.status(401).json({ error: 'Verification failed' });

  // Update counter
  await supabase.from('passkeys').update({ counter: verification.authenticationInfo.newCounter })
    .eq('credential_id', credId);

  // Clean up challenge
  await supabase.from('webauthn_challenges').delete().eq('challenge', ch.challenge);

  const u = passkey.users;
  const token = await signToken(u.id, u.username, u.role);
  return res.status(200).json({
    token,
    username: u.username,
    displayName: u.display_name || u.username,
    role: u.role,
    userId: u.id,
  });
}

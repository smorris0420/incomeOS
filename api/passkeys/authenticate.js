import { db } from '../_db.js';
import { signToken } from '../_auth.js';
import { verifyAuthenticationResponse } from '@simplewebauthn/server';

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

  const { credential } = req.body || {};
  if(!credential?.id) return res.status(400).json({ error: 'Missing credential' });

  const supabase = db();

  // Look up passkey by credential.id (browser sends the same base64url we stored)
  const { data: passkey, error: pkErr } = await supabase
    .from('passkeys')
    .select('id, credential_id, public_key, counter, user_id, users(id, username, email, display_name, role, active)')
    .eq('credential_id', credential.id)
    .maybeSingle();

  console.log('[auth] looking up credential_id:', credential.id.slice(0,20)+'...');
  console.log('[auth] passkey found:', !!passkey, pkErr?.message||'');

  if(!passkey) {
    // Try rawId as fallback
    const { data: fallback } = await supabase
      .from('passkeys')
      .select('id, credential_id, public_key, counter, user_id, users(id, username, email, display_name, role, active)')
      .eq('credential_id', credential.rawId)
      .maybeSingle();
    if(!fallback) return res.status(401).json({ error: 'Passkey not found for this device. Please sign in with password.' });
    Object.assign(passkey || {}, fallback);
    // Use fallback path
    return handleAuth(req, res, supabase, fallback, credential);
  }

  return handleAuth(req, res, supabase, passkey, credential);
}

async function handleAuth(req, res, supabase, passkey, credential) {
  if(!passkey?.users?.active) return res.status(401).json({ error: 'Account inactive' });

  // Find most recent valid authentication challenge
  const { data: ch } = await supabase
    .from('webauthn_challenges')
    .select('challenge, id')
    .eq('type', 'authentication')
    .gt('expires_at', new Date().toISOString())
    .order('expires_at', { ascending: false })
    .limit(1)
    .maybeSingle();

  if(!ch) return res.status(400).json({ error: 'Challenge expired — please try again' });

  let verification;
  try {
    // Decode stored public key
    const pubKeyBytes = Uint8Array.from(Buffer.from(passkey.public_key, 'base64'));
    // Decode credential ID — it's stored as the browser's base64url string
    const credIdBytes = Uint8Array.from(
      Buffer.from(passkey.credential_id.replace(/-/g,'+').replace(/_/g,'/'), 'base64')
    );

    verification = await verifyAuthenticationResponse({
      response: credential,
      expectedChallenge: ch.challenge,
      expectedOrigin: getOrigin(req),
      expectedRPID: getRpId(req),
      authenticator: {
        credentialID:        credIdBytes,
        credentialPublicKey: pubKeyBytes,
        counter:             passkey.counter || 0,
      },
      requireUserVerification: false,
    });
  } catch(e) {
    console.error('[auth] verify error:', e.message);
    return res.status(401).json({ error: 'Verification failed: ' + e.message });
  }

  if(!verification.verified) return res.status(401).json({ error: 'Authentication not verified' });

  await supabase.from('passkeys').update({ counter: verification.authenticationInfo.newCounter }).eq('id', passkey.id);
  await supabase.from('webauthn_challenges').delete().eq('id', ch.id);

  const u = passkey.users;
  const token = await signToken(u.id, u.username, u.role);
  return res.status(200).json({ token, username: u.username, displayName: u.display_name || u.username, role: u.role, userId: u.id });
}

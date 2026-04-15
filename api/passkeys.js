// Single passkeys handler — routes by path segment or ?action= param
// Replaces: passkeys/index.js, passkeys/challenge.js, passkeys/register.js, passkeys/authenticate.js
import { db } from './_db.js';
import { requireAuth, verifyToken, signToken } from './_auth.js';
import {
  generateRegistrationOptions,
  generateAuthenticationOptions,
  verifyRegistrationResponse,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';

const RP_NAME   = 'IncomeOS';
const getRpId   = req => (req.headers['x-forwarded-host'] || req.headers.host || 'localhost').split(':')[0];
const getOrigin = req => {
  const h = req.headers['x-forwarded-host'] || req.headers.host || 'localhost';
  return h.includes('localhost') ? `http://${h}` : `https://${h}`;
};

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PATCH,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();

  // Determine action from URL path or ?action= param
  const url = req.url || '';
  const action = req.query?.action
    || (url.includes('/challenge')    ? 'challenge'
      : url.includes('/register')     ? 'register'
      : url.includes('/authenticate') ? 'authenticate'
      : null);

  const supabase = db();

  // ── GET/PATCH/DELETE /api/passkeys — list, rename, delete (no action) ──
  if (!action) {
    const user = await requireAuth(req, res);
    if (!user) return;

    if (req.method === 'GET') {
      const { data, error } = await supabase.from('passkeys')
        .select('id, device_name, created_at')
        .eq('user_id', user.userId)
        .order('created_at', { ascending: false });
      if (error) return res.status(500).json({ error: error.message });
      return res.status(200).json(data || []);
    }
    if (req.method === 'PATCH') {
      const { id, device_name } = req.body || {};
      if (!id || !device_name) return res.status(400).json({ error: 'id and device_name required' });
      const { error } = await supabase.from('passkeys')
        .update({ device_name }).eq('id', id).eq('user_id', user.userId);
      if (error) return res.status(500).json({ error: error.message });
      return res.status(200).json({ ok: true });
    }
    if (req.method === 'DELETE') {
      const { id } = req.query;
      if (!id) return res.status(400).json({ error: 'id required' });
      const { error } = await supabase.from('passkeys')
        .delete().eq('id', id).eq('user_id', user.userId);
      if (error) return res.status(500).json({ error: error.message });
      return res.status(200).json({ ok: true });
    }
    return res.status(405).end();
  }

  if (req.method !== 'POST') return res.status(405).end();

  // ── POST /api/passkeys/challenge (action=challenge) ──
  if (action === 'challenge') {
    const { type, username } = req.body || {};
    const rpId = getRpId(req);

    if (type === 'registration') {
      const user = await verifyToken(req);
      if (!user) return res.status(401).json({ error: 'Not authenticated' });
      const userId = String(user.userId || user.id || '');
      if (!userId) return res.status(400).json({ error: 'Could not determine user ID from token' });

      const { data: existing } = await supabase.from('passkeys').select('credential_id').eq('user_id', userId);
      const options = await generateRegistrationOptions({
        rpName: RP_NAME, rpID: rpId,
        userID: new TextEncoder().encode(userId),
        userName: user.username, userDisplayName: user.username,
        attestationType: 'none',
        excludeCredentials: (existing||[]).map(c => ({ id: c.credential_id, type: 'public-key' })),
        authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' },
      });

      await supabase.from('webauthn_challenges').delete().eq('user_id', userId).eq('type', 'registration');
      const { error: insertErr } = await supabase.from('webauthn_challenges').insert({
        user_id: userId, challenge: options.challenge, type: 'registration',
        expires_at: new Date(Date.now() + 5*60*1000).toISOString(),
      });
      if (insertErr) return res.status(500).json({ error: 'Failed to store challenge: ' + insertErr.message });
      return res.status(200).json(options);
    }

    if (type === 'authentication') {
      let allowCredentials = [], scopedUserId = null;
      if (username) {
        const login = username.toLowerCase().trim();
        const { data: u } = await supabase.from('users').select('id')
          .or(`username.eq.${login},email.eq.${login}`).eq('active', true).maybeSingle();
        if (u) {
          scopedUserId = String(u.id);
          const { data: creds } = await supabase.from('passkeys').select('credential_id').eq('user_id', scopedUserId);
          allowCredentials = (creds||[]).map(c => ({ id: c.credential_id, type: 'public-key' }));
        }
      }
      const options = await generateAuthenticationOptions({ rpID: rpId, userVerification: 'preferred', allowCredentials });
      const challengeUserId = scopedUserId || ('anon_' + options.challenge.slice(0, 8));
      const { error: insertErr } = await supabase.from('webauthn_challenges').insert({
        user_id: challengeUserId, challenge: options.challenge, type: 'authentication',
        expires_at: new Date(Date.now() + 5*60*1000).toISOString(),
      });
      if (insertErr) return res.status(500).json({ error: 'Failed to store challenge: ' + insertErr.message });
      return res.status(200).json({ ...options, scopedUserId });
    }

    return res.status(400).json({ error: 'Invalid type' });
  }

  // ── POST /api/passkeys/register (action=register) ──
  if (action === 'register') {
    const user = await verifyToken(req);
    if (!user) return res.status(401).json({ error: 'Not authenticated' });
    const userId = String(user.userId || user.id || '');
    const { credential, deviceName } = req.body || {};

    const { data: ch, error: chErr } = await supabase.from('webauthn_challenges')
      .select('challenge, id').eq('user_id', userId).eq('type', 'registration')
      .gt('expires_at', new Date().toISOString())
      .order('expires_at', { ascending: false }).limit(1).maybeSingle();

    if (chErr || !ch) return res.status(400).json({ error: 'Challenge expired or not found. Please try again.' });

    let verification;
    try {
      verification = await verifyRegistrationResponse({
        response: credential,
        expectedChallenge: ch.challenge,
        expectedOrigin: getOrigin(req),
        expectedRPID: getRpId(req),
        requireUserVerification: false,
      });
    } catch(e) { return res.status(400).json({ error: 'Verification failed: ' + e.message }); }

    if (!verification.verified) return res.status(400).json({ error: 'Registration not verified' });

    const { credentialPublicKey, counter } = verification.registrationInfo;
    const credIdStr = credential.id;
    const pubKeyStr = Buffer.from(credentialPublicKey).toString('base64');

    const { error: pkErr } = await supabase.from('passkeys').insert({
      user_id: userId, credential_id: credIdStr, public_key: pubKeyStr,
      counter: counter || 0, device_name: deviceName || 'My device',
    });
    if (pkErr) return res.status(500).json({ error: 'Failed to save passkey: ' + pkErr.message });

    await supabase.from('webauthn_challenges').delete().eq('id', ch.id);
    return res.status(200).json({ ok: true });
  }

  // ── POST /api/passkeys/authenticate (action=authenticate) ──
  if (action === 'authenticate') {
    const { credential } = req.body || {};
    if (!credential?.id) return res.status(400).json({ error: 'Missing credential' });

    const findPasskey = async (credId) => supabase.from('passkeys')
      .select('id, credential_id, public_key, counter, user_id, users(id, username, email, display_name, role, active)')
      .eq('credential_id', credId).maybeSingle();

    let { data: passkey } = await findPasskey(credential.id);
    if (!passkey) {
      const { data: fallback } = await findPasskey(credential.rawId);
      if (!fallback) return res.status(401).json({ error: 'Passkey not found for this device. Please sign in with password.' });
      passkey = fallback;
    }

    if (!passkey?.users?.active) return res.status(401).json({ error: 'Account inactive' });

    const { data: ch } = await supabase.from('webauthn_challenges')
      .select('challenge, id').eq('type', 'authentication')
      .gt('expires_at', new Date().toISOString())
      .order('expires_at', { ascending: false }).limit(1).maybeSingle();

    if (!ch) return res.status(400).json({ error: 'Challenge expired — please try again' });

    let verification;
    try {
      const pubKeyBytes = Uint8Array.from(Buffer.from(passkey.public_key, 'base64'));
      const credIdBytes = Uint8Array.from(
        Buffer.from(passkey.credential_id.replace(/-/g, '+').replace(/_/g, '/'), 'base64')
      );
      verification = await verifyAuthenticationResponse({
        response: credential,
        expectedChallenge: ch.challenge,
        expectedOrigin: getOrigin(req),
        expectedRPID: getRpId(req),
        authenticator: { credentialID: credIdBytes, credentialPublicKey: pubKeyBytes, counter: passkey.counter || 0 },
        requireUserVerification: false,
      });
    } catch(e) { return res.status(401).json({ error: 'Verification failed: ' + e.message }); }

    if (!verification.verified) return res.status(401).json({ error: 'Authentication not verified' });

    await supabase.from('passkeys').update({ counter: verification.authenticationInfo.newCounter }).eq('id', passkey.id);
    await supabase.from('webauthn_challenges').delete().eq('id', ch.id);

    const u = passkey.users;
    const token = await signToken(u.id, u.username, u.role);
    return res.status(200).json({ token, username: u.username, displayName: u.display_name || u.username, role: u.role, userId: u.id });
  }

  return res.status(400).json({ error: 'Unknown action' });
}

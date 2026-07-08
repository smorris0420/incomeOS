import { SignJWT, jwtVerify } from 'jose';

const secret = () => new TextEncoder().encode(process.env.JWT_SECRET);

// Sign a JWT containing userId and role, valid 7 days
export async function signToken(userId, username, role) {
  return new SignJWT({ userId, username, role })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime('7d')
    .sign(secret());
}

// Verify token from Authorization header.
// Returns the decoded payload { userId, username, role } or null.
export async function verifyToken(req) {
  const auth = req.headers['authorization'] || '';
  if (!auth.startsWith('Bearer ')) return null;
  const token = auth.slice(7);
  try {
    const { payload } = await jwtVerify(token, secret());
    return payload;
  } catch {
    return null;
  }
}

// Middleware for any authenticated route.
// Returns the payload if valid, or ends the response with 401.
export async function requireAuth(req, res) {
  if (req.method === 'OPTIONS') { res.status(200).end(); return null; }
  const payload = await verifyToken(req);
  if (!payload) {
    res.status(401).json({ error: 'Unauthorized' });
    return null;
  }
  return payload; // { userId, username, role }
}

// Middleware that also requires role === 'admin'.
export async function requireAdmin(req, res) {
  const payload = await requireAuth(req, res);
  if (!payload) return null;
  if (payload.role !== 'admin') {
    res.status(403).json({ error: 'Admin only' });
    return null;
  }
  return payload;
}

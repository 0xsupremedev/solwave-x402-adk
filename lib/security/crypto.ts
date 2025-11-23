import crypto from 'crypto';

const DEFAULT_NONCE_BYTES = 32;

export function randomNonce(bytes: number = DEFAULT_NONCE_BYTES): string {
  return crypto.randomBytes(bytes).toString('hex');
}

export function sha256(input: string): string {
  return crypto.createHash('sha256').update(input).digest('hex');
}

export function hashFingerprint(value?: string | null): string | null {
  if (!value) return null;
  return sha256(value);
}

export function constantTimeCompare(a: string, b: string): boolean {
  const bufferA = Buffer.from(a);
  const bufferB = Buffer.from(b);

  if (bufferA.length !== bufferB.length) {
    return false;
  }

  return crypto.timingSafeEqual(bufferA, bufferB);
}

export function signJwt(payload: Record<string, any>, secret: string, expiresInSeconds: number) {
  const header = {
    alg: 'HS256',
    typ: 'JWT',
  };

  const encode = (obj: Record<string, any>) =>
    Buffer.from(JSON.stringify(obj)).toString('base64url');

  const unsigned = `${encode(header)}.${encode({
    ...payload,
    exp: Math.floor(Date.now() / 1000) + expiresInSeconds,
    iat: Math.floor(Date.now() / 1000),
  })}`;

  const signature = crypto
    .createHmac('sha256', secret)
    .update(unsigned)
    .digest('base64url');

  return `${unsigned}.${signature}`;
}

export function verifyJwt<T = Record<string, any>>(token: string, secret: string): T | null {
  const [headerB64, payloadB64, signature] = token.split('.');
  if (!headerB64 || !payloadB64 || !signature) {
    return null;
  }

  const expectedSignature = crypto
    .createHmac('sha256', secret)
    .update(`${headerB64}.${payloadB64}`)
    .digest('base64url');

  if (!constantTimeCompare(signature, expectedSignature)) {
    return null;
  }

  const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8')) as T & {
    exp?: number;
  };

  if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
    return null;
  }

  return payload;
}


import type { IncomingMessage } from "node:http";
import * as jose from "jose";
import { createTenantContext, TenantContextError, type TenantContext } from "./tenant-context.js";

export type JwtAuthConfig = {
  /** JWKS endpoint URL for fetching public keys (e.g. https://auth.example.com/.well-known/jwks.json) */
  readonly jwksUrl?: string;
  /** Symmetric secret for HS256 tokens (development/testing only) */
  readonly secret?: string;
  /** Expected JWT audience claim */
  readonly audience?: string;
  /** Expected JWT issuer claim */
  readonly issuer?: string;
  /** JWT algorithm (default: RS256 for JWKS, HS256 for secret) */
  readonly algorithm?: string;
};

export type JwtAuthResult =
  | { ok: true; tenant: TenantContext; claims: jose.JWTPayload }
  | { ok: false; error: string };

/**
 * Extract and verify a JWT token from an HTTP request's Authorization header.
 * Returns a TenantContext with user_id and persona_id from the token claims.
 */
export async function extractTenantFromRequest(
  req: IncomingMessage,
  config: JwtAuthConfig,
): Promise<JwtAuthResult> {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return { ok: false, error: "missing Authorization header" };
  }

  const parts = authHeader.split(" ");
  if (parts.length !== 2 || parts[0]?.toLowerCase() !== "bearer") {
    return { ok: false, error: "invalid Authorization header format (expected: Bearer <token>)" };
  }

  const token = parts[1];
  if (!token) {
    return { ok: false, error: "empty JWT token" };
  }

  try {
    let payload: jose.JWTPayload;

    if (config.jwksUrl) {
      const jwks = jose.createRemoteJWKSet(new URL(config.jwksUrl));
      const verifyOptions: jose.JWTVerifyOptions = {};
      if (config.audience) {
        verifyOptions.audience = config.audience;
      }
      if (config.issuer) {
        verifyOptions.issuer = config.issuer;
      }
      const result = await jose.jwtVerify(token, jwks, verifyOptions);
      payload = result.payload;
    } else if (config.secret) {
      const secret = new TextEncoder().encode(config.secret);
      const verifyOptions: jose.JWTVerifyOptions = {};
      if (config.audience) {
        verifyOptions.audience = config.audience;
      }
      if (config.issuer) {
        verifyOptions.issuer = config.issuer;
      }
      const result = await jose.jwtVerify(token, secret, verifyOptions);
      payload = result.payload;
    } else {
      return { ok: false, error: "JWT auth not configured: no secret or JWKS URL" };
    }

    const userId = payload.user_id as string | undefined;
    const personaId = payload.persona_id as string | undefined;

    const tenant = createTenantContext(userId, personaId);
    return { ok: true, tenant, claims: payload };
  } catch (err) {
    if (err instanceof TenantContextError) {
      return { ok: false, error: err.message };
    }
    if (err instanceof jose.errors.JWTExpired) {
      return { ok: false, error: "JWT token expired" };
    }
    if (err instanceof jose.errors.JWTClaimValidationFailed) {
      return { ok: false, error: `JWT claim validation failed: ${err.message}` };
    }
    const message = err instanceof Error ? err.message : String(err);
    return { ok: false, error: `JWT verification failed: ${message}` };
  }
}

/**
 * Create a JWT token for testing purposes.
 * Only use this in tests — production tokens should come from an external auth provider.
 */
export async function createTestToken(
  claims: { user_id: string; persona_id: string; [key: string]: unknown },
  secret: string,
  options?: { expiresIn?: string },
): Promise<string> {
  const encoder = new TextEncoder();
  const jwt = new jose.SignJWT(claims).setProtectedHeader({ alg: "HS256" }).setIssuedAt();

  if (options?.expiresIn) {
    jwt.setExpirationTime(options.expiresIn);
  }

  return jwt.sign(encoder.encode(secret));
}

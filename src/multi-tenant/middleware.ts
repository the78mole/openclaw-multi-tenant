import type { IncomingMessage, ServerResponse } from "node:http";
import { extractTenantFromRequest, type JwtAuthConfig } from "./jwt-auth.js";
import type { TenantContext } from "./tenant-context.js";

// WeakMap to associate tenant context with request objects without modifying them.
const requestTenantMap = new WeakMap<IncomingMessage, TenantContext>();

/**
 * Store the tenant context for a request.
 */
export function setRequestTenant(req: IncomingMessage, tenant: TenantContext): void {
  requestTenantMap.set(req, tenant);
}

/**
 * Retrieve the tenant context for a request.
 * Returns undefined if the request has not been authenticated.
 */
export function getRequestTenant(req: IncomingMessage): TenantContext | undefined {
  return requestTenantMap.get(req);
}

/**
 * Retrieve the tenant context for a request, throwing if not present.
 * Use this in handlers that require tenant authentication.
 */
export function requireRequestTenant(req: IncomingMessage): TenantContext {
  const tenant = requestTenantMap.get(req);
  if (!tenant) {
    throw new Error(
      "tenant context required but not found on request - ensure JWT auth middleware is active",
    );
  }
  return tenant;
}

/**
 * HTTP middleware that extracts tenant context from JWT tokens.
 * Sends 401 if the token is missing or invalid.
 *
 * @returns true if the request was rejected (response already sent), false if tenant was set.
 */
export async function tenantAuthMiddleware(
  req: IncomingMessage,
  res: ServerResponse,
  config: JwtAuthConfig,
): Promise<boolean> {
  const result = await extractTenantFromRequest(req, config);

  if (!result.ok) {
    res.writeHead(401, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: result.error }));
    return true;
  }

  setRequestTenant(req, result.tenant);
  return false;
}

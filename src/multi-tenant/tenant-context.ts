import path from "node:path";

/**
 * Tenant context extracted from a JWT token.
 * Every API request in multi-tenant mode must carry both user_id and persona_id.
 */
export type TenantContext = {
  readonly userId: string;
  readonly personaId: string;
};

// Regex: only lowercase alphanumeric, hyphens, underscores; 1–64 chars; must start with alphanumeric.
const SAFE_ID_RE = /^[a-z0-9][a-z0-9_-]{0,63}$/;

/**
 * Validate that a tenant identifier is safe for use in filesystem paths and DB queries.
 * Prevents path traversal, shell injection, and other attacks.
 */
export function isSafeTenantId(id: string): boolean {
  if (!id || typeof id !== "string") {
    return false;
  }
  return SAFE_ID_RE.test(id);
}

export class TenantContextError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TenantContextError";
  }
}

/**
 * Create and validate a TenantContext from raw user_id and persona_id values.
 * Throws TenantContextError if either value is missing or unsafe.
 */
export function createTenantContext(
  userId: string | undefined,
  personaId: string | undefined,
): TenantContext {
  if (!userId || typeof userId !== "string" || !userId.trim()) {
    throw new TenantContextError("missing or empty user_id in tenant context");
  }
  if (!personaId || typeof personaId !== "string" || !personaId.trim()) {
    throw new TenantContextError("missing or empty persona_id in tenant context");
  }

  const normalizedUserId = userId.trim().toLowerCase();
  const normalizedPersonaId = personaId.trim().toLowerCase();

  if (!isSafeTenantId(normalizedUserId)) {
    throw new TenantContextError(`unsafe user_id: ${normalizedUserId}`);
  }
  if (!isSafeTenantId(normalizedPersonaId)) {
    throw new TenantContextError(`unsafe persona_id: ${normalizedPersonaId}`);
  }

  return { userId: normalizedUserId, personaId: normalizedPersonaId };
}

/**
 * Resolve the tenant-scoped workspace directory.
 * Path format: {baseDir}/{userId}/{personaId}
 *
 * Includes path traversal protection: the resolved path must be contained
 * within the base directory.
 */
export function resolveTenantWorkspaceDir(baseDir: string, tenant: TenantContext): string {
  const resolved = path.resolve(baseDir, tenant.userId, tenant.personaId);
  const normalizedBase = path.resolve(baseDir);

  // Path traversal protection
  if (!resolved.startsWith(normalizedBase + path.sep) && resolved !== normalizedBase) {
    throw new TenantContextError(
      `path traversal detected: resolved workspace "${resolved}" escapes base "${normalizedBase}"`,
    );
  }

  return resolved;
}

/**
 * Validate that a given absolute path is contained within the tenant workspace.
 * Use this for all file operations to prevent path traversal attacks.
 */
export function assertPathWithinTenantWorkspace(filePath: string, workspaceDir: string): void {
  const resolvedPath = path.resolve(filePath);
  const resolvedWorkspace = path.resolve(workspaceDir);

  if (
    !resolvedPath.startsWith(resolvedWorkspace + path.sep) &&
    resolvedPath !== resolvedWorkspace
  ) {
    throw new TenantContextError(
      `path traversal detected: "${resolvedPath}" is outside tenant workspace "${resolvedWorkspace}"`,
    );
  }
}

/**
 * Build a tenant-scoped session key prefix.
 */
export function buildTenantSessionKeyPrefix(tenant: TenantContext): string {
  return `tenant:${tenant.userId}:${tenant.personaId}`;
}

/**
 * Build a tenant-scoped memory/DB namespace key.
 */
export function buildTenantNamespace(tenant: TenantContext): string {
  return `${tenant.userId}/${tenant.personaId}`;
}

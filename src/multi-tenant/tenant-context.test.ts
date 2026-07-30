import { IncomingMessage, ServerResponse } from "node:http";
import { Socket } from "node:net";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { extractTenantFromRequest, createTestToken, type JwtAuthConfig } from "./jwt-auth.js";
import {
  tenantAuthMiddleware,
  setRequestTenant,
  getRequestTenant,
  requireRequestTenant,
} from "./middleware.js";
import {
  createTenantContext,
  TenantContextError,
  isSafeTenantId,
  resolveTenantWorkspaceDir,
  assertPathWithinTenantWorkspace,
  buildTenantSessionKeyPrefix,
  buildTenantNamespace,
} from "./tenant-context.js";

// ---------------------------------------------------------------------------
// tenant-context.ts tests
// ---------------------------------------------------------------------------

describe("isSafeTenantId", () => {
  it("accepts valid ids", () => {
    expect(isSafeTenantId("alice")).toBe(true);
    expect(isSafeTenantId("user123")).toBe(true);
    expect(isSafeTenantId("my-user")).toBe(true);
    expect(isSafeTenantId("my_user")).toBe(true);
    expect(isSafeTenantId("a")).toBe(true);
    expect(isSafeTenantId("privat")).toBe(true);
    expect(isSafeTenantId("autor")).toBe(true);
    expect(isSafeTenantId("elektro")).toBe(true);
  });

  it("rejects empty or non-string values", () => {
    expect(isSafeTenantId("")).toBe(false);
    expect(isSafeTenantId(null as unknown as string)).toBe(false);
    expect(isSafeTenantId(undefined as unknown as string)).toBe(false);
  });

  it("rejects ids with path traversal characters", () => {
    expect(isSafeTenantId("..")).toBe(false);
    expect(isSafeTenantId("../etc")).toBe(false);
    expect(isSafeTenantId("user/admin")).toBe(false);
    expect(isSafeTenantId("user\\admin")).toBe(false);
    expect(isSafeTenantId("user\0admin")).toBe(false);
  });

  it("rejects ids starting with non-alphanumeric", () => {
    expect(isSafeTenantId("-user")).toBe(false);
    expect(isSafeTenantId("_user")).toBe(false);
    expect(isSafeTenantId(".user")).toBe(false);
  });

  it("rejects ids with special characters", () => {
    expect(isSafeTenantId("user@host")).toBe(false);
    expect(isSafeTenantId("user name")).toBe(false);
    expect(isSafeTenantId("user;drop")).toBe(false);
  });

  it("rejects ids longer than 64 characters", () => {
    const longId = "a" + "b".repeat(64);
    expect(isSafeTenantId(longId)).toBe(false);
    const maxId = "a" + "b".repeat(63);
    expect(isSafeTenantId(maxId)).toBe(true);
  });
});

describe("createTenantContext", () => {
  it("creates valid tenant context", () => {
    const tenant = createTenantContext("alice", "privat");
    expect(tenant.userId).toBe("alice");
    expect(tenant.personaId).toBe("privat");
  });

  it("normalizes to lowercase", () => {
    const tenant = createTenantContext("Alice", "Privat");
    expect(tenant.userId).toBe("alice");
    expect(tenant.personaId).toBe("privat");
  });

  it("trims whitespace", () => {
    const tenant = createTenantContext("  alice  ", "  privat  ");
    expect(tenant.userId).toBe("alice");
    expect(tenant.personaId).toBe("privat");
  });

  it("throws on missing user_id", () => {
    expect(() => createTenantContext(undefined, "privat")).toThrow(TenantContextError);
    expect(() => createTenantContext("", "privat")).toThrow(TenantContextError);
    expect(() => createTenantContext("   ", "privat")).toThrow(TenantContextError);
  });

  it("throws on missing persona_id", () => {
    expect(() => createTenantContext("alice", undefined)).toThrow(TenantContextError);
    expect(() => createTenantContext("alice", "")).toThrow(TenantContextError);
    expect(() => createTenantContext("alice", "   ")).toThrow(TenantContextError);
  });

  it("throws on unsafe user_id", () => {
    expect(() => createTenantContext("../admin", "privat")).toThrow(TenantContextError);
    expect(() => createTenantContext("user/root", "privat")).toThrow(TenantContextError);
  });

  it("throws on unsafe persona_id", () => {
    expect(() => createTenantContext("alice", "../etc")).toThrow(TenantContextError);
    expect(() => createTenantContext("alice", "persona/admin")).toThrow(TenantContextError);
  });
});

describe("resolveTenantWorkspaceDir", () => {
  it("resolves correct workspace path", () => {
    const tenant = createTenantContext("alice", "privat");
    const dir = resolveTenantWorkspaceDir("/workspaces", tenant);
    expect(dir).toBe(path.resolve("/workspaces/alice/privat"));
  });

  it("prevents path traversal in tenant context", () => {
    // Even if someone somehow bypasses createTenantContext validation,
    // resolveTenantWorkspaceDir still checks the resolved path
    const maliciousTenant = { userId: "alice", personaId: "../../etc" } as const;
    expect(() => resolveTenantWorkspaceDir("/workspaces", maliciousTenant)).toThrow(
      TenantContextError,
    );
  });

  it("handles nested base dirs", () => {
    const tenant = createTenantContext("bob", "autor");
    const dir = resolveTenantWorkspaceDir("/data/app/workspaces", tenant);
    expect(dir).toBe(path.resolve("/data/app/workspaces/bob/autor"));
  });
});

describe("assertPathWithinTenantWorkspace", () => {
  it("accepts paths within workspace", () => {
    expect(() =>
      assertPathWithinTenantWorkspace(
        "/workspaces/alice/privat/file.txt",
        "/workspaces/alice/privat",
      ),
    ).not.toThrow();
    expect(() =>
      assertPathWithinTenantWorkspace(
        "/workspaces/alice/privat/sub/dir/file.txt",
        "/workspaces/alice/privat",
      ),
    ).not.toThrow();
  });

  it("rejects paths outside workspace", () => {
    expect(() =>
      assertPathWithinTenantWorkspace(
        "/workspaces/alice/other/file.txt",
        "/workspaces/alice/privat",
      ),
    ).toThrow(TenantContextError);
    expect(() =>
      assertPathWithinTenantWorkspace("/etc/passwd", "/workspaces/alice/privat"),
    ).toThrow(TenantContextError);
  });

  it("rejects traversal attempts", () => {
    expect(() =>
      assertPathWithinTenantWorkspace(
        "/workspaces/alice/privat/../../../etc/passwd",
        "/workspaces/alice/privat",
      ),
    ).toThrow(TenantContextError);
  });
});

describe("buildTenantSessionKeyPrefix", () => {
  it("builds correct prefix", () => {
    const tenant = createTenantContext("alice", "privat");
    expect(buildTenantSessionKeyPrefix(tenant)).toBe("tenant:alice:privat");
  });
});

describe("buildTenantNamespace", () => {
  it("builds correct namespace", () => {
    const tenant = createTenantContext("bob", "elektro");
    expect(buildTenantNamespace(tenant)).toBe("bob/elektro");
  });
});

// ---------------------------------------------------------------------------
// jwt-auth.ts tests
// ---------------------------------------------------------------------------

const TEST_SECRET = "test-secret-key-for-unit-tests-only";

function createMockRequest(headers: Record<string, string>): IncomingMessage {
  const socket = new Socket();
  const req = new IncomingMessage(socket);
  for (const [key, value] of Object.entries(headers)) {
    req.headers[key.toLowerCase()] = value;
  }
  return req;
}

describe("extractTenantFromRequest", () => {
  const config: JwtAuthConfig = { secret: TEST_SECRET };

  it("extracts tenant from valid JWT", async () => {
    const token = await createTestToken({ user_id: "alice", persona_id: "privat" }, TEST_SECRET, {
      expiresIn: "1h",
    });
    const req = createMockRequest({ Authorization: `Bearer ${token}` });
    const result = await extractTenantFromRequest(req, config);

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.tenant.userId).toBe("alice");
      expect(result.tenant.personaId).toBe("privat");
    }
  });

  it("rejects missing Authorization header", async () => {
    const req = createMockRequest({});
    const result = await extractTenantFromRequest(req, config);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain("missing Authorization header");
    }
  });

  it("rejects invalid Authorization format", async () => {
    const req = createMockRequest({ Authorization: "Basic abc" });
    const result = await extractTenantFromRequest(req, config);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain("invalid Authorization header format");
    }
  });

  it("rejects token with missing user_id", async () => {
    // Type assertion needed to test runtime validation with intentionally invalid claims
    const token = await createTestToken(
      { user_id: "", persona_id: "privat" } as Record<string, unknown>,
      TEST_SECRET,
      { expiresIn: "1h" },
    );
    const req = createMockRequest({ Authorization: `Bearer ${token}` });
    const result = await extractTenantFromRequest(req, config);
    expect(result.ok).toBe(false);
  });

  it("rejects token with missing persona_id", async () => {
    // Type assertion needed to test runtime validation with intentionally invalid claims
    const token = await createTestToken(
      { user_id: "alice", persona_id: "" } as Record<string, unknown>,
      TEST_SECRET,
      { expiresIn: "1h" },
    );
    const req = createMockRequest({ Authorization: `Bearer ${token}` });
    const result = await extractTenantFromRequest(req, config);
    expect(result.ok).toBe(false);
  });

  it("rejects token signed with wrong secret", async () => {
    const token = await createTestToken(
      { user_id: "alice", persona_id: "privat" },
      "wrong-secret",
      { expiresIn: "1h" },
    );
    const req = createMockRequest({ Authorization: `Bearer ${token}` });
    const result = await extractTenantFromRequest(req, config);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain("JWT verification failed");
    }
  });

  it("rejects empty bearer token", async () => {
    const req = createMockRequest({ Authorization: "Bearer " });
    const result = await extractTenantFromRequest(req, config);
    expect(result.ok).toBe(false);
  });

  it("returns error when no auth config provided", async () => {
    const token = await createTestToken({ user_id: "alice", persona_id: "privat" }, TEST_SECRET, {
      expiresIn: "1h",
    });
    const req = createMockRequest({ Authorization: `Bearer ${token}` });
    const result = await extractTenantFromRequest(req, {});
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain("not configured");
    }
  });
});

describe("createTestToken", () => {
  it("creates a valid JWT", async () => {
    const token = await createTestToken({ user_id: "alice", persona_id: "privat" }, TEST_SECRET, {
      expiresIn: "1h",
    });
    expect(typeof token).toBe("string");
    expect(token.split(".")).toHaveLength(3);
  });
});

// ---------------------------------------------------------------------------
// middleware.ts tests
// ---------------------------------------------------------------------------

describe("middleware", () => {
  describe("setRequestTenant / getRequestTenant", () => {
    it("stores and retrieves tenant context", () => {
      const req = createMockRequest({});
      const tenant = createTenantContext("alice", "privat");
      setRequestTenant(req, tenant);
      expect(getRequestTenant(req)).toEqual(tenant);
    });

    it("returns undefined for unauthenticated requests", () => {
      const req = createMockRequest({});
      expect(getRequestTenant(req)).toBeUndefined();
    });
  });

  describe("requireRequestTenant", () => {
    it("returns tenant when present", () => {
      const req = createMockRequest({});
      const tenant = createTenantContext("bob", "autor");
      setRequestTenant(req, tenant);
      expect(requireRequestTenant(req)).toEqual(tenant);
    });

    it("throws when tenant is missing", () => {
      const req = createMockRequest({});
      expect(() => requireRequestTenant(req)).toThrow("tenant context required");
    });
  });

  describe("tenantAuthMiddleware", () => {
    const config: JwtAuthConfig = { secret: TEST_SECRET };

    function createMockResponse(): ServerResponse & { _statusCode: number; _body: string } {
      const socket = new Socket();
      const req = new IncomingMessage(socket);
      const res = new ServerResponse(req) as ServerResponse & {
        _statusCode: number;
        _body: string;
      };
      res._statusCode = 200;
      res._body = "";
      const originalWriteHead = res.writeHead.bind(res);
      res.writeHead = ((code: number, ...args: unknown[]) => {
        res._statusCode = code;
        return originalWriteHead(code, ...(args as [Record<string, string>]));
      }) as typeof res.writeHead;
      const originalEnd = res.end.bind(res);
      res.end = ((chunk?: unknown, ...args: unknown[]) => {
        if (typeof chunk === "string") {
          res._body = chunk;
        }
        return originalEnd(chunk, ...(args as [BufferEncoding, () => void]));
      }) as typeof res.end;
      return res;
    }

    it("sets tenant context on valid request", async () => {
      const token = await createTestToken({ user_id: "alice", persona_id: "privat" }, TEST_SECRET, {
        expiresIn: "1h",
      });
      const req = createMockRequest({ Authorization: `Bearer ${token}` });
      const res = createMockResponse();
      const rejected = await tenantAuthMiddleware(req, res, config);

      expect(rejected).toBe(false);
      const tenant = getRequestTenant(req);
      expect(tenant).toBeDefined();
      expect(tenant!.userId).toBe("alice");
      expect(tenant!.personaId).toBe("privat");
    });

    it("rejects request without token", async () => {
      const req = createMockRequest({});
      const res = createMockResponse();
      const rejected = await tenantAuthMiddleware(req, res, config);

      expect(rejected).toBe(true);
      expect(res._statusCode).toBe(401);
    });
  });
});

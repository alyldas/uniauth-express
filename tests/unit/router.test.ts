import { createServer, type Server } from "node:http";
import express from "express";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  AUTHENTICATION_REQUIRED_MESSAGE,
  REQUEST_CANNOT_BE_COMPLETED_MESSAGE,
  createUniAuthExpressRouter,
  type UniAuthExpressService,
} from "../../src/index.js";

const servers: Server[] = [];

afterEach(async () => {
  await Promise.all(
    servers.splice(0).map(
      (server) =>
        new Promise<void>((resolve, reject) => {
          server.close((error) => {
            if (error) {
              reject(error);
              return;
            }

            resolve();
          });
        }),
    ),
  );
});

describe("UniAuth Express router", () => {
  it("uses bearer transport before cookie transport for account routes", async () => {
    const context = vi.fn(({ sessionToken }: { sessionToken: string }) =>
      Promise.resolve({
        session: {
          id: "session-record",
          tokenHash: "hash",
          userId: "user-1",
          status: "active",
          createdAt: new Date("2026-01-01T00:00:00.000Z"),
          expiresAt: new Date("2026-01-02T00:00:00.000Z"),
          lastSeenAt: new Date("2026-01-01T00:00:00.000Z"),
          metadata: {
            providerAccessToken: "provider-token",
          },
        },
        user: {
          id: "user-1",
          status: "active",
          passwordHash: "password-hash",
          createdAt: new Date("2026-01-01T00:00:00.000Z"),
          updatedAt: new Date("2026-01-01T00:00:00.000Z"),
          metadata: {
            internal: true,
          },
        },
        sessionToken,
      }),
    );
    const app = createTestApp({
      auth: createAuthService({ context }),
      session: {
        cookie: {
          decode: (value) => `cookie:${value}`,
        },
      },
    });

    const response = await request(app, "/auth/account/session", {
      headers: {
        authorization: "Bearer bearer-token",
        cookie: "session=cookie-token",
      },
    });

    expect(response.status).toBe(200);
    await expectSafeSessionResponse(response);
    expect(context).toHaveBeenCalledWith({ sessionToken: "bearer-token" });
  });

  it("writes a session cookie for public password sign-in when cookie transport is enabled", async () => {
    const signIn = vi.fn(() =>
      Promise.resolve({
        user: { id: "user-1" },
        identity: { id: "identity-1" },
        session: { id: "session-record" },
        sessionToken: "new-session-token",
        isNewUser: false,
        isNewIdentity: false,
      }),
    );
    const app = createTestApp({
      auth: createAuthService({ signIn }),
      session: {
        cookie: {
          encode: (sessionToken) => `sealed:${sessionToken}`,
          options: {
            httpOnly: true,
            sameSite: "lax",
          },
        },
      },
    });

    const response = await request(app, "/auth/password/sign-in", {
      method: "POST",
      body: {
        email: "demo@example.com",
        password: "demo-password",
      },
    });

    expect(response.status).toBe(200);
    expect(response.headers.get("set-cookie")).toContain(
      "session=sealed%3Anew-session-token",
    );
    expect(signIn).toHaveBeenCalledWith({
      email: "demo@example.com",
      password: "demo-password",
      now: undefined,
      sessionExpiresAt: undefined,
      metadata: undefined,
    });
  });

  it("uses secure cookie defaults when cookie transport is enabled without options", async () => {
    const app = createTestApp({
      auth: createAuthService({
        signIn: vi.fn(() =>
          Promise.resolve({
            user: { id: "user-1" },
            identity: { id: "identity-1" },
            session: { id: "session-record" },
            sessionToken: "new-session-token",
            isNewUser: false,
            isNewIdentity: false,
          }),
        ),
      }),
      session: {
        cookie: {},
      },
    });

    const response = await request(app, "/auth/password/sign-in", {
      method: "POST",
      body: {
        email: "demo@example.com",
        password: "demo-password",
      },
    });

    const setCookie = response.headers.get("set-cookie");

    expect(response.status).toBe(200);
    expect(setCookie).toContain("session=new-session-token");
    expect(setCookie).toContain("HttpOnly");
    expect(setCookie).toContain("Path=/");
    expect(setCookie).toContain("SameSite=Lax");
  });

  it("maps validation failures to neutral public request errors", async () => {
    const app = createTestApp({
      auth: createAuthService(),
    });

    const response = await request(app, "/auth/password/sign-in", {
      method: "POST",
      body: {
        email: "",
        password: "demo-password",
      },
    });

    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({
      error: REQUEST_CANNOT_BE_COMPLETED_MESSAGE,
    });
  });

  it("returns 401 when a protected account route has no bearer token or cookie", async () => {
    const app = createTestApp({
      auth: createAuthService(),
    });

    const response = await request(app, "/auth/account/session");

    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({
      error: AUTHENTICATION_REQUIRED_MESSAGE,
    });
  });

  it("returns the current account session with a safe cookie transport response", async () => {
    const context = vi.fn(({ sessionToken }: { sessionToken: string }) =>
      Promise.resolve({
        session: {
          id: "cookie-session",
          tokenHash: "cookie-hash",
          userId: "user-1",
          status: "active",
          createdAt: new Date("2026-01-01T00:00:00.000Z"),
          expiresAt: new Date("2026-01-02T00:00:00.000Z"),
          metadata: {
            providerRefreshToken: "provider-refresh-token",
          },
        },
        user: {
          id: "user-1",
          email: "demo@example.com",
          status: "active",
          secretHash: "secret-hash",
          createdAt: new Date("2026-01-01T00:00:00.000Z"),
          updatedAt: new Date("2026-01-01T00:00:00.000Z"),
        },
        sessionToken,
      }),
    );
    const app = createTestApp({
      auth: createAuthService({ context }),
      session: {
        cookie: {
          decode: (value) => `cookie:${value}`,
        },
      },
    });

    const response = await request(app, "/auth/account/session", {
      headers: {
        cookie: "session=cookie-token",
      },
    });

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      session: {
        id: "cookie-session",
        status: "active",
        createdAt: "2026-01-01T00:00:00.000Z",
        expiresAt: "2026-01-02T00:00:00.000Z",
      },
      user: {
        id: "user-1",
        email: "demo@example.com",
        createdAt: "2026-01-01T00:00:00.000Z",
        updatedAt: "2026-01-01T00:00:00.000Z",
      },
    });
    expect(context).toHaveBeenCalledWith({
      sessionToken: "cookie:cookie-token",
    });
  });

  it("refreshes the current account session context", async () => {
    const context = vi.fn(
      ({
        sessionToken,
        touch,
      }: {
        readonly sessionToken: string;
        readonly touch?: boolean;
      }) =>
        Promise.resolve({
          session: {
            id: touch ? "refreshed-session" : "session-record",
            tokenHash: "hash",
            userId: "user-1",
            status: "active",
            createdAt: new Date("2026-01-01T00:00:00.000Z"),
            expiresAt: new Date("2026-01-02T00:00:00.000Z"),
            lastSeenAt: new Date("2026-01-01T00:00:00.000Z"),
            metadata: {
              providerPayload: { accessToken: "provider-token" },
            },
          },
          user: {
            id: "user-1",
            status: "active",
            passwordHash: "password-hash",
            createdAt: new Date("2026-01-01T00:00:00.000Z"),
            updatedAt: new Date("2026-01-01T00:00:00.000Z"),
            metadata: {
              internal: true,
            },
          },
          sessionToken,
        }),
    );
    const app = createTestApp({
      auth: createAuthService({ context }),
    });

    const response = await request(app, "/auth/account/session/refresh", {
      method: "POST",
      headers: {
        authorization: "Bearer bearer-token",
      },
    });

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      session: {
        id: "refreshed-session",
        status: "active",
        createdAt: "2026-01-01T00:00:00.000Z",
        expiresAt: "2026-01-02T00:00:00.000Z",
        lastSeenAt: "2026-01-01T00:00:00.000Z",
      },
      user: {
        id: "user-1",
        createdAt: "2026-01-01T00:00:00.000Z",
        updatedAt: "2026-01-01T00:00:00.000Z",
      },
    });
    expect(context).toHaveBeenNthCalledWith(1, {
      sessionToken: "bearer-token",
    });
    expect(context).toHaveBeenNthCalledWith(2, {
      sessionToken: "bearer-token",
      touch: true,
    });
  });

  it("revokes the current account session and clears the cookie", async () => {
    const context = vi.fn(({ sessionToken }: { sessionToken: string }) =>
      Promise.resolve({
        session: {
          id: "session-record",
          tokenHash: "hash",
          userId: "user-1",
          status: "active",
          createdAt: new Date("2026-01-01T00:00:00.000Z"),
          expiresAt: new Date("2026-01-02T00:00:00.000Z"),
        },
        user: {
          id: "user-1",
          createdAt: new Date("2026-01-01T00:00:00.000Z"),
          updatedAt: new Date("2026-01-01T00:00:00.000Z"),
        },
        sessionToken,
      }),
    );
    const revokeCurrent = vi.fn(() => Promise.resolve());
    const app = createTestApp({
      auth: createAuthService({ context, revokeCurrent }),
      session: {
        cookie: {},
      },
    });

    const response = await request(
      app,
      "/auth/account/sessions/revoke-current",
      {
        method: "POST",
        body: {},
        headers: {
          authorization: "Bearer bearer-token",
        },
      },
    );

    expect(response.status).toBe(204);
    expect(response.headers.get("set-cookie")).toContain("session=;");
    expect(revokeCurrent).toHaveBeenCalledWith({
      sessionToken: "bearer-token",
      now: undefined,
    });
  });

  it("keeps admin routes closed unless an application guard is supplied", async () => {
    const app = createTestApp({
      auth: createAuthService(),
    });

    const response = await request(app, "/auth/admin/users/user-1");

    expect(response.status).toBe(403);
  });
});

function createTestApp(
  options: Parameters<typeof createUniAuthExpressRouter>[0],
): express.Express {
  const app = express();
  app.use(express.json());
  app.use("/auth", createUniAuthExpressRouter(options));

  return app;
}

async function expectSafeSessionResponse(response: Response): Promise<void> {
  expect(await response.json()).toEqual({
    session: {
      id: "session-record",
      status: "active",
      createdAt: "2026-01-01T00:00:00.000Z",
      expiresAt: "2026-01-02T00:00:00.000Z",
      lastSeenAt: "2026-01-01T00:00:00.000Z",
    },
    user: {
      id: "user-1",
      createdAt: "2026-01-01T00:00:00.000Z",
      updatedAt: "2026-01-01T00:00:00.000Z",
    },
  });
}

async function request(
  app: express.Express,
  path: string,
  init: Omit<RequestInit, "body"> & { readonly body?: unknown } = {},
): Promise<Response> {
  const server = createServer(app);
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();

  if (!address || typeof address === "string") {
    throw new Error("Expected TCP server address.");
  }

  const headers = new Headers(init.headers);

  if (init.body !== undefined) {
    headers.set("content-type", "application/json");
  }

  return fetch(`http://127.0.0.1:${String(address.port)}${path}`, {
    ...init,
    body: init.body === undefined ? undefined : JSON.stringify(init.body),
    headers,
  });
}

function createAuthService(
  overrides: {
    readonly context?: unknown;
    readonly revokeCurrent?: unknown;
    readonly signIn?: unknown;
  } = {},
): UniAuthExpressService {
  return {
    public: {
      password: {
        signIn: overrides.signIn ?? vi.fn(),
      },
    },
    account: {
      sessions: {
        revokeCurrent: overrides.revokeCurrent ?? vi.fn(),
      },
    },
    admin: {
      sessions: {
        context: overrides.context ?? vi.fn(),
      },
      users: {
        get: vi.fn(),
      },
    },
  } as unknown as UniAuthExpressService;
}

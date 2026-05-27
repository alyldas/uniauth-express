import type { CookieOptions, Request, Response } from "express";
import type {
  UniAuthSessionCookieOptions,
  UniAuthSessionTransportOptions,
} from "./types.js";

const DEFAULT_SESSION_COOKIE_NAME = "session";
const DEFAULT_SESSION_COOKIE_OPTIONS: CookieOptions = {
  httpOnly: true,
  path: "/",
  sameSite: "lax",
};

export function readBearerToken(
  header: string | undefined,
): string | undefined {
  if (!header) {
    return undefined;
  }

  const parts = header.trim().split(/\s+/);

  if (parts.length !== 2) {
    return undefined;
  }

  const [scheme, value] = parts;

  return scheme?.toLowerCase() === "bearer" && value ? value : undefined;
}

export function readCookieHeaderToken(
  header: string | undefined,
  name: string,
): string | undefined {
  if (!header) {
    return undefined;
  }

  for (const part of header.split(";")) {
    const [rawName, ...rest] = part.split("=");

    if (rawName?.trim() !== name) {
      continue;
    }

    const value = rest.join("=").trim();

    if (!value) {
      return undefined;
    }

    try {
      return decodeURIComponent(value);
    } catch {
      return undefined;
    }
  }

  return undefined;
}

export async function readSessionToken(
  request: Request,
  options: UniAuthSessionTransportOptions = {},
): Promise<string | undefined> {
  if (options.bearer !== false) {
    const bearerToken = readBearerToken(request.headers.authorization);

    if (bearerToken) {
      return bearerToken;
    }
  }

  const cookie = normalizeCookieOptions(options.cookie);

  if (!cookie) {
    return undefined;
  }

  const rawCookie = readCookieHeaderToken(request.headers.cookie, cookie.name);

  if (!rawCookie) {
    return undefined;
  }

  return cookie.decode ? await cookie.decode(rawCookie) : rawCookie;
}

export async function writeSessionCookie(
  response: Response,
  sessionToken: string,
  options: UniAuthSessionTransportOptions = {},
): Promise<void> {
  const cookie = normalizeCookieOptions(options.cookie);

  if (!cookie) {
    return;
  }

  const value = cookie.encode
    ? await cookie.encode(sessionToken)
    : sessionToken;
  response.cookie(cookie.name, value, cookie.options ?? {});
}

export function clearSessionCookie(
  response: Response,
  options: UniAuthSessionTransportOptions = {},
): void {
  const cookie = normalizeCookieOptions(options.cookie);

  if (!cookie) {
    return;
  }

  response.clearCookie(cookie.name, cookie.options ?? {});
}

function normalizeCookieOptions(
  input: UniAuthSessionTransportOptions["cookie"],
):
  | (Required<Pick<UniAuthSessionCookieOptions, "name">> &
      Omit<UniAuthSessionCookieOptions, "name">)
  | undefined {
  if (input === false) {
    return undefined;
  }

  return {
    ...input,
    name: input?.name ?? DEFAULT_SESSION_COOKIE_NAME,
    options: {
      ...DEFAULT_SESSION_COOKIE_OPTIONS,
      ...(input?.options ?? {}),
    },
  };
}

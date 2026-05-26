import type { NextFunction, Request, RequestHandler, Response } from "express";
import {
  AUTHENTICATION_REQUIRED_MESSAGE,
  FORBIDDEN_MESSAGE,
  isSessionContextError,
} from "./errors.js";
import { readSessionToken } from "./transport.js";
import type {
  UniAuthExpressService,
  UniAuthSessionTransportOptions,
} from "./types.js";

export function createUniAuthSessionMiddleware(
  auth: UniAuthExpressService,
  options: UniAuthSessionTransportOptions = {},
): RequestHandler {
  return async (
    request: Request,
    response: Response,
    next: NextFunction,
  ): Promise<void> => {
    const sessionToken = await readSessionToken(request, options);

    if (!sessionToken) {
      next();
      return;
    }

    try {
      const { session, user } = await auth.admin.sessions.context({
        sessionToken,
        ...(options.touch !== undefined ? { touch: options.touch } : {}),
      });

      request.auth = {
        sessionToken,
        session,
        user,
        userId: session.userId,
      };
      next();
    } catch (error) {
      if (isSessionContextError(error)) {
        response.status(401).json({ error: AUTHENTICATION_REQUIRED_MESSAGE });
        return;
      }

      next(error);
    }
  };
}

export function requireUniAuthSession(
  request: Request,
  response: Response,
  next: NextFunction,
): void {
  if (request.auth?.session.status !== "active") {
    response.status(401).json({ error: AUTHENTICATION_REQUIRED_MESSAGE });
    return;
  }

  next();
}

export function rejectMissingAdminGuard(
  _request: Request,
  response: Response,
  _next: NextFunction,
): void {
  response.status(403).json({ error: FORBIDDEN_MESSAGE });
}

export function asyncHandler(handler: RequestHandler): RequestHandler {
  return (request, response, next): void => {
    Promise.resolve(handler(request, response, next)).catch(next);
  };
}

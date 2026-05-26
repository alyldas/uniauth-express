import type { ErrorRequestHandler, Request, Response } from "express";
import { RequestValidationError } from "./validation.js";
import type { UniAuthErrorMappingOptions } from "./types.js";

export const AUTHENTICATION_REQUIRED_MESSAGE = "Authentication required.";
export const FORBIDDEN_MESSAGE = "Forbidden.";
export const INTERNAL_SERVER_ERROR_MESSAGE = "Internal server error.";
export const REQUEST_CANNOT_BE_COMPLETED_MESSAGE =
  "Request cannot be completed.";
export const TOO_MANY_AUTH_ATTEMPTS_MESSAGE = "Too many auth attempts.";

const UniAuthErrorCode = {
  InvalidCredentials: "invalid_credentials",
  InvalidInput: "invalid_input",
  PolicyDenied: "policy_denied",
  RateLimited: "rate_limited",
  ReAuthRequired: "re_auth_required",
  SessionNotFound: "session_not_found",
  VerificationConsumed: "verification_consumed",
  VerificationExpired: "verification_expired",
  VerificationInvalidSecret: "verification_invalid_secret",
  VerificationNotFound: "verification_not_found",
} as const;

type UniAuthErrorCodeType =
  (typeof UniAuthErrorCode)[keyof typeof UniAuthErrorCode];

interface UniAuthErrorLike {
  readonly code: UniAuthErrorCodeType;
  readonly message: string;
}

const neutralErrorCodes = new Set<UniAuthErrorCodeType>([
  UniAuthErrorCode.InvalidCredentials,
  UniAuthErrorCode.InvalidInput,
  UniAuthErrorCode.VerificationNotFound,
  UniAuthErrorCode.VerificationExpired,
  UniAuthErrorCode.VerificationConsumed,
  UniAuthErrorCode.VerificationInvalidSecret,
]);

export function createUniAuthErrorHandler(
  options: UniAuthErrorMappingOptions = {},
): ErrorRequestHandler {
  return (error: unknown, request: Request, response: Response, next): void => {
    void request;

    if (response.headersSent) {
      next(error);
      return;
    }

    if (
      isRequestSyntaxError(error) ||
      error instanceof RequestValidationError
    ) {
      response.status(400).json({ error: REQUEST_CANNOT_BE_COMPLETED_MESSAGE });
      return;
    }

    if (!isUniAuthErrorLike(error)) {
      response.status(500).json({
        error:
          options.exposeInternalErrors && error instanceof Error
            ? error.message
            : INTERNAL_SERVER_ERROR_MESSAGE,
      });
      return;
    }

    if (error.code === UniAuthErrorCode.RateLimited) {
      response.status(429).json({ error: TOO_MANY_AUTH_ATTEMPTS_MESSAGE });
      return;
    }

    if (error.code === UniAuthErrorCode.SessionNotFound) {
      response.status(401).json({ error: AUTHENTICATION_REQUIRED_MESSAGE });
      return;
    }

    if (
      error.code === UniAuthErrorCode.ReAuthRequired ||
      error.code === UniAuthErrorCode.PolicyDenied
    ) {
      response.status(403).json({ error: error.message });
      return;
    }

    response.status(400).json({
      error: neutralErrorCodes.has(error.code)
        ? REQUEST_CANNOT_BE_COMPLETED_MESSAGE
        : error.message,
    });
  };
}

export function isSessionContextError(error: unknown): boolean {
  return (
    isUniAuthErrorLike(error) &&
    (error.code === UniAuthErrorCode.InvalidInput ||
      error.code === UniAuthErrorCode.SessionNotFound)
  );
}

function isUniAuthErrorLike(error: unknown): error is UniAuthErrorLike {
  if (!(error instanceof Error) || !("code" in error)) {
    return false;
  }

  const codes: readonly string[] = Object.values(UniAuthErrorCode);

  return typeof error.code === "string" && codes.includes(error.code);
}

function isRequestSyntaxError(error: unknown): boolean {
  if (!(error instanceof SyntaxError)) {
    return false;
  }

  const candidate = error as SyntaxError & { status?: unknown; body?: unknown };

  return candidate.status === 400 && "body" in candidate;
}

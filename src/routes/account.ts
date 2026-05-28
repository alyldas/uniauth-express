import type {
  ResolvedSessionContext,
  IdentityId,
  SessionId,
  VerificationId,
} from "@alyldas/uniauth-core";
import {
  toAccountSecuritySessionView,
  toAccountSecurityUserView,
} from "@alyldas/uniauth-core";
import { Router } from "express";
import { asyncHandler, requireUniAuthSession } from "../middleware.js";
import { clearSessionCookie } from "../transport.js";
import type { UniAuthExpressOptions } from "../types.js";
import {
  readAuthPolicyAction,
  readBody,
  readOptionalCursor,
  readOptionalDate,
  readOptionalFields,
  readOptionalMetadata,
  readOptionalNumber,
  readOptionalReAuthMarker,
  readOtpChannel,
  readRequiredString,
} from "../validation.js";

export function createUniAuthAccountRouter(
  options: UniAuthExpressOptions,
): Router {
  const router = Router();
  const csrf = options.csrf;

  router.use(requireUniAuthSession);

  router.get("/session", (request, response) => {
    response.status(200).json(toAccountSessionResponse(request.auth!));
  });

  router.post(
    "/session/refresh",
    ...(csrf ? [csrf] : []),
    asyncHandler(async (request, response) => {
      const result = await options.auth.admin.sessions.context({
        sessionToken: request.auth!.sessionToken,
        touch: true,
      });

      response.status(200).json(toAccountSessionResponse(result));
    }),
  );

  router.get(
    "/security",
    asyncHandler(async (request, response) => {
      const result = await options.auth.account.security.snapshot({
        sessionToken: request.auth!.sessionToken,
        touch: readQueryBoolean(request.query.touch),
      });

      response.status(200).json(result);
    }),
  );

  router.get(
    "/inspection",
    asyncHandler(async (request, response) => {
      const result = await options.auth.account.inspection.snapshot({
        sessionToken: request.auth!.sessionToken,
        touch: readQueryBoolean(request.query.touch),
        auditLimit: readQueryNumber(request.query.auditLimit),
      });

      response.status(200).json(result);
    }),
  );

  router.get(
    "/closure-export",
    asyncHandler(async (request, response) => {
      const result = await options.auth.account.inspection.closureExport({
        sessionToken: request.auth!.sessionToken,
        touch: readQueryBoolean(request.query.touch),
        auditLimit: readQueryNumber(request.query.auditLimit),
      });

      response.status(200).json(result);
    }),
  );

  router.post(
    "/inspection/audit",
    asyncHandler(async (request, response) => {
      const body = readBody(request.body);
      const result = await options.auth.account.inspection.auditPage({
        sessionToken: request.auth!.sessionToken,
        ...readOptionalFields(body, ["identityId", "sessionId", "type"]),
        before: readOptionalCursor(body, "before"),
        after: readOptionalCursor(body, "after"),
        limit: readOptionalNumber(body, "limit"),
      });

      response.status(200).json(result);
    }),
  );

  router.patch(
    "/profile",
    ...(csrf ? [csrf] : []),
    asyncHandler(async (request, response) => {
      const body = readBody(request.body);
      const result = await options.auth.account.profile.update({
        sessionToken: request.auth!.sessionToken,
        displayName: readOptionalStringOrNull(body, "displayName"),
        reAuthenticatedAt: readOptionalReAuthMarker(body),
        now: readOptionalDate(body, "now"),
        metadata: readOptionalMetadata(body),
      });

      response.status(200).json(result);
    }),
  );

  router.post(
    "/contact/start",
    ...(csrf ? [csrf] : []),
    asyncHandler(async (request, response) => {
      const body = readBody(request.body);
      const result = await options.auth.account.contact.start({
        sessionToken: request.auth!.sessionToken,
        channel: readOtpChannel(body),
        target: readRequiredString(body, "target"),
        secret: readOptionalStringOrNull(body, "secret"),
        ttlSeconds: readOptionalNumber(body, "ttlSeconds"),
        reAuthenticatedAt: readOptionalReAuthMarker(body),
        now: readOptionalDate(body, "now"),
        metadata: readOptionalMetadata(body),
      });

      response.status(202).json(result);
    }),
  );

  router.post(
    "/contact/resend",
    ...(csrf ? [csrf] : []),
    asyncHandler(async (request, response) => {
      const body = readBody(request.body);
      const result = await options.auth.account.contact.resend({
        sessionToken: request.auth!.sessionToken,
        verificationId: readRequiredString(
          body,
          "verificationId",
        ) as VerificationId,
        secret: readOptionalStringOrNull(body, "secret"),
        ttlSeconds: readOptionalNumber(body, "ttlSeconds"),
        now: readOptionalDate(body, "now"),
        metadata: readOptionalMetadata(body),
      });

      response.status(202).json(result);
    }),
  );

  router.post(
    "/contact/cancel",
    ...(csrf ? [csrf] : []),
    asyncHandler(async (request, response) => {
      const body = readBody(request.body);
      const result = await options.auth.account.contact.cancel({
        sessionToken: request.auth!.sessionToken,
        verificationId: readRequiredString(
          body,
          "verificationId",
        ) as VerificationId,
        now: readOptionalDate(body, "now"),
        metadata: readOptionalMetadata(body),
      });

      response.status(200).json(result);
    }),
  );

  router.post(
    "/contact/finish",
    ...(csrf ? [csrf] : []),
    asyncHandler(async (request, response) => {
      const body = readBody(request.body);
      const result = await options.auth.account.contact.finish({
        sessionToken: request.auth!.sessionToken,
        verificationId: readRequiredString(
          body,
          "verificationId",
        ) as VerificationId,
        secret: readRequiredString(body, "secret"),
        now: readOptionalDate(body, "now"),
        metadata: readOptionalMetadata(body),
      });

      response.status(200).json(result);
    }),
  );

  router.post(
    "/password/set",
    ...(csrf ? [csrf] : []),
    asyncHandler(async (request, response) => {
      const body = readBody(request.body);
      const result = await options.auth.account.password.set({
        sessionToken: request.auth!.sessionToken,
        password: readRequiredString(body, "password"),
        reAuthenticatedAt: readOptionalReAuthMarker(body),
        now: readOptionalDate(body, "now"),
        metadata: readOptionalMetadata(body),
      });

      response.status(200).json(result);
    }),
  );

  router.post(
    "/password/confirm",
    ...(csrf ? [csrf] : []),
    asyncHandler(async (request, response) => {
      const body = readBody(request.body);
      const result = await options.auth.account.password.confirm({
        sessionToken: request.auth!.sessionToken,
        currentPassword: readRequiredString(body, "currentPassword"),
        now: readOptionalDate(body, "now"),
      });

      response.status(200).json(result);
    }),
  );

  router.post(
    "/password/change",
    ...(csrf ? [csrf] : []),
    asyncHandler(async (request, response) => {
      const body = readBody(request.body);
      const result = await options.auth.account.password.change({
        sessionToken: request.auth!.sessionToken,
        currentPassword: readRequiredString(body, "currentPassword"),
        newPassword: readRequiredString(body, "newPassword"),
        reAuthenticatedAt: readOptionalReAuthMarker(body),
        now: readOptionalDate(body, "now"),
        metadata: readOptionalMetadata(body),
      });

      response.status(200).json(result);
    }),
  );

  router.post(
    "/re-auth/status",
    asyncHandler(async (request, response) => {
      const body = readBody(request.body);
      const result = await options.auth.account.reAuth.status({
        sessionToken: request.auth!.sessionToken,
        action: readAuthPolicyAction(body),
        reAuthenticatedAt: readOptionalReAuthMarker(body),
        now: readOptionalDate(body, "now"),
      });

      response.status(200).json(result);
    }),
  );

  router.post(
    "/re-auth/assert",
    asyncHandler(async (request, response) => {
      const body = readBody(request.body);
      const result = await options.auth.account.reAuth.assert({
        sessionToken: request.auth!.sessionToken,
        action: readAuthPolicyAction(body),
        reAuthenticatedAt: readOptionalReAuthMarker(body),
        now: readOptionalDate(body, "now"),
      });

      response.status(200).json(result);
    }),
  );

  router.post(
    "/re-auth/otp/start",
    ...(csrf ? [csrf] : []),
    asyncHandler(async (request, response) => {
      const body = readBody(request.body);
      const result = await options.auth.account.reAuth.startOtp({
        sessionToken: request.auth!.sessionToken,
        identityId: readRequiredString(body, "identityId") as IdentityId,
        channel: readOtpChannel(body),
        secret: readOptionalStringOrNull(body, "secret"),
        ttlSeconds: readOptionalNumber(body, "ttlSeconds"),
        now: readOptionalDate(body, "now"),
        metadata: readOptionalMetadata(body),
      });

      response.status(202).json(result);
    }),
  );

  router.post(
    "/re-auth/otp/resend",
    ...(csrf ? [csrf] : []),
    asyncHandler(async (request, response) => {
      const body = readBody(request.body);
      const result = await options.auth.account.reAuth.resendOtp({
        sessionToken: request.auth!.sessionToken,
        verificationId: readRequiredString(
          body,
          "verificationId",
        ) as VerificationId,
        secret: readOptionalStringOrNull(body, "secret"),
        ttlSeconds: readOptionalNumber(body, "ttlSeconds"),
        now: readOptionalDate(body, "now"),
        metadata: readOptionalMetadata(body),
      });

      response.status(202).json(result);
    }),
  );

  router.post(
    "/re-auth/otp/cancel",
    ...(csrf ? [csrf] : []),
    asyncHandler(async (request, response) => {
      const body = readBody(request.body);
      const result = await options.auth.account.reAuth.cancelOtp({
        sessionToken: request.auth!.sessionToken,
        verificationId: readRequiredString(
          body,
          "verificationId",
        ) as VerificationId,
        now: readOptionalDate(body, "now"),
        metadata: readOptionalMetadata(body),
      });

      response.status(200).json(result);
    }),
  );

  router.post(
    "/re-auth/otp/finish",
    ...(csrf ? [csrf] : []),
    asyncHandler(async (request, response) => {
      const body = readBody(request.body);
      const result = await options.auth.account.reAuth.finishOtp({
        sessionToken: request.auth!.sessionToken,
        verificationId: readRequiredString(
          body,
          "verificationId",
        ) as VerificationId,
        secret: readRequiredString(body, "secret"),
        now: readOptionalDate(body, "now"),
      });

      response.status(200).json(result);
    }),
  );

  router.post(
    "/re-auth/password/confirm",
    ...(csrf ? [csrf] : []),
    asyncHandler(async (request, response) => {
      const body = readBody(request.body);
      const result = await options.auth.account.reAuth.confirmPassword({
        sessionToken: request.auth!.sessionToken,
        currentPassword: readRequiredString(body, "currentPassword"),
        now: readOptionalDate(body, "now"),
      });

      response.status(200).json(result);
    }),
  );

  router.post(
    "/sessions/revoke-current",
    ...(csrf ? [csrf] : []),
    asyncHandler(async (request, response) => {
      const body = readBody(request.body);
      await options.auth.account.sessions.revokeCurrent({
        sessionToken: request.auth!.sessionToken,
        now: readOptionalDate(body, "now"),
      });
      clearSessionCookie(response, options.session);
      response.status(204).end();
    }),
  );

  router.post(
    "/sessions/revoke-owned",
    ...(csrf ? [csrf] : []),
    asyncHandler(async (request, response) => {
      const body = readBody(request.body);
      const result = await options.auth.account.sessions.revokeOwned({
        sessionToken: request.auth!.sessionToken,
        targetSessionId: readRequiredString(
          body,
          "targetSessionId",
        ) as SessionId,
        now: readOptionalDate(body, "now"),
      });

      response.status(200).json(result);
    }),
  );

  router.post(
    "/sessions/revoke-other",
    ...(csrf ? [csrf] : []),
    asyncHandler(async (request, response) => {
      const body = readBody(request.body);
      const result = await options.auth.account.sessions.revokeOther({
        sessionToken: request.auth!.sessionToken,
        now: readOptionalDate(body, "now"),
      });

      response.status(200).json(result);
    }),
  );

  router.post(
    "/identities/link",
    ...(csrf ? [csrf] : []),
    asyncHandler(async (request, response) => {
      const body = readBody(request.body);
      const result = await options.auth.account.identities.link({
        sessionToken: request.auth!.sessionToken,
        assertion: readOptionalObject(body, "assertion") as never,
        provider: readOptionalObject(body, "provider") as never,
        finishInput: readOptionalObject(body, "finishInput") as never,
        reAuthenticatedAt: readOptionalReAuthMarker(body),
        now: readOptionalDate(body, "now"),
        metadata: readOptionalMetadata(body),
      });

      response.status(200).json(result);
    }),
  );

  router.post(
    "/identities/unlink",
    ...(csrf ? [csrf] : []),
    asyncHandler(async (request, response) => {
      const body = readBody(request.body);
      await options.auth.account.identities.unlink({
        sessionToken: request.auth!.sessionToken,
        identityId: readRequiredString(body, "identityId") as IdentityId,
        reAuthenticatedAt: readOptionalReAuthMarker(body),
        now: readOptionalDate(body, "now"),
        metadata: readOptionalMetadata(body),
      });

      response.status(204).end();
    }),
  );

  router.post(
    "/closure/close",
    ...(csrf ? [csrf] : []),
    asyncHandler(async (request, response) => {
      const body = readBody(request.body);
      const result = await options.auth.account.closure.close({
        sessionToken: request.auth!.sessionToken,
        reAuthenticatedAt: readOptionalReAuthMarker(body),
        now: readOptionalDate(body, "now"),
        metadata: readOptionalMetadata(body),
      });
      clearSessionCookie(response, options.session);
      response.status(200).json(result);
    }),
  );

  return router;
}

function readQueryBoolean(input: unknown): boolean | undefined {
  if (input === undefined) {
    return undefined;
  }

  if (input === "true") {
    return true;
  }

  if (input === "false") {
    return false;
  }

  return undefined;
}

function readQueryNumber(input: unknown): number | undefined {
  if (typeof input !== "string" || !input.trim()) {
    return undefined;
  }

  const value = Number(input);

  return Number.isFinite(value) ? value : undefined;
}

function toAccountSessionResponse(context: ResolvedSessionContext): {
  readonly session: ReturnType<typeof toAccountSecuritySessionView>;
  readonly user: ReturnType<typeof toAccountSecurityUserView>;
} {
  return {
    session: toAccountSecuritySessionView(context.session),
    user: toAccountSecurityUserView(context.user),
  };
}

function readOptionalStringOrNull(
  input: Record<string, unknown>,
  key: string,
): string | undefined {
  const value = input[key];

  if (value === undefined || value === null) {
    return undefined;
  }

  if (typeof value !== "string") {
    throw new Error(`${key} must be a string.`);
  }

  return value.trim() || undefined;
}

function readOptionalObject(
  input: Record<string, unknown>,
  key: string,
): Record<string, unknown> | undefined {
  const value = input[key];

  if (value === undefined || value === null) {
    return undefined;
  }

  if (typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${key} must be an object.`);
  }

  return value as Record<string, unknown>;
}

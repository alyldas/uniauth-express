import type { SessionId, UserId, VerificationId } from "@alyldas/uniauth-core";
import { Router } from "express";
import { asyncHandler, rejectMissingAdminGuard } from "../middleware.js";
import type { UniAuthExpressOptions } from "../types.js";
import {
  readBody,
  readOptionalAuditWindow,
  readOptionalCursor,
  readOptionalDate,
  readOptionalFields,
  readOptionalMetadata,
  readOptionalNumber,
  readOptionalOtpChannel,
  readOptionalVerificationPurpose,
  readRequiredString,
  readVerificationPurpose,
} from "../validation.js";

export function createUniAuthAdminRouter(
  options: UniAuthExpressOptions,
): Router {
  const router = Router();
  const csrf = options.csrf;

  router.use(options.adminGuard ?? rejectMissingAdminGuard);

  router.get(
    "/users/:userId",
    asyncHandler(async (request, response) => {
      response
        .status(200)
        .json(
          await options.auth.admin.users.get(request.params.userId as UserId),
        );
    }),
  );

  router.get(
    "/users/:userId/identities",
    asyncHandler(async (request, response) => {
      response
        .status(200)
        .json(
          await options.auth.admin.users.identities(
            request.params.userId as UserId,
          ),
        );
    }),
  );

  router.get(
    "/users/:userId/credentials",
    asyncHandler(async (request, response) => {
      response
        .status(200)
        .json(
          await options.auth.admin.users.credentials(
            request.params.userId as UserId,
          ),
        );
    }),
  );

  router.get(
    "/users/:userId/sessions",
    asyncHandler(async (request, response) => {
      response
        .status(200)
        .json(
          await options.auth.admin.users.sessions(
            request.params.userId as UserId,
          ),
        );
    }),
  );

  router.post(
    "/users/:userId/sessions/revoke",
    ...(csrf ? [csrf] : []),
    asyncHandler(async (request, response) => {
      const body = readBody(request.body);
      const result = await options.auth.admin.users.revokeSessions({
        userId: request.params.userId as UserId,
        exceptSessionId: readOptionalSessionId(body, "exceptSessionId"),
        now: readOptionalDate(body, "now"),
      });

      response.status(200).json(result);
    }),
  );

  router.get(
    "/users/:userId/security",
    asyncHandler(async (request, response) => {
      response
        .status(200)
        .json(
          await options.auth.admin.users.securitySnapshot(
            request.params.userId as UserId,
          ),
        );
    }),
  );

  router.post(
    "/users/:userId/inspection",
    asyncHandler(async (request, response) => {
      const body = readBody(request.body);
      const result = await options.auth.admin.users.inspectionSnapshot({
        userId: request.params.userId as UserId,
        auditLimit: readOptionalNumber(body, "auditLimit"),
        audit: readOptionalAuditWindow(body) as never,
      });

      response.status(200).json(result);
    }),
  );

  router.post(
    "/sessions/create",
    ...(csrf ? [csrf] : []),
    asyncHandler(async (request, response) => {
      const body = readBody(request.body);
      const result = await options.auth.admin.sessions.create({
        userId: readRequiredString(body, "userId") as UserId,
        expiresAt: readOptionalDate(body, "expiresAt"),
        now: readOptionalDate(body, "now"),
        metadata: readOptionalMetadata(body),
      });

      response.status(201).json(result);
    }),
  );

  router.post(
    "/sessions/revoke",
    ...(csrf ? [csrf] : []),
    asyncHandler(async (request, response) => {
      const body = readBody(request.body);
      await options.auth.admin.sessions.revoke(
        readRequiredString(body, "sessionId") as SessionId,
      );
      response.status(204).end();
    }),
  );

  router.post(
    "/sessions/touch",
    ...(csrf ? [csrf] : []),
    asyncHandler(async (request, response) => {
      const body = readBody(request.body);
      const result = await options.auth.admin.sessions.touch({
        sessionId: readRequiredString(body, "sessionId") as SessionId,
        now: readOptionalDate(body, "now"),
      });

      response.status(200).json(result);
    }),
  );

  router.post(
    "/sessions/resolve",
    asyncHandler(async (request, response) => {
      const body = readBody(request.body);
      const result = await options.auth.admin.sessions.resolve({
        sessionToken: readRequiredString(body, "sessionToken"),
        now: readOptionalDate(body, "now"),
      });

      response.status(200).json(result);
    }),
  );

  router.post(
    "/sessions/context",
    asyncHandler(async (request, response) => {
      const body = readBody(request.body);
      const result = await options.auth.admin.sessions.context({
        sessionToken: readRequiredString(body, "sessionToken"),
        touch: readOptionalBoolean(body, "touch"),
        now: readOptionalDate(body, "now"),
      });

      response.status(200).json(result);
    }),
  );

  router.post(
    "/verifications/create",
    ...(csrf ? [csrf] : []),
    asyncHandler(async (request, response) => {
      const body = readBody(request.body);
      const result = await options.auth.admin.verifications.create({
        purpose: readVerificationPurpose(body),
        target: readRequiredString(body, "target"),
        secret: readOptionalString(body, "secret"),
        ttlSeconds: readOptionalNumber(body, "ttlSeconds"),
        now: readOptionalDate(body, "now"),
        metadata: readOptionalMetadata(body),
      });

      response.status(201).json(result);
    }),
  );

  router.get(
    "/verifications/:verificationId",
    asyncHandler(async (request, response) => {
      response
        .status(200)
        .json(
          await options.auth.admin.verifications.get(
            request.params.verificationId as VerificationId,
          ),
        );
    }),
  );

  router.post(
    "/verifications/cancel",
    ...(csrf ? [csrf] : []),
    asyncHandler(async (request, response) => {
      const body = readBody(request.body);
      const result = await options.auth.admin.verifications.cancel({
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
    "/verifications/resend-window",
    asyncHandler(async (request, response) => {
      const body = readBody(request.body);
      const result = await options.auth.admin.verifications.resendWindow({
        verificationId: readRequiredString(
          body,
          "verificationId",
        ) as VerificationId,
        cooldownSeconds: readOptionalNumber(body, "cooldownSeconds"),
        now: readOptionalDate(body, "now"),
      });

      response.status(200).json(result);
    }),
  );

  router.post(
    "/verifications/finish-otp",
    ...(csrf ? [csrf] : []),
    asyncHandler(async (request, response) => {
      const body = readBody(request.body);
      const result = await options.auth.admin.verifications.finishOtp({
        verificationId: readRequiredString(
          body,
          "verificationId",
        ) as VerificationId,
        secret: readRequiredString(body, "secret"),
        purpose: readOptionalVerificationPurpose(body),
        channel: readOptionalOtpChannel(body),
        now: readOptionalDate(body, "now"),
      });

      response.status(200).json(result);
    }),
  );

  router.post(
    "/verifications/cancel-otp",
    ...(csrf ? [csrf] : []),
    asyncHandler(async (request, response) => {
      const body = readBody(request.body);
      const result = await options.auth.admin.verifications.cancelOtp({
        verificationId: readRequiredString(
          body,
          "verificationId",
        ) as VerificationId,
        purpose: readOptionalVerificationPurpose(body),
        channel: readOptionalOtpChannel(body),
        now: readOptionalDate(body, "now"),
        metadata: readOptionalMetadata(body),
      });

      response.status(200).json(result);
    }),
  );

  router.post(
    "/credentials/set-password",
    ...(csrf ? [csrf] : []),
    asyncHandler(async (request, response) => {
      const body = readBody(request.body);
      const result = await options.auth.admin.credentials.setPassword({
        userId: readRequiredString(body, "userId") as UserId,
        email: readRequiredString(body, "email"),
        password: readRequiredString(body, "password"),
        reAuthenticatedAt: readOptionalDate(body, "reAuthenticatedAt"),
        now: readOptionalDate(body, "now"),
        metadata: readOptionalMetadata(body),
      });

      response.status(200).json(result);
    }),
  );

  router.post(
    "/credentials/change-password",
    ...(csrf ? [csrf] : []),
    asyncHandler(async (request, response) => {
      const body = readBody(request.body);
      const result = await options.auth.admin.credentials.changePassword({
        userId: readRequiredString(body, "userId") as UserId,
        currentPassword: readRequiredString(body, "currentPassword"),
        newPassword: readRequiredString(body, "newPassword"),
        reAuthenticatedAt: readOptionalDate(body, "reAuthenticatedAt"),
        now: readOptionalDate(body, "now"),
        metadata: readOptionalMetadata(body),
      });

      response.status(200).json(result);
    }),
  );

  router.post(
    "/credentials/finish-password-recovery",
    ...(csrf ? [csrf] : []),
    asyncHandler(async (request, response) => {
      const body = readBody(request.body);
      const result =
        await options.auth.admin.credentials.finishPasswordRecovery({
          verificationId: readRequiredString(
            body,
            "verificationId",
          ) as VerificationId,
          secret: readRequiredString(body, "secret"),
          newPassword: readRequiredString(body, "newPassword"),
          now: readOptionalDate(body, "now"),
          metadata: readOptionalMetadata(body),
        });

      response.status(200).json(result);
    }),
  );

  router.post(
    "/audit/events",
    asyncHandler(async (request, response) => {
      const body = readBody(request.body);
      response
        .status(200)
        .json(await options.auth.admin.audit.events(readAuditQuery(body)));
    }),
  );

  router.post(
    "/audit/page",
    asyncHandler(async (request, response) => {
      const body = readBody(request.body);
      response
        .status(200)
        .json(await options.auth.admin.audit.page(readAuditQuery(body)));
    }),
  );

  return router;
}

function readAuditQuery(
  input: Record<string, unknown>,
): Record<string, unknown> {
  return {
    ...readOptionalFields(input, ["userId", "identityId", "sessionId", "type"]),
    before: readOptionalCursor(input, "before"),
    after: readOptionalCursor(input, "after"),
    limit: readOptionalNumber(input, "limit"),
  };
}

function readOptionalSessionId(
  input: Record<string, unknown>,
  key: string,
): SessionId | undefined {
  const value = readOptionalString(input, key);

  return value as SessionId | undefined;
}

function readOptionalString(
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

function readOptionalBoolean(
  input: Record<string, unknown>,
  key: string,
): boolean | undefined {
  const value = input[key];

  if (value === undefined || value === null) {
    return undefined;
  }

  if (typeof value !== "boolean") {
    throw new Error(`${key} must be a boolean.`);
  }

  return value;
}

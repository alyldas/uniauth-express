import type { PublicAuthResult, VerificationId } from "@alyldas/uniauth-core";
import { Router } from "express";
import { asyncHandler } from "../middleware.js";
import { writeSessionCookie } from "../transport.js";
import type { UniAuthExpressOptions } from "../types.js";
import {
  readBody,
  readOptionalDate,
  readOptionalMetadata,
  readOptionalNumber,
  readOptionalOtpChannel,
  readOtpChannel,
  readRequiredString,
  readVerificationPurpose,
} from "../validation.js";

export function createUniAuthPublicRouter(
  options: UniAuthExpressOptions,
): Router {
  const router = Router();
  const csrf = options.csrf;

  router.post(
    "/provider/sign-in",
    ...(csrf ? [csrf] : []),
    asyncHandler(async (request, response) => {
      const body = readBody(request.body);
      const result = await options.auth.public.provider.signIn({
        assertion: readOptionalRecord(body, "assertion") as never,
        provider: readOptionalRecord(body, "provider") as never,
        finishInput: readOptionalRecord(body, "finishInput") as never,
        now: readOptionalDate(body, "now"),
        sessionExpiresAt: readOptionalDate(body, "sessionExpiresAt"),
        metadata: readOptionalMetadata(body),
      });

      await sendPublicAuthResult(response, result, options);
    }),
  );

  router.post(
    "/password/sign-in",
    ...(csrf ? [csrf] : []),
    asyncHandler(async (request, response) => {
      const body = readBody(request.body);
      const result = await options.auth.public.password.signIn({
        email: readRequiredString(body, "email"),
        password: readRequiredString(body, "password"),
        now: readOptionalDate(body, "now"),
        sessionExpiresAt: readOptionalDate(body, "sessionExpiresAt"),
        metadata: readOptionalMetadata(body),
      });

      await sendPublicAuthResult(response, result, options);
    }),
  );

  router.post(
    "/otp/start",
    ...(csrf ? [csrf] : []),
    asyncHandler(async (request, response) => {
      const body = readBody(request.body);
      const result = await options.auth.public.otp.start({
        purpose: readVerificationPurpose(body),
        channel: readOtpChannel(body),
        target: readRequiredString(body, "target"),
        secret: readOptionalStringForForwarding(body, "secret"),
        ttlSeconds: readOptionalNumber(body, "ttlSeconds"),
        now: readOptionalDate(body, "now"),
        metadata: readOptionalMetadata(body),
      });

      response.status(202).json(result);
    }),
  );

  router.post(
    "/otp/resend",
    ...(csrf ? [csrf] : []),
    asyncHandler(async (request, response) => {
      const body = readBody(request.body);
      const result = await options.auth.public.otp.resend({
        verificationId: readRequiredString(
          body,
          "verificationId",
        ) as VerificationId,
        secret: readOptionalStringForForwarding(body, "secret"),
        ttlSeconds: readOptionalNumber(body, "ttlSeconds"),
        now: readOptionalDate(body, "now"),
        metadata: readOptionalMetadata(body),
      });

      response.status(202).json(result);
    }),
  );

  router.post(
    "/otp/sign-in",
    ...(csrf ? [csrf] : []),
    asyncHandler(async (request, response) => {
      const body = readBody(request.body);
      const result = await options.auth.public.otp.signIn({
        verificationId: readRequiredString(
          body,
          "verificationId",
        ) as VerificationId,
        secret: readRequiredString(body, "secret"),
        channel: readOptionalOtpChannel(body),
        now: readOptionalDate(body, "now"),
        sessionExpiresAt: readOptionalDate(body, "sessionExpiresAt"),
        metadata: readOptionalMetadata(body),
      });

      await sendPublicAuthResult(response, result, options);
    }),
  );

  router.post(
    "/magic-link/start",
    ...(csrf ? [csrf] : []),
    asyncHandler(async (request, response) => {
      const body = readBody(request.body);
      const result = await options.auth.public.magicLink.start({
        email: readRequiredString(body, "email"),
        createLink: createStaticLink(readRequiredString(body, "link")),
        secret: readOptionalStringForForwarding(body, "secret"),
        ttlSeconds: readOptionalNumber(body, "ttlSeconds"),
        now: readOptionalDate(body, "now"),
        metadata: readOptionalMetadata(body),
      });

      response.status(202).json(result);
    }),
  );

  router.post(
    "/magic-link/resend",
    ...(csrf ? [csrf] : []),
    asyncHandler(async (request, response) => {
      const body = readBody(request.body);
      const result = await options.auth.public.magicLink.resend({
        verificationId: readRequiredString(
          body,
          "verificationId",
        ) as VerificationId,
        createLink: createStaticLink(readRequiredString(body, "link")),
        secret: readOptionalStringForForwarding(body, "secret"),
        ttlSeconds: readOptionalNumber(body, "ttlSeconds"),
        now: readOptionalDate(body, "now"),
        metadata: readOptionalMetadata(body),
      });

      response.status(202).json(result);
    }),
  );

  router.post(
    "/magic-link/finish",
    ...(csrf ? [csrf] : []),
    asyncHandler(async (request, response) => {
      const body = readBody(request.body);
      const result = await options.auth.public.magicLink.finish({
        verificationId: readRequiredString(
          body,
          "verificationId",
        ) as VerificationId,
        secret: readRequiredString(body, "secret"),
        now: readOptionalDate(body, "now"),
        sessionExpiresAt: readOptionalDate(body, "sessionExpiresAt"),
        metadata: readOptionalMetadata(body),
      });

      await sendPublicAuthResult(response, result, options);
    }),
  );

  router.post(
    "/password-recovery/start",
    ...(csrf ? [csrf] : []),
    asyncHandler(async (request, response) => {
      const body = readBody(request.body);
      const result = await options.auth.public.passwordRecovery.start({
        email: readRequiredString(body, "email"),
        createLink: createStaticLink(readRequiredString(body, "link")),
        secret: readOptionalStringForForwarding(body, "secret"),
        ttlSeconds: readOptionalNumber(body, "ttlSeconds"),
        now: readOptionalDate(body, "now"),
        metadata: readOptionalMetadata(body),
      });

      response.status(202).json(result);
    }),
  );

  router.post(
    "/password-recovery/resend",
    ...(csrf ? [csrf] : []),
    asyncHandler(async (request, response) => {
      const body = readBody(request.body);
      const result = await options.auth.public.passwordRecovery.resend({
        verificationId: readRequiredString(
          body,
          "verificationId",
        ) as VerificationId,
        createLink: createStaticLink(readRequiredString(body, "link")),
        secret: readOptionalStringForForwarding(body, "secret"),
        ttlSeconds: readOptionalNumber(body, "ttlSeconds"),
        now: readOptionalDate(body, "now"),
        metadata: readOptionalMetadata(body),
      });

      response.status(202).json(result);
    }),
  );

  return router;
}

async function sendPublicAuthResult(
  response: Parameters<Parameters<typeof asyncHandler>[0]>[1],
  result: PublicAuthResult,
  options: UniAuthExpressOptions,
): Promise<void> {
  await writeSessionCookie(response, result.sessionToken, options.session);
  response.status(200).json(result);
}

function readOptionalRecord(
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

function readOptionalStringForForwarding(
  input: Record<string, unknown>,
  key: string,
): string | undefined {
  const value = input[key];

  if (value === undefined || value === null) {
    return undefined;
  }

  return readRequiredString(input, key);
}

function createStaticLink(value: string): () => string {
  return () => value;
}

import type { UniAuthRequestAuth } from "./types.js";

declare module "express-serve-static-core" {
  interface Request {
    auth?: UniAuthRequestAuth;
  }
}

export {
  AUTHENTICATION_REQUIRED_MESSAGE,
  FORBIDDEN_MESSAGE,
  INTERNAL_SERVER_ERROR_MESSAGE,
  REQUEST_CANNOT_BE_COMPLETED_MESSAGE,
  TOO_MANY_AUTH_ATTEMPTS_MESSAGE,
  createUniAuthErrorHandler,
  isSessionContextError,
} from "./errors.js";
export {
  asyncHandler,
  createUniAuthSessionMiddleware,
  rejectMissingAdminGuard,
  requireUniAuthSession,
} from "./middleware.js";
export { createUniAuthExpressRouter, createUniAuthRouters } from "./router.js";
export { createUniAuthAccountRouter } from "./routes/account.js";
export { createUniAuthAdminRouter } from "./routes/admin.js";
export { createUniAuthPublicRouter } from "./routes/public.js";
export {
  clearSessionCookie,
  readBearerToken,
  readCookieHeaderToken,
  readSessionToken,
  writeSessionCookie,
} from "./transport.js";
export {
  RequestValidationError,
  readAuthPolicyAction,
  readBody,
  readOptionalAuditWindow,
  readOptionalBoolean,
  readOptionalCursor,
  readOptionalDate,
  readOptionalFields,
  readOptionalMetadata,
  readOptionalNumber,
  readOptionalOtpChannel,
  readOptionalReAuthMarker,
  readOptionalString,
  readOptionalVerificationPurpose,
  readOtpChannel,
  readRequiredDate,
  readRequiredString,
  readVerificationPurpose,
} from "./validation.js";
export type {
  UniAuthErrorHandler,
  UniAuthErrorMappingOptions,
  UniAuthExpressOptions,
  UniAuthExpressService,
  UniAuthRequestAuth,
  UniAuthRouterSet,
  UniAuthSessionCookieOptions,
  UniAuthSessionTransportOptions,
} from "./types.js";

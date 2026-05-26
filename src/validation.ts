import type {
  AuditEventCursor,
  AuthPolicyAction,
  CurrentAccountRecentAuthMarker,
  OtpChannel,
  VerificationPurpose,
} from "@alyldas/uniauth-core";

export class RequestValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RequestValidationError";
  }
}

export function readBody(input: unknown): Record<string, unknown> {
  if (!isRecord(input)) {
    throw new RequestValidationError("Request body must be an object.");
  }

  return input;
}

export function readRequiredString(
  input: Record<string, unknown>,
  key: string,
): string {
  const value = input[key];

  if (typeof value !== "string" || !value.trim()) {
    throw new RequestValidationError(`${key} is required.`);
  }

  return value.trim();
}

export function readOptionalString(
  input: Record<string, unknown>,
  key: string,
): string | undefined {
  const value = input[key];

  if (value === undefined || value === null) {
    return undefined;
  }

  if (typeof value !== "string") {
    throw new RequestValidationError(`${key} must be a string.`);
  }

  return value.trim() || undefined;
}

export function readOptionalNumber(
  input: Record<string, unknown>,
  key: string,
): number | undefined {
  const value = input[key];

  if (value === undefined || value === null) {
    return undefined;
  }

  if (!Number.isFinite(value) || typeof value !== "number") {
    throw new RequestValidationError(`${key} must be a finite number.`);
  }

  return value;
}

export function readOptionalBoolean(
  input: Record<string, unknown>,
  key: string,
): boolean | undefined {
  const value = input[key];

  if (value === undefined || value === null) {
    return undefined;
  }

  if (typeof value !== "boolean") {
    throw new RequestValidationError(`${key} must be a boolean.`);
  }

  return value;
}

export function readOptionalDate(
  input: Record<string, unknown>,
  key: string,
): Date | undefined {
  const value = readOptionalString(input, key);

  if (!value) {
    return undefined;
  }

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    throw new RequestValidationError(`${key} must be an ISO date string.`);
  }

  return date;
}

export function readOptionalMetadata(
  input: Record<string, unknown>,
): Record<string, unknown> | undefined {
  const value = input.metadata;

  if (value === undefined || value === null) {
    return undefined;
  }

  if (!isRecord(value)) {
    throw new RequestValidationError("metadata must be an object.");
  }

  return value;
}

export function readOptionalReAuthMarker(
  input: Record<string, unknown>,
): CurrentAccountRecentAuthMarker | undefined {
  const value = input.reAuthenticatedAt;

  if (value === undefined || value === null) {
    return undefined;
  }

  if (!isRecord(value)) {
    throw new RequestValidationError("reAuthenticatedAt must be an object.");
  }

  return {
    currentSessionId: readRequiredString(
      value,
      "currentSessionId",
    ) as CurrentAccountRecentAuthMarker["currentSessionId"],
    userId: readRequiredString(
      value,
      "userId",
    ) as CurrentAccountRecentAuthMarker["userId"],
    reAuthenticatedAt: readRequiredDate(value, "reAuthenticatedAt"),
    markerId: readRequiredString(value, "markerId"),
  };
}

export function readRequiredDate(
  input: Record<string, unknown>,
  key: string,
): Date {
  const value = readRequiredString(input, key);
  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    throw new RequestValidationError(`${key} must be an ISO date string.`);
  }

  return date;
}

export function readOptionalAuditWindow(
  input: Record<string, unknown>,
): Record<string, unknown> | undefined {
  const value = input.audit;

  if (value === undefined || value === null) {
    return undefined;
  }

  if (!isRecord(value)) {
    throw new RequestValidationError("audit must be an object.");
  }

  return {
    ...readOptionalFields(value, ["identityId", "sessionId", "type"]),
    ...readOptionalCursorField(value, "before"),
    ...readOptionalCursorField(value, "after"),
    ...readOptionalNumberField(value, "limit"),
  };
}

export function readOptionalCursor(
  input: Record<string, unknown>,
  key: string,
): AuditEventCursor | undefined {
  const value = input[key];

  if (value === undefined || value === null) {
    return undefined;
  }

  if (!isRecord(value)) {
    throw new RequestValidationError(`${key} must be an object.`);
  }

  return {
    occurredAt: readRequiredDate(value, "occurredAt"),
    id: readRequiredString(value, "id") as AuditEventCursor["id"],
  };
}

export function readOtpChannel(input: Record<string, unknown>): OtpChannel {
  return readRequiredString(input, "channel") as OtpChannel;
}

export function readOptionalOtpChannel(
  input: Record<string, unknown>,
): OtpChannel | undefined {
  return readOptionalString(input, "channel") as OtpChannel | undefined;
}

export function readVerificationPurpose(
  input: Record<string, unknown>,
): VerificationPurpose {
  return readRequiredString(input, "purpose") as VerificationPurpose;
}

export function readOptionalVerificationPurpose(
  input: Record<string, unknown>,
): VerificationPurpose | undefined {
  return readOptionalString(input, "purpose") as
    | VerificationPurpose
    | undefined;
}

export function readAuthPolicyAction(
  input: Record<string, unknown>,
): AuthPolicyAction {
  return readRequiredString(input, "action") as AuthPolicyAction;
}

export function readOptionalFields(
  input: Record<string, unknown>,
  keys: readonly string[],
): Record<string, string> {
  const output: Record<string, string> = {};

  for (const key of keys) {
    const value = readOptionalString(input, key);

    if (value !== undefined) {
      output[key] = value;
    }
  }

  return output;
}

function readOptionalCursorField(
  input: Record<string, unknown>,
  key: string,
): Record<string, AuditEventCursor> {
  const value = readOptionalCursor(input, key);

  return value ? { [key]: value } : {};
}

function readOptionalNumberField(
  input: Record<string, unknown>,
  key: string,
): Record<string, number> {
  const value = readOptionalNumber(input, key);

  return value === undefined ? {} : { [key]: value };
}

export function isRecord(input: unknown): input is Record<string, unknown> {
  return typeof input === "object" && input !== null && !Array.isArray(input);
}

import { createHash } from "node:crypto";
import { APIError } from "better-auth/api";
import { createAuthEndpoint } from "better-auth/api";
import { setSessionCookie } from "better-auth/cookies";
import { parseUserOutput } from "better-auth/db";
import type { BetterAuthPlugin, GenericEndpointContext } from "better-auth";

/**
 * Default Better Auth endpoint path for exchanging a legacy credential.
 *
 * Better Auth mounts plugin endpoints under the auth base path, so the default
 * full route is usually `/api/auth/legacy-immigration/exchange`.
 */
export const DEFAULT_ENDPOINT_PATH = "/legacy-immigration/exchange";

/**
 * Default legacy cookie name used when cookie-based token extraction is enabled.
 */
export const DEFAULT_COOKIE_NAME = "cookie";

/**
 * Result returned after a legacy credential has been verified.
 *
 * `legacyUserId` should be the stable identifier from the legacy auth system.
 * `payload` can carry decoded token claims or other verification output into
 * `resolveTransition` without requiring the token to be parsed twice.
 */
export type VerifiedLegacyToken<Payload = unknown> = {
  legacyUserId: string;
  payload?: Payload;
};

/**
 * Mapping from a verified legacy identity to the Better Auth user that should
 * receive the new session.
 */
export type LegacyImmigrationTransition = {
  /**
   * Better Auth user id that should receive the migrated session.
   */
  userId: string;

  /**
   * Optional fields forwarded to Better Auth's session creation adapter.
   */
  sessionOverrides?: Record<string, unknown>;
};

type ExchangeContext = GenericEndpointContext;

export type LegacyImmigrationOptions<
  Payload = unknown,
  Transition extends LegacyImmigrationTransition = LegacyImmigrationTransition,
> = {
  /**
   * Endpoint path registered inside Better Auth.
   *
   * Defaults to {@link DEFAULT_ENDPOINT_PATH}.
   */
  endpointPath?: string;

  /**
   * Legacy cookie name to read when cookie extraction is enabled.
   *
   * Defaults to {@link DEFAULT_COOKIE_NAME}.
   */
  cookieName?: string;

  /**
   * Whether to accept `Authorization: Bearer <token>` credentials.
   *
   * Defaults to `true`. Authorization headers take precedence over cookies.
   */
  acceptAuthorization?: boolean;

  /**
   * Whether to accept a legacy credential from `cookieName`.
   *
   * Defaults to `true`.
   */
  acceptCookie?: boolean;

  /**
   * Verifies the raw legacy credential and returns its legacy identity.
   *
   * Throw from this callback to reject invalid, expired, revoked, or malformed
   * credentials. The optional payload is forwarded to `resolveTransition`.
   */
  verifyLegacyToken: (
    token: string,
    ctx: ExchangeContext,
  ) => Promise<VerifiedLegacyToken<Payload>> | VerifiedLegacyToken<Payload>;

  /**
   * Resolves a verified legacy identity to the Better Auth user to sign in.
   *
   * Return `null` when the credential is valid but cannot be migrated, such as
   * when no mapping exists or a one-time migration has already been consumed.
   * `tokenHash` is a SHA-256 hash of the raw token for lookup/audit use without
   * storing or comparing the raw credential.
   */
  resolveTransition: (input: {
    legacyUserId: string;
    tokenHash: string;
    payload?: Payload;
    ctx: ExchangeContext;
  }) => Promise<Transition | null> | Transition | null;

  /**
   * Optional final authorization check after the Better Auth user is loaded.
   *
   * Return `false` to reject the sign-in. Any other return value allows the
   * migration to continue.
   */
  validateUser?: (input: {
    user: Record<string, unknown>;
    transition: Transition;
    ctx: ExchangeContext;
  }) => Promise<boolean | void> | boolean | void;

  /**
   * Optional hook called after the Better Auth session is created.
   *
   * Use this to mark the legacy credential as migrated or record audit data. If
   * this callback throws, the newly created session is deleted and the error is
   * re-thrown.
   */
  onMigrated?: (input: {
    legacyUserId: string;
    user: Record<string, unknown>;
    session: Record<string, unknown>;
    transition: Transition;
    ctx: ExchangeContext;
  }) => Promise<void> | void;
};

/**
 * Hashes a legacy token with SHA-256.
 *
 * This is useful for transition-table lookups, idempotency checks, and audit
 * records where storing the raw legacy credential would be unsafe.
 */
export function hashLegacyToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

/**
 * Extracts a legacy token from request headers.
 *
 * Bearer authorization is checked first when enabled. If no bearer token is
 * present and cookie extraction is enabled, the configured legacy cookie is
 * decoded and returned. Returns `null` when no accepted credential source is
 * present.
 */
export function extractLegacyToken(
  headers: Headers,
  options?: {
    cookieName?: string;
    acceptAuthorization?: boolean;
    acceptCookie?: boolean;
  },
): string | null {
  const acceptAuthorization = options?.acceptAuthorization ?? true;
  const acceptCookie = options?.acceptCookie ?? true;
  const cookieName = options?.cookieName ?? DEFAULT_COOKIE_NAME;

  if (acceptAuthorization) {
    const authorization = headers.get("authorization");
    if (authorization) {
      const [scheme, ...rest] = authorization.trim().split(/\s+/);
      if (/^Bearer$/i.test(scheme) && rest.length === 1 && rest[0]) {
        return rest[0];
      }
    }
  }

  if (!acceptCookie) {
    return null;
  }

  const cookieHeader = headers.get("cookie");
  if (!cookieHeader) {
    return null;
  }

  for (const item of cookieHeader.split(";")) {
    const [name, ...valueParts] = item.trim().split("=");
    if (name === cookieName && valueParts.length > 0) {
      return decodeURIComponent(valueParts.join("="));
    }
  }

  return null;
}

/**
 * Creates the Better Auth server plugin for legacy credential immigration.
 *
 * The registered endpoint verifies a legacy credential, resolves it to a Better
 * Auth user, creates a Better Auth session, sets the normal Better Auth session
 * cookie, and returns the migrated user/session token payload. It accepts
 * bearer-token credentials and/or a legacy cookie based on the provided options.
 */
export function legacyImmigration<
  Payload = unknown,
  Transition extends LegacyImmigrationTransition = LegacyImmigrationTransition,
>(options: LegacyImmigrationOptions<Payload, Transition>): BetterAuthPlugin {
  const endpointPath = options.endpointPath ?? DEFAULT_ENDPOINT_PATH;

  return {
    id: "legacy-immigration",
    endpoints: {
      legacyImmigrationExchange: createAuthEndpoint(
        endpointPath,
        {
          method: "POST",
          metadata: {
            openapi: {
              description: "Exchange a legacy credential for a Better Auth session",
              responses: {
                200: {
                  description: "Legacy credential migrated",
                },
              },
            },
          },
        },
        async (ctx) => {
          const request = (ctx as { request?: Request }).request;
          const headers = ctx.headers ?? request?.headers ?? new Headers();
          const token = extractLegacyToken(headers, options);
          if (!token) {
            throw APIError.from("UNAUTHORIZED", {
              code: "LEGACY_TOKEN_MISSING",
              message: "Missing legacy credential.",
            });
          }

          const verified = await options.verifyLegacyToken(token, ctx);
          const transition = await options.resolveTransition({
            legacyUserId: verified.legacyUserId,
            tokenHash: hashLegacyToken(token),
            payload: verified.payload,
            ctx,
          });

          if (!transition) {
            throw APIError.from("UNAUTHORIZED", {
              code: "LEGACY_TRANSITION_NOT_FOUND",
              message: "Legacy credential cannot be migrated.",
            });
          }

          const user = await ctx.context.internalAdapter.findUserById(
            transition.userId,
          );
          if (!user) {
            throw APIError.from("UNAUTHORIZED", {
              code: "LEGACY_USER_NOT_FOUND",
              message: "Migrated user was not found.",
            });
          }

          const validationResult = await options.validateUser?.({
            user,
            transition,
            ctx,
          });
          if (validationResult === false) {
            throw APIError.from("FORBIDDEN", {
              code: "LEGACY_USER_REJECTED",
              message: "Migrated user is not allowed to sign in.",
            });
          }

          const session = await ctx.context.internalAdapter.createSession(
            transition.userId,
            undefined,
            transition.sessionOverrides as any,
          );

          try {
            await options.onMigrated?.({
              legacyUserId: verified.legacyUserId,
              user,
              session,
              transition,
              ctx,
            });
          } catch (error) {
            await ctx.context.internalAdapter.deleteSession(session.token);
            throw error;
          }

          await setSessionCookie(ctx, { session, user });

          return ctx.json({
            migrated: true,
            token: session.token,
            user: parseUserOutput(ctx.context.options, user),
          });
        },
      ),
    },
  };
}

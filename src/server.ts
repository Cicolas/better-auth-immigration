import { createHash } from "node:crypto";
import { APIError } from "better-auth/api";
import { createAuthEndpoint } from "better-auth/api";
import { setSessionCookie } from "better-auth/cookies";
import { parseUserOutput } from "better-auth/db";
import type { BetterAuthPlugin, GenericEndpointContext } from "better-auth";

export const DEFAULT_ENDPOINT_PATH = "/legacy-immigration/exchange";
export const DEFAULT_COOKIE_NAME = "cookie";

export type VerifiedLegacyToken<Payload = unknown> = {
  legacyUserId: string;
  payload?: Payload;
};

export type LegacyImmigrationTransition = {
  userId: string;
  sessionOverrides?: Record<string, unknown>;
};

type ExchangeContext = GenericEndpointContext;

export type LegacyImmigrationOptions<
  Payload = unknown,
  Transition extends LegacyImmigrationTransition = LegacyImmigrationTransition,
> = {
  endpointPath?: string;
  cookieName?: string;
  acceptAuthorization?: boolean;
  acceptCookie?: boolean;
  verifyLegacyToken: (
    token: string,
    ctx: ExchangeContext,
  ) => Promise<VerifiedLegacyToken<Payload>> | VerifiedLegacyToken<Payload>;
  resolveTransition: (input: {
    legacyUserId: string;
    tokenHash: string;
    payload?: Payload;
    ctx: ExchangeContext;
  }) => Promise<Transition | null> | Transition | null;
  validateUser?: (input: {
    user: Record<string, unknown>;
    transition: Transition;
    ctx: ExchangeContext;
  }) => Promise<boolean | void> | boolean | void;
  onMigrated?: (input: {
    legacyUserId: string;
    user: Record<string, unknown>;
    session: Record<string, unknown>;
    transition: Transition;
    ctx: ExchangeContext;
  }) => Promise<void> | void;
};

export function hashLegacyToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

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

import type { BetterAuthClientPlugin } from "better-auth/client";
import { DEFAULT_ENDPOINT_PATH } from "./server.js";

/**
 * Client-side options for the legacy immigration plugin.
 */
export type LegacyImmigrationClientOptions = {
  /**
   * Endpoint path registered by the server plugin.
   *
   * Must match the server-side `endpointPath`. Defaults to
   * {@link DEFAULT_ENDPOINT_PATH}.
   */
  endpointPath?: string;
};

type LegacyFetchOptions = {
  headers?: HeadersInit;
  [key: string]: unknown;
};

type ExchangeInput = {
  token?: string;
};

function withAuthorizationHeader(
  fetchOptions: LegacyFetchOptions | undefined,
  token: string | undefined,
): LegacyFetchOptions {
  if (!token) {
    return fetchOptions ?? {};
  }

  const headers = new Headers(fetchOptions?.headers);
  headers.set("authorization", `Bearer ${token}`);

  return {
    ...fetchOptions,
    headers,
  };
}

/**
 * Creates the Better Auth client plugin for legacy credential immigration.
 *
 * Adds `authClient.legacyImmigration.exchange()`. Passing `input.token` sends
 * it as `Authorization: Bearer <token>`. Omitting the token leaves credentials
 * to the request context, which allows the server endpoint to read the legacy
 * cookie when cookie extraction is enabled.
 */
export function legacyImmigrationClient(
  options?: LegacyImmigrationClientOptions,
) {
  const endpointPath = options?.endpointPath ?? DEFAULT_ENDPOINT_PATH;

  return {
    id: "legacy-immigration",
    $InferServerPlugin: {} as any,
    pathMethods: {
      [endpointPath]: "POST",
    },
    getActions: ($fetch) => ({
      legacyImmigration: {
        exchange: async (
          input?: ExchangeInput,
          fetchOptions?: LegacyFetchOptions,
        ) => {
          return $fetch(
            endpointPath,
            {
              method: "POST",
              ...withAuthorizationHeader(fetchOptions, input?.token),
            } as any,
          );
        },
      },
    }),
    atomListeners: [
      {
        matcher: (path) => path === endpointPath,
        signal: "$sessionSignal",
      },
    ],
  } satisfies BetterAuthClientPlugin;
}

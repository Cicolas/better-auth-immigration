import type { BetterAuthClientPlugin } from "better-auth/client";
import { DEFAULT_ENDPOINT_PATH } from "./server.js";

export type LegacyImmigrationClientOptions = {
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

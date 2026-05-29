import { describe, expect, it } from "bun:test";
import { legacyImmigrationClient } from "../src/client.js";

describe("legacyImmigrationClient", () => {
  it("sends bearer token when exchange receives a token", async () => {
    const plugin = legacyImmigrationClient();
    const actions = plugin.getActions!(
      (async (_path: string, options: { headers?: Headers; method?: string }) => {
        return {
          authorization: options.headers?.get("authorization"),
          method: options.method,
        };
      }) as any,
    );

    const result = (await actions.legacyImmigration.exchange({
      token: "old-token",
    })) as { authorization?: string; method?: string };

    expect(result.authorization).toBe("Bearer old-token");
    expect(result.method).toBe("POST");
  });
});

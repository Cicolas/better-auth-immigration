import { describe, expect, it } from "bun:test";
import {
  DEFAULT_COOKIE_NAME,
  extractLegacyToken,
  hashLegacyToken,
} from "../src/server.js";

describe("extractLegacyToken", () => {
  it("extracts bearer tokens", () => {
    const headers = new Headers({
      authorization: "Bearer abc123",
    });

    expect(extractLegacyToken(headers)).toBe("abc123");
  });

  it("extracts the legacy cookie", () => {
    const headers = new Headers({
      cookie: `${DEFAULT_COOKIE_NAME}=cookie-token; other=value`,
    });

    expect(extractLegacyToken(headers)).toBe("cookie-token");
  });

  it("returns null when no accepted token source exists", () => {
    expect(extractLegacyToken(new Headers())).toBeNull();
  });

  it("can disable cookie extraction", () => {
    const headers = new Headers({
      cookie: `${DEFAULT_COOKIE_NAME}=cookie-token`,
    });

    expect(extractLegacyToken(headers, { acceptCookie: false })).toBeNull();
  });
});

describe("hashLegacyToken", () => {
  it("hashes tokens without returning the raw token", () => {
    const hash = hashLegacyToken("secret-token");

    expect(hash).not.toBe("secret-token");
    expect(hash).toHaveLength(64);
  });
});

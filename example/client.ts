import { createAuthClient } from "better-auth/client";
import { legacyImmigrationClient } from "../src/index.js";

export const authClient = createAuthClient({
  plugins: [legacyImmigrationClient()],
});

await authClient.legacyImmigration.exchange({
  token: "legacy:old-user-1",
});

await authClient.legacyImmigration.exchange();

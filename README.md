# better-auth-immigration

Exchange a legacy credential for a normal Better Auth session.

```ts
import { betterAuth } from "better-auth";
import { legacyImmigration } from "better-auth-immigration";

export const auth = betterAuth({
  plugins: [
    legacyImmigration({
      async verifyLegacyToken(token) {
        return { legacyUserId: token };
      },
      async resolveTransition({ legacyUserId }) {
        return { userId: legacyUserId };
      },
      async onMigrated({ legacyUserId }) {
        console.log("migrated", legacyUserId);
      }
    })
  ]
});
```

Client:

```ts
import { createAuthClient } from "better-auth/client";
import { legacyImmigrationClient } from "better-auth-immigration";

export const authClient = createAuthClient({
  plugins: [legacyImmigrationClient()]
});

await authClient.legacyImmigration.exchange({ token: oldToken });
```

Default endpoint:

```txt
POST /legacy-immigration/exchange
Authorization: Bearer <legacy-token>
```

If no token is passed by the client, the endpoint can also read the legacy token from a cookie named `cookie`.

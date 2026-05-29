import { betterAuth } from "better-auth";
import { legacyImmigration } from "../src/index.js";

const transitionTable = new Map([
  ["old-user-1", { userId: "1", migrated: false }],
]);

export const auth = betterAuth({
  plugins: [
    legacyImmigration({
      async verifyLegacyToken(token) {
        if (!token.startsWith("legacy:")) {
          throw new Error("Invalid legacy token");
        }

        return {
          legacyUserId: token.slice("legacy:".length),
        };
      },
      async resolveTransition({ legacyUserId }) {
        const row = transitionTable.get(legacyUserId);
        if (!row || row.migrated) {
          return null;
        }

        return {
          userId: row.userId,
        };
      },
      validateUser({ user }) {
        if (user.isBan || user.isDeleted || user.isRegistered === false) {
          return false;
        }
      },
      async onMigrated({ legacyUserId }) {
        const row = transitionTable.get(legacyUserId);
        if (row) {
          row.migrated = true;
        }
      },
    }),
  ],
});

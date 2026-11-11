
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { pool } from "./db";
import { config } from "./config";

declare global {
  namespace Express {
    interface User {
      id: number;
      name: string;
      email: string;
      avatar?: string;
    }
  }
}

// ==========================================
// GOOGLE OAUTH STRATEGY
// ==========================================

if (config.googleId && config.googleSecret) {
  passport.use(
    new GoogleStrategy(
      {
        clientID: config.googleId,
        clientSecret: config.googleSecret,
        callbackURL: config.googleCallback
      },
      async (_accessToken, _refreshToken, profile, done) => {
        try {
          const email = profile.emails?.[0]?.value
            ?.trim()
            .toLowerCase();

          if (!email) {
            return done(
              new Error("Google account did not provide an email")
            );
          }

          const name = profile.displayName || email;
          const avatar = profile.photos?.[0]?.value || "";

          // Save or update Google user in MySQL
          await pool.execute(
            `INSERT INTO users
              (google_id, name, email, avatar)
             VALUES (?, ?, ?, ?)
             ON DUPLICATE KEY UPDATE
              google_id = VALUES(google_id),
              name = VALUES(name),
              email = VALUES(email),
              avatar = VALUES(avatar)`,
            [profile.id, name, email, avatar]
          );

          // Find the user using Google ID
          const [rows] = await pool.execute<any[]>(
            `SELECT id, name, email, avatar
             FROM users
             WHERE google_id = ?
             LIMIT 1`,
            [profile.id]
          );

          if (!rows.length) {
            return done(
              new Error("Unable to find Google user in database")
            );
          }

          return done(null, rows[0]);
        } catch (error) {
          console.error("Google authentication error:", error);
          return done(error as Error);
        }
      }
    )
  );
}

// ==========================================
// SERIALIZE USER
// ==========================================

passport.serializeUser((user: any, done) => {
  done(null, user.id);
});

// ==========================================
// DESERIALIZE USER
// ==========================================

passport.deserializeUser(async (id: number, done) => {
  try {
    const [rows] = await pool.execute<any[]>(
      `SELECT id, name, email, avatar
       FROM users
       WHERE id = ?
       LIMIT 1`,
      [id]
    );

    if (!rows.length) {
      return done(null, false);
    }

    return done(null, rows[0]);
  } catch (error) {
    console.error("User session restoration error:", error);
    return done(error as Error);
  }
});

export default passport;


import express from "express";
import cors from "cors";
import session from "express-session";
import passport from "./auth";
import { initDb, pool } from "./db";
import { config } from "./config";
import { emailQueue } from "./queue";
import { indexEmail, es } from "./search";
import { createBullBoard } from "@bull-board/api";
import { BullMQAdapter } from "@bull-board/api/bullMQAdapter";
import { ExpressAdapter } from "@bull-board/express";
import axios from "axios";
import { randomUUID } from "crypto";

const app = express();

// ==========================================
// TRUST RENDER PROXY
// ==========================================

app.set("trust proxy", 1);

// ==========================================
// CORS CONFIGURATION
// ==========================================

const allowedOrigins = [
  "http://localhost:5173",
  "https://reach-inbox-email-scheduler-ebon.vercel.app"
];

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin || allowedOrigins.includes(origin)) {
        return callback(null, true);
      }

      return callback(new Error("Not allowed by CORS"));
    },
    credentials: true
  })
);

// ==========================================
// BODY PARSER
// ==========================================

app.use(express.json({ limit: "5mb" }));

// ==========================================
// SESSION CONFIGURATION
// ==========================================

app.use(
  session({
    secret: config.sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite:
        process.env.NODE_ENV === "production"
          ? "none"
          : "lax",
      secure: process.env.NODE_ENV === "production",
      maxAge: 24 * 60 * 60 * 1000
    }
  })
);

// ==========================================
// PASSPORT CONFIGURATION
// ==========================================

app.use(passport.initialize());
app.use(passport.session());

// ==========================================
// CURRENT USER
// ==========================================

function currentUser(req: express.Request) {
  if (req.user) {
    return req.user;
  }

  if (process.env.NODE_ENV !== "production") {
    return {
      id: 1,
      name: "Local Demo User",
      email: "demo@reachinbox.local",
      avatar: ""
    };
  }

  return null;
}

// ==========================================
// CREATE DEMO USER
// ==========================================

async function ensureDemoUser() {
  await pool.execute(
    `INSERT INTO users (id, name, email)
     VALUES (1, 'Local Demo User', 'demo@reachinbox.local')
     ON DUPLICATE KEY UPDATE name = name`
  );
}

// ==========================================
// HEALTH CHECK
// ==========================================

app.get("/health", (_req, res) => {
  res.json({
    ok: true,
    message: "ReachInbox API is running"
  });
});

// ==========================================
// GOOGLE OAUTH LOGIN
// ==========================================

app.get("/auth/google", (req, res, next) => {
  if (!config.googleId) {
    return res
      .status(503)
      .send("Google OAuth is not configured");
  }

  passport.authenticate("google", {
    scope: ["profile", "email"]
  })(req, res, next);
});

// ==========================================
// GOOGLE OAUTH CALLBACK
// ==========================================

app.get(
  "/auth/google/callback",
  passport.authenticate("google", {
    failureRedirect: `${config.frontendUrl}/?login=failed`
  }),
  (_req, res) => {
    res.redirect(config.frontendUrl);
  }
);

// ==========================================
// GET CURRENT USER
// ==========================================

app.get("/auth/me", (req, res) => {
  res.json({
    user: currentUser(req)
  });
});

// ==========================================
// LOGOUT
// ==========================================

app.post("/auth/logout", (req, res) => {
  req.logout((error) => {
    if (error) {
      console.error("Logout error:", error);

      return res.status(500).json({
        error: "Unable to logout"
      });
    }

    req.session.destroy((sessionError) => {
      if (sessionError) {
        console.error("Session destroy error:", sessionError);

        return res.status(500).json({
          error: "Unable to destroy session"
        });
      }

      res.clearCookie("connect.sid", {
        httpOnly: true,
        sameSite:
          process.env.NODE_ENV === "production"
            ? "none"
            : "lax",
        secure: process.env.NODE_ENV === "production"
      });

      res.json({
        ok: true,
        message: "Logged out successfully"
      });
    });
  });
});

// ==========================================
// SLACK OAUTH
// ==========================================

app.get("/auth/slack", (req, res) => {
  if (!config.slackId) {
    return res
      .status(503)
      .send("Slack OAuth is not configured");
  }

  const state = randomUUID();

  (req.session as any).slackState = state;

  const url = new URL(
    "https://slack.com/oauth/v2/authorize"
  );

  url.searchParams.set("client_id", config.slackId);
  url.searchParams.set("scope", "chat:write");
  url.searchParams.set("redirect_uri", config.slackCallback);
  url.searchParams.set("state", state);

  res.redirect(url.toString());
});

// ==========================================
// SLACK OAUTH CALLBACK
// ==========================================

app.get("/auth/slack/callback", async (req, res) => {
  try {
    if (
      req.query.state !==
      (req.session as any).slackState
    ) {
      return res.status(400).send("Invalid OAuth state");
    }

    const tokenResult = await axios.post(
      "https://slack.com/api/oauth.v2.access",
      null,
      {
        params: {
          code: req.query.code,
          client_id: config.slackId,
          client_secret: config.slackSecret,
          redirect_uri: config.slackCallback
        }
      }
    );

    if (!tokenResult.data.ok) {
      console.error("Slack token error:", tokenResult.data);

      return res.status(400).send(
        "Slack authorization failed"
      );
    }

    const accessToken = tokenResult.data.access_token;
    const user = currentUser(req);

    if (accessToken && user) {
      await pool.execute(
        "UPDATE users SET slack_access_token = ? WHERE id = ?",
        [accessToken, user.id]
      );
    }

    delete (req.session as any).slackState;

    res.redirect(config.frontendUrl);
  } catch (error) {
    console.error("Slack OAuth error:", error);

    res.status(500).send("Slack connection failed");
  }
});

// ==========================================
// SCHEDULE EMAILS
// ==========================================

app.post("/api/emails/schedule", async (req, res) => {
  const user = currentUser(req);

  if (!user) {
    return res.status(401).json({
      error: "Please log in"
    });
  }

  const {
    recipients,
    subject,
    body,
    startAt,
    delaySeconds = 0,
    hourlyLimit
  } = req.body;

  if (
    !Array.isArray(recipients) ||
    recipients.length === 0 ||
    !subject ||
    !body ||
    !startAt
  ) {
    return res.status(400).json({
      error:
        "recipients, subject, body and startAt are required"
    });
  }

  // Validate email addresses
  const valid = recipients
    .map((x: unknown) => String(x).trim())
    .filter((x: string) =>
      /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(x)
    );

  if (valid.length === 0) {
    return res.status(400).json({
      error: "No valid email addresses found"
    });
  }

  const start = new Date(startAt);

  if (Number.isNaN(start.getTime())) {
    return res.status(400).json({
      error: "Invalid startAt date"
    });
  }

  try {
    const ids: number[] = [];

    for (let i = 0; i < valid.length; i++) {
      const recipient = valid[i];

      const scheduledAt = new Date(
        start.getTime() +
          i * Math.max(0, Number(delaySeconds)) * 1000
      );

      const key = `${user.id}:${recipient}:${randomUUID()}`;

      // Save email in MySQL
      const [result]: any = await pool.execute(
        `INSERT INTO emails
         (user_id, recipient, subject, body, scheduled_at, status, idempotency_key)
         VALUES (?, ?, ?, ?, ?, 'scheduled', ?)`,
        [
          user.id,
          recipient,
          subject,
          body,
          scheduledAt,
          key
        ]
      );

      const id = Number(result.insertId);

      ids.push(id);

      // Add email job to BullMQ
      await emailQueue.add(
        "send-email",
        {
          emailId: id,
          hourlyLimit: Number(
            hourlyLimit || config.hourlyLimit
          )
        },
        {
          jobId: `email-${id}`,
          delay: Math.max(
            0,
            scheduledAt.getTime() - Date.now()
          )
        }
      );

      // Index email in Elasticsearch
      await indexEmail({
        id,
        user_id: user.id,
        recipient,
        subject,
        body,
        status: "scheduled",
        scheduled_at: scheduledAt
      });
    }

    res.status(201).json({
      message: "Emails scheduled",
      count: ids.length,
      ids
    });
  } catch (error) {
    console.error("Email scheduling error:", error);

    res.status(500).json({
      error: "Unable to schedule emails"
    });
  }
});

// ==========================================
// GET EMAILS
// ==========================================

app.get("/api/emails", async (req, res) => {
  const user = currentUser(req);

  if (!user) {
    return res.status(401).json({
      error: "Please log in"
    });
  }

  const status = String(req.query.status || "");

  const allowed = [
    "scheduled",
    "processing",
    "sent",
    "failed"
  ];

  const params: any[] = [user.id];

  let sql = `
    SELECT
      id,
      recipient,
      subject,
      scheduled_at,
      sent_at,
      status,
      error_message
    FROM emails
    WHERE user_id = ?
  `;

  if (allowed.includes(status)) {
    sql += " AND status = ?";
    params.push(status);
  }

  sql += " ORDER BY created_at DESC LIMIT 500";

  try {
    const [rows] = await pool.execute(sql, params);

    res.json(rows);
  } catch (error) {
    console.error("Get emails error:", error);

    res.status(500).json({
      error: "Unable to fetch emails"
    });
  }
});

// ==========================================
// SEARCH EMAILS USING ELASTICSEARCH
// ==========================================

app.get("/api/emails/search", async (req, res) => {
  const user = currentUser(req);

  if (!user) {
    return res.status(401).json({
      error: "Please log in"
    });
  }

  const q = String(req.query.q || "").trim();

  if (!q) {
    return res.json([]);
  }

  try {
    const result = await es.search({
      index: "reachinbox-emails",
      query: {
        bool: {
          must: [
            {
              multi_match: {
                query: q,
                fields: ["recipient", "subject", "body"]
              }
            }
          ],
          filter: [
            {
              term: {
                user_id: user.id
              }
            }
          ]
        }
      }
    });

    res.json(
      result.hits.hits.map((hit: any) => hit._source)
    );
  } catch (error) {
    console.error("Email search error:", error);

    res.status(503).json({
      error: "Search service is unavailable"
    });
  }
});

// ==========================================
// START SERVER AND BULL BOARD
// ==========================================

async function start() {
  try {
    // Initialize database
    await initDb();

    // Create demo user in development only
    if (process.env.NODE_ENV !== "production") {
      await ensureDemoUser();
    }

    // Configure Bull Board
    const board = new ExpressAdapter();

    board.setBasePath("/admin/queues");

    createBullBoard({
      queues: [
        new BullMQAdapter(emailQueue)
      ],
      serverAdapter: board
    });

    app.use("/admin/queues", board.getRouter());

    // Start server
    app.listen(config.port, () => {
      console.log(
        `API running on port ${config.port}`
      );

      console.log(
        `Bull Board running at /admin/queues`
      );

      console.log(
        `Environment: ${process.env.NODE_ENV}`
      );
    });
  } catch (error) {
    console.error("Server startup failed:", error);
    process.exit(1);
  }
}

start();

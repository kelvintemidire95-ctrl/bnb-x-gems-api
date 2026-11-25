
const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

// BNB X GEMS ADMIN
const ADMIN_ID = "8251220398";

// Keep your bot token private in Render Environment Variables.
const BOT_TOKEN = process.env.BOT_TOKEN;

app.use(express.json({ limit: "1mb" }));

// Allow your separate frontend to connect.
const FRONTEND_URL = process.env.FRONTEND_URL || "*";
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", FRONTEND_URL);
  res.header("Access-Control-Allow-Headers", "Content-Type, X-Telegram-Init-Data");
  res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

// DATA STORAGE
const DATA_FILE = process.env.DATA_FILE || path.join(__dirname, "data.json");

const defaultDB = {
  users: {},
  tasks: {},
  withdrawals: {},
  settings: {
    taskReward: 10,
    referralReward: 5,
    bonusReward: 10,
    minimumWithdraw: 100,
    maximumWithdraw: 10000,
    withdrawalFee: 0,
    currency: "GEMS"
  }
};

function loadDB() {
  try {
    if (!fs.existsSync(DATA_FILE)) {
      fs.writeFileSync(DATA_FILE, JSON.stringify(defaultDB, null, 2));
    }

    const saved = JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));

    return {
      ...defaultDB,
      ...saved,
      users: saved.users || {},
      tasks: saved.tasks || {},
      withdrawals: saved.withdrawals || {},
      settings: { ...defaultDB.settings, ...(saved.settings || {}) }
    };
  } catch (error) {
    console.error("Database loading error:", error.message);
    return JSON.parse(JSON.stringify(defaultDB));
  }
}

let db = loadDB();

function saveDB() {
  const tempFile = DATA_FILE + ".tmp";
  fs.writeFileSync(tempFile, JSON.stringify(db, null, 2));
  fs.renameSync(tempFile, DATA_FILE);
}

function makeId() {
  return crypto.randomUUID();
}

function number(value, fallback = 0) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function getUser(id) {
  if (!db.users[id]) {
    db.users[id] = {
      id: String(id),
      firstName: "",
      username: "",
      balance: 0,
      wallet: "",
      referrals: [],
      referralEarnings: 0,
      totalWithdrawn: 0,
      completedTasks: [],
      createdAt: new Date().toISOString()
    };
  }

  return db.users[id];
}

// TELEGRAM MINI APP AUTHENTICATION
function verifyTelegramInitData(initData) {
  if (!BOT_TOKEN) {
    throw new Error("BOT_TOKEN is missing from Render Environment Variables.");
  }

  if (!initData || typeof initData !== "string") {
    throw new Error("Telegram authentication data is missing.");
  }

  const params = new URLSearchParams(initData);
  const receivedHash = params.get("hash");

  if (!receivedHash) {
    throw new Error("Invalid Telegram authentication data.");
  }

  params.delete("hash");

  const authDate = Number(params.get("auth_date") || 0);

  if (!authDate || Date.now() / 1000 - authDate > 86400) {
    throw new Error("Telegram login has expired. Please reopen the app.");
  }

  const dataCheckString = [...params.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, value]) => `${key}=${value}`)
    .join("\n");

  const secretKey = crypto
    .createHmac("sha256", "WebAppData")
    .update(BOT_TOKEN)
    .digest();

  const calculatedHash = crypto
    .createHmac("sha256", secretKey)
    .update(dataCheckString)
    .digest("hex");

  const received = Buffer.from(receivedHash, "hex");
  const calculated = Buffer.from(calculatedHash, "hex");

  if (
    received.length !== calculated.length ||
    !crypto.timingSafeEqual(received, calculated)
  ) {
    throw new Error("Telegram authentication failed.");
  }

  const userData = params.get("user");

  if (!userData) {
    throw new Error("Telegram user information is missing.");
  }

  return {
    user: JSON.parse(userData),
    startParam: params.get("start_param") || ""
  };
}

// AUTHENTICATION MIDDLEWARE
app.use("/api", (req, res, next) => {
  if (req.path === "/health") return next();

  try {
    const initData =
      req.headers["x-telegram-init-data"] ||
      (req.body && req.body.initData);

    const verified = verifyTelegramInitData(initData);
    const telegramUser = verified.user;

    if (!telegramUser.id) {
      return res.status(401).json({ error: "Invalid Telegram user." });
    }

    req.userId = String(telegramUser.id);
    req.telegramUser = telegramUser;
    req.startParam = verified.startParam;

    const user = getUser(req.userId);

    user.firstName = telegramUser.first_name || "";
    user.username = telegramUser.username || "";

    // Register a referral only when the user is first created.
    if (!user.referralRegistered && req.startParam) {
      const referrerId = req.startParam.replace(/^ref_/, "");

      if (
        /^\d+$/.test(referrerId) &&
        referrerId !== req.userId &&
        db.users[referrerId]
      ) {
        const referrer = getUser(referrerId);

        if (!referrer.referrals.includes(req.userId)) {
          referrer.referrals.push(req.userId);

          const reward = number(db.settings.referralReward);
          referrer.balance += reward;
          referrer.referralEarnings += reward;
        }
      }

      user.referralRegistered = true;
    }

    saveDB();
    next();
  } catch (error) {
    return res.status(401).json({ error: error.message });
  }
});

function requireAdmin(req, res, next) {
  if (String(req.userId) !== ADMIN_ID) {
    return res.status(403).json({ error: "Admin access denied." });
  }

  next();
}

// BOT INFORMATION
let botInfoCache = null;

async function getBotInfo() {
  if (botInfoCache) return botInfoCache;

  if (!BOT_TOKEN) return { name: "BNB X GEMS", username: "" };

  try {
    const response = await fetch(
      `https://api.telegram.org/bot${BOT_TOKEN}/getMe`
    );

    const result = await response.json();

    if (result.ok) {
      botInfoCache = {
        name: result.result.first_name,
        username: result.result.username
      };

      return botInfoCache;
    }
  } catch (error) {
    console.error("Bot information error:", error.message);
  }

  return { name: "BNB X GEMS", username: "" };
}

// HEALTH CHECK
app.get("/api/health", (req, res) => {
  res.json({ success: true, service: "BNB X GEMS API" });
});

// USER DASHBOARD
app.get("/api/me", async (req, res) => {
  const user = getUser(req.userId);
  const bot = await getBotInfo();

  res.json({
    success: true,
    user,
    settings: db.settings,
    bot,
    isAdmin: req.userId === ADMIN_ID
  });
});

// USER TASKS
app.get("/api/tasks", (req, res) => {
  const user = getUser(req.userId);

  const tasks = Object.values(db.tasks).map(task => ({
    ...task,
    completed: user.completedTasks.includes(task.id)
  }));

  res.json({ success: true, tasks });
});

// CLAIM TASK
app.post("/api/tasks/:id/claim", (req, res) => {
  const user = getUser(req.userId);
  const task = db.tasks[req.params.id];

  if (!task) {
    return res.status(404).json({ error: "Task not found." });
  }

  if (user.completedTasks.includes(task.id)) {
    return res.status(400).json({ error: "You already claimed this task." });
  }

  const reward = number(task.reward, number(db.settings.taskReward));

  user.balance += reward;
  user.completedTasks.push(task.id);

  saveDB();

  res.json({
    success: true,
    message: "Task reward added.",
    balance: user.balance
  });
});

// REFERRAL INFORMATION
app.get("/api/referrals", async (req, res) => {
  const user = getUser(req.userId);
  const bot = await getBotInfo();

  const referralLink = bot.username
    ? `https://t.me/${bot.username}?startapp=ref_${req.userId}`
    : "";

  res.json({
    success: true,
    referrals: user.referrals.length,
    earnings: user.referralEarnings,
    referralLink
  });
});

// SET WALLET
app.post("/api/wallet", (req, res) => {
  const wallet = String(req.body.wallet || "").trim();

  if (wallet.length < 10 || wallet.length > 150) {
    return res.status(400).json({ error: "Please enter a valid wallet address." });
  }

  const user = getUser(req.userId);
  user.wallet = wallet;

  saveDB();

  res.json({ success: true, message: "Wallet saved.", wallet });
});

// WITHDRAWAL HISTORY
app.get("/api/withdrawals", (req, res) => {
  const withdrawals = Object.values(db.withdrawals)
    .filter(item => item.userId === req.userId)
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

  res.json({ success: true, withdrawals });
});

// REQUEST WITHDRAWAL
function createWithdrawal(req, res) {
  const user = getUser(req.userId);
  const amount = number(req.body.amount, -1);
  const settings = db.settings;

  const minimum = number(settings.minimumWithdraw);
  const maximum = number(settings.maximumWithdraw);
  const fee = number(settings.withdrawalFee);

  if (!user.wallet) {
    return res.status(400).json({ error: "Set your wallet address first." });
  }

  if (!Number.isFinite(amount) || amount <= 0) {
    return res.status(400).json({ error: "Enter a valid withdrawal amount." });
  }

  if (amount < minimum || amount > maximum) {
    return res.status(400).json({
      error: `Withdrawal must be between ${minimum} and ${maximum} GEMS.`
    });
  }

  if (user.balance < amount + fee) {
    return res.status(400).json({ error: "Insufficient GEMS balance." });
  }

  user.balance -= amount + fee;

  const id = makeId();

  db.withdrawals[id] = {
    id,
    userId: req.userId,
    username: user.username,
    firstName: user.firstName,
    wallet: user.wallet,
    amount,
    fee,
    status: "pending",
    transactionHash: "",
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  };

  saveDB();

  res.json({
    success: true,
    message: "Withdrawal request sent to admin for manual review.",
    withdrawal: db.withdrawals[id],
    balance: user.balance
  });
}

app.post("/api/withdraw", createWithdrawal);
app.post("/api/withdrawals", createWithdrawal);

// ADMIN OVERVIEW
app.get("/api/admin/overview", requireAdmin, (req, res) => {
  const users = Object.values(db.users);
  const withdrawals = Object.values(db.withdrawals);

  res.json({
    success: true,
    totalUsers: users.length,
    totalTasks: Object.keys(db.tasks).length,
    pendingWithdrawals: withdrawals.filter(w => w.status === "pending").length,
    totalWithdrawals: withdrawals.length,
    totalGems: users.reduce((sum, user) => sum + number(user.balance), 0),
    settings: db.settings
  });
});

// ADMIN: LIST USERS
app.get("/api/admin/users", requireAdmin, (req, res) => {
  res.json({ success: true, users: Object.values(db.users) });
});

// ADMIN: ADD TASK
app.post("/api/admin/tasks", requireAdmin, (req, res) => {
  const title = String(req.body.title || "").trim();
  const description = String(req.body.description || "").trim();
  const link = String(req.body.link || "").trim();
  const reward = number(req.body.reward, number(db.settings.taskReward));

  if (!title || !link || reward < 0) {
    return res.status(400).json({ error: "Enter a title, link and valid reward." });
  }

  const id = makeId();

  db.tasks[id] = {
    id,
    title,
    description,
    link,
    reward,
    createdAt: new Date().toISOString()
  };

  saveDB();

  res.json({ success: true, task: db.tasks[id] });
});

// ADMIN: DELETE TASK
app.delete("/api/admin/tasks/:id", requireAdmin, (req, res) => {
  if (!db.tasks[req.params.id]) {
    return res.status(404).json({ error: "Task not found." });
  }

  delete db.tasks[req.params.id];
  saveDB();

  res.json({ success: true, message: "Task deleted." });
});

// ADMIN: LIST WITHDRAWALS
app.get("/api/admin/withdrawals", requireAdmin, (req, res) => {
  const withdrawals = Object.values(db.withdrawals)
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

  res.json({ success: true, withdrawals });
});

// ADMIN: REVIEW WITHDRAWAL
// Approving does NOT send money. Payment is sent manually by the admin.
app.post("/api/admin/withdrawals/:id/review", requireAdmin, (req, res) => {
  const withdrawal = db.withdrawals[req.params.id];

  if (!withdrawal) {
    return res.status(404).json({ error: "Withdrawal not found." });
  }

  const action = String(req.body.action || "").toLowerCase();

  if (withdrawal.status === "paid" || withdrawal.status === "rejected") {
    return res.status(400).json({ error: "This withdrawal has already been closed." });
  }

  if (action === "approve") {
    if (withdrawal.status !== "pending") {
      return res.status(400).json({ error: "Withdrawal is not pending." });
    }

    withdrawal.status = "approved";
    withdrawal.updatedAt = new Date().toISOString();
    withdrawal.adminNote = "Approved for manual payment.";
  } else if (action === "reject") {
    const user = getUser(withdrawal.userId);

    user.balance += withdrawal.amount + withdrawal.fee;
    withdrawal.status = "rejected";
    withdrawal.updatedAt = new Date().toISOString();
    withdrawal.adminNote = String(req.body.note || "Withdrawal rejected.");
  } else if (action === "paid") {
    if (withdrawal.status !== "approved") {
      return res.status(400).json({
        error: "Approve this request before marking it as paid."
      });
    }

    const transactionHash = String(req.body.transactionHash || "").trim();

    if (!transactionHash) {
      return res.status(400).json({
        error: "Enter the transaction hash for the manual payment."
      });
    }

    withdrawal.status = "paid";
    withdrawal.transactionHash = transactionHash;
    withdrawal.updatedAt = new Date().toISOString();

    const user = getUser(withdrawal.userId);
    user.totalWithdrawn += withdrawal.amount;
  } else {
    return res.status(400).json({
      error: "Action must be approve, reject or paid."
    });
  }

  saveDB();

  res.json({
    success: true,
    message: `Withdrawal ${withdrawal.status}.`,
    withdrawal
  });
});

// ADMIN: UPDATE SETTINGS
app.put("/api/admin/settings", requireAdmin, (req, res) => {
  const allowed = [
    "taskReward",
    "referralReward",
    "bonusReward",
    "minimumWithdraw",
    "maximumWithdraw",
    "withdrawalFee"
  ];

  for (const key of allowed) {
    if (req.body[key] !== undefined) {
      const value = number(req.body[key], NaN);

      if (!Number.isFinite(value) || value < 0) {
        return res.status(400).json({ error: `Invalid setting: ${key}` });
      }

      db.settings[key] = value;
    }
  }

  saveDB();

  res.json({ success: true, settings: db.settings });
});

// ADMIN: GIVE USER A BONUS
app.post("/api/admin/bonus", requireAdmin, (req, res) => {
  const targetId = String(req.body.userId || "");
  const amount = number(req.body.amount, -1);

  if (!db.users[targetId]) {
    return res.status(404).json({ error: "User not found." });
  }

  if (amount <= 0) {
    return res.status(400).json({ error: "Enter a valid bonus amount." });
  }

  db.users[targetId].balance += amount;
  saveDB();

  res.json({
    success: true,
    message: "Bonus added.",
    balance: db.users[targetId].balance
  });
});

// START SERVER
app.listen(PORT, () => {
  console.log(`BNB X GEMS API running on port ${PORT}`);
});

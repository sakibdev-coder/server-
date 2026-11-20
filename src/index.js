import "dotenv/config";
import bcrypt from "bcryptjs";
import cors from "cors";
import express from "express";
import { OAuth2Client } from "google-auth-library";
import jwt from "jsonwebtoken";
import mongoose from "mongoose";

const app = express();
const port = process.env.PORT || 5000;
const allowedOrigins = (process.env.CLIENT_URL || "http://localhost:3000")
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);
const jwtSecret = process.env.JWT_SECRET;
const googleClient = process.env.GOOGLE_CLIENT_ID ? new OAuth2Client(process.env.GOOGLE_CLIENT_ID) : null;

app.use(cors({
  origin(origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error("Origin is not allowed by the API CORS policy."));
  }
}));
app.use(express.json());

const equipmentSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  category: { type: String, required: true },
  location: { type: String, required: true },
  price: { type: Number, required: true, min: 0 },
  rating: { type: Number, default: 5 },
  image: { type: String, required: true },
  ownerId: { type: mongoose.Schema.Types.ObjectId, ref: "User" }
}, { timestamps: true });

const bookingSchema = new mongoose.Schema({
  equipmentId: { type: mongoose.Schema.Types.ObjectId, ref: "Equipment", required: true },
  renterName: { type: String, required: true, trim: true },
  renterEmail: { type: String, required: true, trim: true },
  startDate: { type: Date, required: true },
  endDate: { type: Date, required: true },
  status: { type: String, enum: ["pending", "accepted", "declined"], default: "pending" }
}, { timestamps: true });

const userSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  photo: { type: String, default: "" },
  passwordHash: { type: String },
  googleId: { type: String },
  role: { type: String, enum: ["Customer", "Owner", "Admin"], default: "Customer" }
}, { timestamps: true });

const Equipment = mongoose.model("Equipment", equipmentSchema);
const Booking = mongoose.model("Booking", bookingSchema);
const User = mongoose.model("User", userSchema);

function createToken(user) {
  if (!jwtSecret) throw new Error("JWT_SECRET is not configured.");
  return jwt.sign({ sub: user._id.toString(), role: user.role }, jwtSecret, { expiresIn: "7d" });
}

function serializeUser(user) {
  return { id: user._id.toString(), name: user.name, email: user.email, photo: user.photo, role: user.role };
}

function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header?.startsWith("Bearer ")) return res.status(401).json({ message: "Authentication is required." });
  try {
    if (!jwtSecret) return res.status(500).json({ message: "JWT_SECRET is not configured." });
    const payload = jwt.verify(header.slice(7), jwtSecret);
    req.auth = payload;
    return next();
  } catch { return res.status(401).json({ message: "Your session is invalid or expired." }); }
}

function requireRoles(...roles) {
  return (req, res, next) => roles.includes(req.auth?.role)
    ? next() : res.status(403).json({ message: "You do not have permission for this action." });
}

app.get("/api/health", (_req, res) => res.json({
  status: "ok",
  service: "equiply-api",
  database: mongoose.connection.readyState === 1 ? "connected" : "demo"
}));

app.post("/api/auth/register", async (req, res, next) => {
  try {
    const { name, email, photo, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ message: "Name, email, and password are required." });
    if (password.length < 6) return res.status(400).json({ message: "Password must be at least 6 characters." });
    if (mongoose.connection.readyState !== 1) return res.status(503).json({ message: "Registration requires a database connection." });
    const normalizedEmail = email.toLowerCase().trim();
    if (await User.exists({ email: normalizedEmail })) return res.status(409).json({ message: "An account with this email already exists." });
    const user = await User.create({ name: name.trim(), email: normalizedEmail, photo: photo || "", passwordHash: await bcrypt.hash(password, 12) });
    return res.status(201).json({ token: createToken(user), user: serializeUser(user) });
  } catch (error) { return next(error); }
});

app.post("/api/auth/login", async (req, res, next) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: "Email and password are required." });
    if (mongoose.connection.readyState !== 1) return res.status(503).json({ message: "Login requires a database connection." });
    const user = await User.findOne({ email: email.toLowerCase().trim() });
    if (!user?.passwordHash || !(await bcrypt.compare(password, user.passwordHash))) return res.status(401).json({ message: "Invalid email or password." });
    return res.json({ token: createToken(user), user: serializeUser(user) });
  } catch (error) { return next(error); }
});

app.post("/api/auth/google", async (req, res, next) => {
  try {
    if (!googleClient || !process.env.GOOGLE_CLIENT_ID) return res.status(503).json({ message: "Google login is not configured yet." });
    const { credential } = req.body;
    if (!credential) return res.status(400).json({ message: "Google credential is required." });
    const ticket = await googleClient.verifyIdToken({ idToken: credential, audience: process.env.GOOGLE_CLIENT_ID });
    const profile = ticket.getPayload();
    if (!profile?.email || !profile.email_verified) return res.status(401).json({ message: "Google account email could not be verified." });
    let user = await User.findOne({ email: profile.email.toLowerCase() });
    if (!user) user = await User.create({ name: profile.name || "Equiply customer", email: profile.email.toLowerCase(), photo: profile.picture || "", googleId: profile.sub, role: "Customer" });
    return res.json({ token: createToken(user), user: serializeUser(user) });
  } catch (error) { return next(error); }
});

app.get("/api/auth/me", authMiddleware, async (req, res, next) => {
  try {
    if (mongoose.connection.readyState !== 1) return res.status(503).json({ message: "Profile service is not connected to the database." });
    const user = await User.findById(req.auth.sub);
    if (!user) return res.status(404).json({ message: "User account was not found." });
    return res.json({ user: serializeUser(user) });
  } catch (error) { return next(error); }
});

app.get("/api/equipment", async (_req, res, next) => {
  try {
    if (mongoose.connection.readyState !== 1) return res.json([]);
    const items = await Equipment.find().sort({ createdAt: -1 }).limit(50);
    return res.json(items);
  } catch (error) { return next(error); }
});

app.post("/api/bookings", authMiddleware, requireRoles("Customer", "Owner", "Admin"), async (req, res, next) => {
  try {
    const { equipmentId, renterName, renterEmail, startDate, endDate } = req.body;
    if (!equipmentId || !renterName || !renterEmail || !startDate || !endDate) return res.status(400).json({ message: "All booking fields are required." });
    if (new Date(endDate) <= new Date(startDate)) return res.status(400).json({ message: "Return date must be after pick-up date." });
    if (mongoose.connection.readyState !== 1) return res.status(503).json({ message: "Booking service is not connected to the database." });
    const booking = await Booking.create({ equipmentId, renterName, renterEmail, startDate, endDate });
    return res.status(201).json(booking);
  } catch (error) { return next(error); }
});

app.get("/api/owner/dashboard", authMiddleware, requireRoles("Owner", "Admin"), async (_req, res) => {
  res.json({ message: "Owner dashboard access granted." });
});

app.use("/api", (_req, res) => res.status(404).json({ message: "API route not found." }));

app.use((error, _req, res, _next) => {
  console.error(error);
  if (error.message === "Origin is not allowed by the API CORS policy.") {
    return res.status(403).json({ message: error.message });
  }
  return res.status(500).json({ message: "Something went wrong on the server." });
});

async function start() {
  if (process.env.MONGODB_URI) {
    try { await mongoose.connect(process.env.MONGODB_URI); console.log("Connected to MongoDB"); }
    catch (error) { console.error("MongoDB connection failed:", error.message); process.exitCode = 1; return; }
  } else console.warn("MONGODB_URI is not set; API is running in demo mode.");
  app.listen(port, () => console.log(`Equiply API listening on port ${port}`));
}

start();

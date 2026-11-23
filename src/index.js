import "dotenv/config";
import bcrypt from "bcryptjs";
import cors from "cors";
import express from "express";
import { OAuth2Client } from "google-auth-library";
import jwt from "jsonwebtoken";
import mongoose from "mongoose";
import Stripe from "stripe";
import { fromNodeHeaders, toNodeHandler } from "better-auth/node";
import { betterAuthInstance, betterAuthMongoClient } from "./better-auth.js";

const app = express();
const port = process.env.PORT || 5001;
const configuredOrigins = (process.env.CLIENT_URL || "").split(",").map((x) => x.trim()).filter(Boolean);
const vercelUrl = process.env.VERCEL_URL ? `https://${process.env.VERCEL_URL}` : null;
const allowedOrigins = new Set([
  "http://localhost:3000",
  "http://localhost:3001",
  "http://127.0.0.1:3000",
  "http://127.0.0.1:3001",
  ...configuredOrigins,
  ...(process.env.BETTER_AUTH_URL ? [process.env.BETTER_AUTH_URL] : []),
  ...(vercelUrl ? [vercelUrl] : [])
]);
const clientAppUrl = configuredOrigins[0] || "http://localhost:3000";
const jwtSecret = process.env.JWT_SECRET;
const googleClient = process.env.GOOGLE_CLIENT_ID ? new OAuth2Client(process.env.GOOGLE_CLIENT_ID) : null;
const stripe = process.env.STRIPE_SECRET_KEY ? new Stripe(process.env.STRIPE_SECRET_KEY) : null;

app.use(cors({
  origin(origin, callback) {
    if (!origin || allowedOrigins.has(origin)) return callback(null, true);
    callback(new Error("Origin is not allowed"));
  },
  credentials: true
}));
const betterAuthHandler = toNodeHandler(betterAuthInstance);
app.all("/api/better-auth", betterAuthHandler);
app.all("/api/better-auth/*", betterAuthHandler);
app.use(express.json({ limit: "2mb" }));

const userSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true }, email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  photo: { type: String, default: "" }, phone: { type: String, default: "" }, address: { type: String, default: "" },
  passwordHash: String, googleId: String, role: { type: String, enum: ["Customer", "Owner", "Admin"], default: "Customer" }
}, { timestamps: true });

const equipmentSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true }, description: { type: String, default: "" },
  category: { type: String, required: true }, location: { type: String, required: true },
  price: { type: Number, required: true, min: 0 }, rentalType: { type: String, enum: ["Daily", "Weekly", "Monthly"], default: "Daily" },
  quantity: { type: Number, required: true, min: 1 }, condition: { type: String, default: "Good" }, brand: String, model: String,
  image: { type: String, required: true }, terms: { type: String, default: "" },
  status: { type: String, enum: ["Pending", "Approved", "Rejected"], default: "Pending" },
  ownerId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true }, rating: { type: Number, default: 5 }
}, { timestamps: true });

const bookingSchema = new mongoose.Schema({
  customerId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  ownerId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  equipmentId: { type: mongoose.Schema.Types.ObjectId, ref: "Equipment", required: true },
  startDate: { type: Date, required: true }, endDate: { type: Date, required: true }, quantity: { type: Number, required: true, min: 1 },
  contactNumber: String, deliveryAddress: String, notes: String, totalAmount: { type: Number, required: true, min: 0 },
  paymentStatus: { type: String, enum: ["Pending", "Paid", "Failed"], default: "Pending" },
  bookingStatus: { type: String, enum: ["Pending", "Confirmed", "Rejected", "Completed"], default: "Pending" },
  transactionId: String, paymentProvider: { type: String, default: "Stripe" }
}, { timestamps: true });

const favoriteSchema = new mongoose.Schema({
  customerId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  equipmentId: { type: mongoose.Schema.Types.ObjectId, ref: "Equipment", required: true }
}, { timestamps: true });
favoriteSchema.index({ customerId: 1, equipmentId: 1 }, { unique: true });

const paymentSchema = new mongoose.Schema({
  bookingId: { type: mongoose.Schema.Types.ObjectId, ref: "Booking" }, customerId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  amount: Number, currency: { type: String, default: "usd" }, stripeSessionId: String, transactionId: String,
  status: { type: String, enum: ["Pending", "Paid", "Failed"], default: "Pending" }
}, { timestamps: true });

const reviewSchema = new mongoose.Schema({
  customerId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  equipmentId: { type: mongoose.Schema.Types.ObjectId, ref: "Equipment", required: true },
  rating: { type: Number, min: 1, max: 5, required: true }, comment: { type: String, required: true }
}, { timestamps: true });

const User = mongoose.model("User", userSchema);
const Equipment = mongoose.model("Equipment", equipmentSchema);
const Booking = mongoose.model("Booking", bookingSchema);
const Favorite = mongoose.model("Favorite", favoriteSchema);
const Payment = mongoose.model("Payment", paymentSchema);
const Review = mongoose.model("Review", reviewSchema);

function verifyToken(req, res, next) {
  const token = req.headers.authorization?.startsWith("Bearer ") ? req.headers.authorization.slice(7) : null;
  if (!token) return res.status(401).json({ message: "Authentication is required." });
  try { if (!jwtSecret) return res.status(500).json({ message: "JWT_SECRET is not configured." }); req.auth = jwt.verify(token, jwtSecret); next(); }
  catch { res.status(401).json({ message: "Your session is invalid or expired." }); }
}
function verifyRenter(req, res, next) { return req.auth?.role === "Customer" ? next() : res.status(403).json({ message: "Customer access required." }); }
function verifyOwner(req, res, next) { return ["Owner", "Admin"].includes(req.auth?.role) ? next() : res.status(403).json({ message: "Owner access required." }); }
function verifyAdmin(req, res, next) { return req.auth?.role === "Admin" ? next() : res.status(403).json({ message: "Admin access required." }); }
function tokenFor(user) { if (!jwtSecret) throw new Error("JWT_SECRET is not configured."); return jwt.sign({ sub: user._id.toString(), role: user.role }, jwtSecret, { expiresIn: "7d" }); }
function publicUser(user) { return { id: user._id.toString(), name: user.name, email: user.email, photo: user.photo, phone: user.phone, address: user.address, role: user.role, createdAt: user.createdAt }; }
function connected(res) { if (mongoose.connection.readyState !== 1) { res.status(503).json({ message: "MongoDB is not connected." }); return false; } return true; }

app.get("/", (req, res) => {
  const clientOrigin = (process.env.CLIENT_URL || "").split(",")[0]?.trim();
  if (req.query.error && clientOrigin) {
    const error = encodeURIComponent(String(req.query.error));
    return res.redirect(`${clientOrigin}/login?error=${error}`);
  }
  return res.json({
    name: "Equiply API",
    status: "ok",
    health: "/api/health",
    docs: "Use /api/* routes from the client app."
  });
});
app.get("/api/health", (_req, res) => res.json({ status: "ok", database: mongoose.connection.readyState === 1 ? "connected" : "demo" }));

app.post("/api/auth/register", async (req, res, next) => {
  try {
    const { name, email, photo, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ message: "Name, email and password are required." });
    if (password.length < 6) return res.status(400).json({ message: "Password must be at least 6 characters." });
    if (!/[A-Z]/.test(password)) return res.status(400).json({ message: "Password must include an uppercase letter." });
    if (!/[a-z]/.test(password)) return res.status(400).json({ message: "Password must include a lowercase letter." });
    if (!connected(res)) return;
    const normalized = email.toLowerCase().trim();
    if (await User.exists({ email: normalized })) return res.status(409).json({ message: "An account with this email already exists." });
    const user = await User.create({ name: name.trim(), email: normalized, photo: photo || "", passwordHash: await bcrypt.hash(password, 12) });
    res.status(201).json({ token: tokenFor(user), user: publicUser(user) });
  } catch (error) { next(error); }
});
app.post("/api/auth/login", async (req, res, next) => {
  try {
    if (!connected(res)) return;
    const user = await User.findOne({ email: req.body.email?.toLowerCase().trim() });
    if (!user?.passwordHash || !(await bcrypt.compare(req.body.password || "", user.passwordHash))) return res.status(401).json({ message: "Invalid email or password." });
    res.json({ token: tokenFor(user), user: publicUser(user) });
  } catch (error) { next(error); }
});
app.post("/api/auth/google", async (req, res, next) => {
  try {
    if (!googleClient) return res.status(503).json({ message: "Google login is not configured." });
    const ticket = await googleClient.verifyIdToken({ idToken: req.body.credential, audience: process.env.GOOGLE_CLIENT_ID });
    const profile = ticket.getPayload();
    if (!profile?.email || !profile.email_verified) return res.status(401).json({ message: "Google email could not be verified." });
    let user = await User.findOne({ email: profile.email.toLowerCase() });
    if (!user) user = await User.create({ name: profile.name || "Equiply customer", email: profile.email.toLowerCase(), photo: profile.picture || "", googleId: profile.sub, role: "Customer" });
    res.json({ token: tokenFor(user), user: publicUser(user) });
  } catch (error) { next(error); }
});
app.get("/api/auth/google-session", async (req, res, next) => {
  try {
    if (!connected(res)) return;
    const session = await betterAuthInstance.api.getSession({
      headers: fromNodeHeaders(req.headers)
    });
    if (!session?.user?.email) return res.status(401).json({ message: "Google session not found." });
    const email = session.user.email.toLowerCase();
    let user = await User.findOne({ email });
    if (!user) {
      // Google social sign-up always starts as Customer per assignment RBAC rules.
      user = await User.create({
        name: session.user.name || "Equiply customer",
        email,
        photo: session.user.image || "",
        googleId: session.user.id,
        role: "Customer"
      });
    } else {
      const sync = {};
      if (!user.googleId && session.user.id) sync.googleId = session.user.id;
      if (!user.photo && session.user.image) sync.photo = session.user.image;
      if (Object.keys(sync).length) user = await User.findByIdAndUpdate(user._id, sync, { new: true });
    }
    res.json({ token: tokenFor(user), user: publicUser(user) });
  } catch (error) { next(error); }
});
app.get("/api/auth/me", verifyToken, async (req, res) => {
  if (!connected(res)) return;
  const user = await User.findById(req.auth.sub);
  if (!user) return res.status(404).json({ message: "User not found." });
  res.json({ user: publicUser(user) });
});
app.put("/api/profile", verifyToken, async (req, res) => {
  if (!connected(res)) return;
  const allowed = ["name", "photo", "phone", "address"];
  const update = {};
  for (const key of allowed) if (typeof req.body[key] === "string") update[key] = req.body[key].trim();
  if (!update.name) return res.status(400).json({ message: "Name is required." });
  const user = await User.findByIdAndUpdate(req.auth.sub, update, { new: true, runValidators: true });
  if (!user) return res.status(404).json({ message: "User not found." });
  res.json({ user: publicUser(user) });
});

app.get("/api/equipment", async (req, res) => {
  if (!connected(res)) return;
  const { search, category, rentalType, minPrice, maxPrice, availability, sort } = req.query;
  const filter = { status: "Approved" };
  if (search) {
    filter.$or = [
      { name: { $regex: search, $options: "i" } },
      { location: { $regex: search, $options: "i" } },
      { category: { $regex: search, $options: "i" } }
    ];
  }
  if (category && category !== "All equipment") filter.category = category;
  if (rentalType && rentalType !== "All") filter.rentalType = rentalType;
  if (minPrice || maxPrice) filter.price = { ...(minPrice && { $gte: Number(minPrice) }), ...(maxPrice && { $lte: Number(maxPrice) }) };
  if (availability === "Available") filter.quantity = { $gt: 0 };
  if (availability === "Unavailable") filter.quantity = { $lte: 0 };
  const sortOption = sort === "priceAsc" ? { price: 1 } : sort === "priceDesc" ? { price: -1 } : { createdAt: -1 };
  const [items, total] = await Promise.all([
    Equipment.find(filter).populate("ownerId", "name photo").sort(sortOption).limit(100),
    Equipment.countDocuments(filter)
  ]);
  res.json({ items, total });
});
app.get("/api/equipment/featured", async (_req, res) => {
  if (!connected(res)) return;
  res.json(await Equipment.find({ status: "Approved" }).populate("ownerId", "name").sort({ rating: -1, createdAt: -1 }).limit(6));
});
app.get("/api/equipment/:id", async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.id)) return res.status(404).json({ message: "Equipment not found." });
  if (!connected(res)) return;
  const item = await Equipment.findById(req.params.id).populate("ownerId", "name email photo");
  if (!item) return res.status(404).json({ message: "Equipment not found." });
  res.json(item);
});
app.post("/api/equipment", verifyToken, verifyOwner, async (req, res) => {
  if (!connected(res)) return;
  const { name, description, category, location, price, rentalType, quantity, condition, brand, model, image, terms } = req.body;
  if (!name || !category || !location || price == null || !quantity || !image) {
    return res.status(400).json({ message: "Name, category, location, price, quantity and image are required." });
  }
  const item = await Equipment.create({
    name: String(name).trim(),
    description: description ? String(description).trim() : "",
    category,
    location: String(location).trim(),
    price: Number(price),
    rentalType: rentalType || "Daily",
    quantity: Number(quantity),
    condition: condition || "Good",
    brand: brand ? String(brand).trim() : "",
    model: model ? String(model).trim() : "",
    image: String(image).trim(),
    terms: terms ? String(terms).trim() : "",
    ownerId: req.auth.sub,
    status: "Pending"
  });
  res.status(201).json(item);
});
app.put("/api/equipment/:id", verifyToken, async (req, res) => {
  if (!connected(res)) return;
  const item = await Equipment.findById(req.params.id);
  if (!item) return res.status(404).json({ message: "Equipment not found." });
  if (item.ownerId.toString() !== req.auth.sub && req.auth.role !== "Admin") return res.status(403).json({ message: "Permission denied." });
  const allowed = ["name", "description", "category", "location", "price", "rentalType", "quantity", "condition", "brand", "model", "image", "terms"];
  for (const key of allowed) {
    if (req.body[key] === undefined) continue;
    if (key === "price" || key === "quantity") item[key] = Number(req.body[key]);
    else item[key] = typeof req.body[key] === "string" ? req.body[key].trim() : req.body[key];
  }
  if (req.auth.role !== "Admin") item.status = "Pending";
  await item.save(); res.json(item);
});
app.delete("/api/equipment/:id", verifyToken, async (req, res) => {
  if (!connected(res)) return;
  const item = await Equipment.findById(req.params.id);
  if (!item) return res.status(404).json({ message: "Equipment not found." });
  if (item.ownerId.toString() !== req.auth.sub && req.auth.role !== "Admin") return res.status(403).json({ message: "Permission denied." });
  await item.deleteOne(); res.json({ message: "Equipment deleted." });
});
app.get("/api/owner/equipment", verifyToken, verifyOwner, async (req, res) => {
  if (!connected(res)) return;
  res.json(await Equipment.find({ ownerId: req.auth.sub }).sort({ createdAt: -1 }));
});

app.post("/api/favorites/:equipmentId", verifyToken, verifyRenter, async (req, res) => {
  if (!connected(res)) return;
  await Favorite.findOneAndUpdate({ customerId: req.auth.sub, equipmentId: req.params.equipmentId }, {}, { upsert: true, new: true });
  res.status(201).json({ message: "Added to favorites." });
});
app.delete("/api/favorites/:equipmentId", verifyToken, async (req, res) => {
  await Favorite.findOneAndDelete({ customerId: req.auth.sub, equipmentId: req.params.equipmentId });
  res.json({ message: "Removed from favorites." });
});
app.get("/api/favorites", verifyToken, verifyRenter, async (req, res) => {
  if (!connected(res)) return;
  res.json(await Favorite.find({ customerId: req.auth.sub }).populate("equipmentId").sort({ createdAt: -1 }));
});

app.post("/api/bookings", verifyToken, verifyRenter, async (req, res) => {
  if (!connected(res)) return;
  const { equipmentId, startDate, endDate, quantity, contactNumber, deliveryAddress, notes } = req.body;
  if (!equipmentId || !startDate || !endDate || !quantity || !contactNumber || !deliveryAddress) {
    return res.status(400).json({ message: "Equipment, dates, quantity, contact number and delivery address are required." });
  }
  const start = new Date(startDate);
  const end = new Date(endDate);
  if (Number.isNaN(start.getTime()) || Number.isNaN(end.getTime()) || end < start) {
    return res.status(400).json({ message: "Please provide a valid rental date range." });
  }
  const equipment = await Equipment.findById(equipmentId);
  if (!equipment || equipment.status !== "Approved") return res.status(404).json({ message: "Approved equipment not found." });
  if (Number(quantity) < 1 || Number(quantity) > equipment.quantity) return res.status(400).json({ message: "Requested quantity is not available." });
  const overlap = await Booking.countDocuments({ equipmentId, paymentStatus: "Paid", bookingStatus: { $ne: "Rejected" }, startDate: { $lt: end }, endDate: { $gt: start } });
  if (overlap > 0) return res.status(409).json({ message: "Equipment is unavailable for the selected dates." });
  const days = Math.max(1, Math.ceil((end - start) / 86400000));
  const unitDays = equipment.rentalType === "Monthly" ? 30 : equipment.rentalType === "Weekly" ? 7 : 1;
  const totalAmount = equipment.price * Math.ceil(days / unitDays) * Number(quantity);
  const booking = await Booking.create({
    customerId: req.auth.sub,
    ownerId: equipment.ownerId,
    equipmentId,
    startDate: start,
    endDate: end,
    quantity: Number(quantity),
    contactNumber: String(contactNumber).trim(),
    deliveryAddress: String(deliveryAddress).trim(),
    notes: notes ? String(notes).trim() : "",
    totalAmount
  });
  res.status(201).json(booking);
});
app.get("/api/customer/rentals", verifyToken, verifyRenter, async (req, res) => {
  if (!connected(res)) return;
  res.json(await Booking.find({ customerId: req.auth.sub }).populate("equipmentId").populate("ownerId", "name").sort({ createdAt: -1 }));
});
app.get("/api/owner/rentals", verifyToken, verifyOwner, async (req, res) => {
  if (!connected(res)) return;
  res.json(await Booking.find({ ownerId: req.auth.sub }).populate("equipmentId").populate("customerId", "name email phone").sort({ createdAt: -1 }));
});

app.post("/api/payments/checkout", verifyToken, verifyRenter, async (req, res) => {
  if (!stripe) return res.status(503).json({ message: "Stripe is not configured." });
  if (!connected(res)) return;
  const booking = await Booking.findById(req.body.bookingId).populate("equipmentId");
  if (!booking) return res.status(404).json({ message: "Booking not found." });
  if (booking.customerId.toString() !== req.auth.sub) return res.status(403).json({ message: "Permission denied." });
  const session = await stripe.checkout.sessions.create({
    mode: "payment",
    success_url: `${clientAppUrl}/payment/success?session_id={CHECKOUT_SESSION_ID}`,
    cancel_url: `${clientAppUrl}/payment/cancel?bookingId=${booking._id.toString()}`,
    customer_email: (await User.findById(req.auth.sub)).email,
    line_items: [{
      quantity: 1,
      price_data: {
        currency: "usd",
        unit_amount: Math.round(booking.totalAmount * 100),
        product_data: { name: booking.equipmentId.name }
      }
    }],
    metadata: { bookingId: booking._id.toString(), customerId: req.auth.sub }
  });
  await Payment.create({ bookingId: booking._id, customerId: req.auth.sub, amount: booking.totalAmount, stripeSessionId: session.id, status: "Pending" });
  res.json({ url: session.url, sessionId: session.id });
});
app.post("/api/payments/verify", verifyToken, verifyRenter, async (req, res) => {
  if (!stripe) return res.status(503).json({ message: "Stripe is not configured." });
  const session = await stripe.checkout.sessions.retrieve(req.body.sessionId);
  if (session.payment_status !== "paid") return res.status(400).json({ message: "Payment is not complete." });
  const booking = await Booking.findById(session.metadata.bookingId);
  if (!booking) return res.status(404).json({ message: "Booking not found." });
  booking.paymentStatus = "Paid"; booking.bookingStatus = "Confirmed"; booking.transactionId = session.payment_intent?.toString() || session.id;
  await booking.save();
  await Payment.findOneAndUpdate({ stripeSessionId: session.id }, { status: "Paid", transactionId: booking.transactionId });
  res.json({ booking, status: "paid" });
});

app.get("/api/admin/users", verifyToken, verifyAdmin, async (_req, res) => {
  if (!connected(res)) return;
  const users = await User.find().sort({ createdAt: -1 });
  res.json(users.map(publicUser));
});
app.put("/api/admin/users/:id/role", verifyToken, verifyAdmin, async (req, res) => {
  if (!connected(res)) return;
  if (!["Customer", "Owner", "Admin"].includes(req.body.role)) return res.status(400).json({ message: "Invalid role." });
  if (req.params.id === req.auth.sub && req.body.role !== "Admin") {
    return res.status(400).json({ message: "You cannot remove your own admin role." });
  }
  const user = await User.findByIdAndUpdate(req.params.id, { role: req.body.role }, { new: true });
  if (!user) return res.status(404).json({ message: "User not found." });
  res.json(publicUser(user));
});
app.get("/api/admin/equipment", verifyToken, verifyAdmin, async (_req, res) => {
  if (!connected(res)) return;
  res.json(await Equipment.find().populate("ownerId", "name email").sort({ createdAt: -1 }));
});
app.put("/api/admin/equipment/:id/status", verifyToken, verifyAdmin, async (req, res) => {
  if (!connected(res)) return;
  if (!["Pending", "Approved", "Rejected"].includes(req.body.status)) return res.status(400).json({ message: "Invalid status." });
  const item = await Equipment.findByIdAndUpdate(req.params.id, { status: req.body.status }, { new: true });
  if (!item) return res.status(404).json({ message: "Equipment not found." });
  res.json(item);
});
app.get("/api/admin/rentals", verifyToken, verifyAdmin, async (_req, res) => {
  if (!connected(res)) return;
  res.json(await Booking.find().populate("customerId", "name email").populate("ownerId", "name email").populate("equipmentId").sort({ createdAt: -1 }));
});

app.get("/api/admin/analytics", verifyToken, verifyAdmin, async (_req, res) => {
  if (!connected(res)) return;
  const since = new Date(Date.now() - 180 * 24 * 60 * 60 * 1000);
  const [totalUsers, totalEquipment, totalBookings, pendingApprovals, completedRentals, paidPayments, monthlyBookings, monthlyRevenue] = await Promise.all([
    User.countDocuments(),
    Equipment.countDocuments(),
    Booking.countDocuments(),
    Equipment.countDocuments({ status: "Pending" }),
    Booking.countDocuments({ bookingStatus: "Completed" }),
    Payment.aggregate([{ $match: { status: "Paid" } }, { $group: { _id: null, total: { $sum: "$amount" } } }]),
    Booking.aggregate([
      { $match: { createdAt: { $gte: since } } },
      { $group: { _id: { year: { $year: "$createdAt" }, month: { $month: "$createdAt" } }, bookings: { $sum: 1 } } },
      { $sort: { "_id.year": 1, "_id.month": 1 } },
      { $project: { _id: 0, month: { $concat: [{ $toString: "$_id.year" }, "-", { $toString: "$_id.month" }] }, bookings: 1 } }
    ]),
    Payment.aggregate([
      { $match: { status: "Paid", createdAt: { $gte: since } } },
      { $group: { _id: { year: { $year: "$createdAt" }, month: { $month: "$createdAt" } }, revenue: { $sum: "$amount" } } },
      { $sort: { "_id.year": 1, "_id.month": 1 } },
      { $project: { _id: 0, month: { $concat: [{ $toString: "$_id.year" }, "-", { $toString: "$_id.month" }] }, revenue: 1 } }
    ])
  ]);
  res.json({
    totalUsers, totalEquipment, totalBookings, pendingApprovals, completedRentals,
    totalRevenue: paidPayments[0]?.total || 0,
    monthlyBookings,
    monthlyRevenue
  });
});

app.get("/api/owner/analytics", verifyToken, verifyOwner, async (req, res) => {
  if (!connected(res)) return;
  const ownerId = new mongoose.Types.ObjectId(req.auth.sub);
  const [listedEquipment, completedRentals, paidSummary, monthlyEarnings] = await Promise.all([
    Equipment.countDocuments({ ownerId }),
    Booking.countDocuments({ ownerId, bookingStatus: "Completed" }),
    Payment.aggregate([
      { $match: { status: "Paid" } },
      { $lookup: { from: "bookings", localField: "bookingId", foreignField: "_id", as: "booking" } },
      { $unwind: "$booking" },
      { $match: { "booking.ownerId": ownerId } },
      { $group: { _id: null, total: { $sum: "$amount" } } }
    ]),
    Payment.aggregate([
      { $match: { status: "Paid", createdAt: { $gte: new Date(Date.now() - 180 * 24 * 60 * 60 * 1000) } } },
      { $lookup: { from: "bookings", localField: "bookingId", foreignField: "_id", as: "booking" } },
      { $unwind: "$booking" },
      { $match: { "booking.ownerId": ownerId } },
      { $group: { _id: { year: { $year: "$createdAt" }, month: { $month: "$createdAt" } }, earnings: { $sum: "$amount" } } },
      { $sort: { "_id.year": 1, "_id.month": 1 } },
      { $project: { _id: 0, month: { $concat: [{ $toString: "$_id.year" }, "-", { $toString: "$_id.month" }] }, earnings: 1 } }
    ])
  ]);
  res.json({
    listedEquipment,
    completedRentals,
    totalEarnings: paidSummary[0]?.total || 0,
    monthlyEarnings
  });
});

app.use("/api", (_req, res) => res.status(404).json({ message: "API route not found." }));
app.use((error, _req, res, _next) => { console.error(error); res.status(error.message === "Origin is not allowed" ? 403 : 500).json({ message: error.message === "Origin is not allowed" ? error.message : "Something went wrong." }); });

async function start() {
  if (process.env.MONGODB_URI) {
    try {
      await mongoose.connect(process.env.MONGODB_URI);
      if (betterAuthMongoClient) await betterAuthMongoClient.connect();
      console.log("Connected to MongoDB");
    } catch (error) { console.error(error.message); process.exit(1); }
  }
  app.listen(port, () => console.log(`Equiply API listening on ${port}`));
}
start();

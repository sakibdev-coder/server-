import "dotenv/config";
import cors from "cors";
import express from "express";
import mongoose from "mongoose";

const app = express();
const port = process.env.PORT || 5000;
const clientUrl = process.env.CLIENT_URL || "http://localhost:3000";

app.use(cors({ origin: clientUrl }));
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

const Equipment = mongoose.model("Equipment", equipmentSchema);
const Booking = mongoose.model("Booking", bookingSchema);

app.get("/api/health", (_req, res) => res.json({ status: "ok", service: "equiply-api" }));

app.get("/api/equipment", async (_req, res, next) => {
  try {
    if (mongoose.connection.readyState !== 1) return res.json([]);
    const items = await Equipment.find().sort({ createdAt: -1 }).limit(50);
    return res.json(items);
  } catch (error) { return next(error); }
});

app.post("/api/bookings", async (req, res, next) => {
  try {
    const { equipmentId, renterName, renterEmail, startDate, endDate } = req.body;
    if (!equipmentId || !renterName || !renterEmail || !startDate || !endDate) return res.status(400).json({ message: "All booking fields are required." });
    if (new Date(endDate) <= new Date(startDate)) return res.status(400).json({ message: "Return date must be after pick-up date." });
    if (mongoose.connection.readyState !== 1) return res.status(503).json({ message: "Booking service is not connected to the database." });
    const booking = await Booking.create({ equipmentId, renterName, renterEmail, startDate, endDate });
    return res.status(201).json(booking);
  } catch (error) { return next(error); }
});

app.use((error, _req, res, _next) => {
  console.error(error);
  res.status(500).json({ message: "Something went wrong on the server." });
});

async function start() {
  if (process.env.MONGODB_URI) {
    try { await mongoose.connect(process.env.MONGODB_URI); console.log("Connected to MongoDB"); }
    catch (error) { console.error("MongoDB connection failed:", error.message); process.exitCode = 1; return; }
  } else console.warn("MONGODB_URI is not set; API is running in demo mode.");
  app.listen(port, () => console.log(`Equiply API listening on port ${port}`));
}

start();

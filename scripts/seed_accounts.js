import "dotenv/config";
import bcrypt from "bcryptjs";
import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  photo: { type: String, default: "" },
  phone: { type: String, default: "" },
  address: { type: String, default: "" },
  passwordHash: String,
  googleId: String,
  role: { type: String, enum: ["Customer", "Owner", "Admin"], default: "Customer" }
}, { timestamps: true });

const User = mongoose.models.User || mongoose.model("User", userSchema);

async function seed() {
  if (!process.env.MONGODB_URI) {
    console.error("MONGODB_URI missing in .env");
    process.exit(1);
  }

  await mongoose.connect(process.env.MONGODB_URI);
  console.log("Connected to MongoDB");

  const accounts = [
    {
      name: "Equiply Admin",
      email: "admin@equiply.test",
      password: "Admin123",
      role: "Admin",
      phone: "+8801600000000",
      address: "Dhaka, Bangladesh"
    },
    {
      name: "Equiply Admin",
      email: "admin@equiply.com",
      password: "Admin123",
      role: "Admin",
      phone: "+8801600000000",
      address: "Dhaka, Bangladesh"
    },
    {
      name: "Demo Owner",
      email: "owner@equiply.test",
      password: "Owner123",
      role: "Owner",
      phone: "+8801700000000",
      address: "Dhaka, Bangladesh"
    },
    {
      name: "Demo Owner",
      email: "owner@equiply.com",
      password: "Owner123",
      role: "Owner",
      phone: "+8801700000000",
      address: "Dhaka, Bangladesh"
    }
  ];

  for (const acc of accounts) {
    const existing = await User.findOne({ email: acc.email });
    const passwordHash = await bcrypt.hash(acc.password, 12);

    if (existing) {
      existing.name = acc.name;
      existing.role = acc.role;
      existing.passwordHash = passwordHash;
      existing.phone = acc.phone;
      existing.address = acc.address;
      await existing.save();
      console.log(`Updated existing account: ${acc.email} (${acc.role})`);
    } else {
      await User.create({
        name: acc.name,
        email: acc.email,
        passwordHash,
        role: acc.role,
        phone: acc.phone,
        address: acc.address
      });
      console.log(`Created new account: ${acc.email} (${acc.role})`);
    }
  }

  console.log("\nAll accounts verified & ready!");
  await mongoose.disconnect();
}

seed().catch(err => {
  console.error("Seed error:", err);
  process.exit(1);
});

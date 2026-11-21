import "dotenv/config";
import { betterAuth } from "better-auth";
import { mongodbAdapter } from "@better-auth/mongo-adapter";
import { jwt } from "better-auth/plugins";
import { MongoClient } from "mongodb";

const mongoUri = process.env.MONGODB_URI;
export const betterAuthMongoClient = mongoUri ? new MongoClient(mongoUri) : null;

export const betterAuthInstance = betterAuth({
  secret: process.env.BETTER_AUTH_SECRET || process.env.JWT_SECRET,
  baseURL: process.env.BETTER_AUTH_URL,
  basePath: "/api/better-auth",
  trustedOrigins: [
    "http://localhost:3000",
    "http://localhost:5001",
    ...(process.env.CLIENT_URL || "").split(",").map((origin) => origin.trim())
  ].filter(Boolean),
  database: betterAuthMongoClient
    ? mongodbAdapter(betterAuthMongoClient.db(process.env.MONGODB_DATABASE || "equiply"), {
        client: betterAuthMongoClient
      })
    : undefined,
  emailAndPassword: {
    enabled: true,
    requireEmailVerification: false
  },
  socialProviders: process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET
    ? {
        google: {
          clientId: process.env.GOOGLE_CLIENT_ID,
          clientSecret: process.env.GOOGLE_CLIENT_SECRET
        }
      }
    : {},
  user: {
    additionalFields: {
      role: {
        type: "string",
        required: false,
        defaultValue: "Customer",
        input: false
      },
      phone: { type: "string", required: false, defaultValue: "" },
      address: { type: "string", required: false, defaultValue: "" }
    }
  },
  plugins: [jwt()]
});

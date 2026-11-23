import "dotenv/config";
import { betterAuth } from "better-auth";
import { mongodbAdapter } from "@better-auth/mongo-adapter";
import { jwt } from "better-auth/plugins";
import { MongoClient } from "mongodb";

const mongoUri = process.env.MONGODB_URI;
export const betterAuthMongoClient = mongoUri ? new MongoClient(mongoUri) : null;
const vercelUrl = process.env.VERCEL_URL ? `https://${process.env.VERCEL_URL}` : null;
const betterAuthUrl = process.env.BETTER_AUTH_URL || vercelUrl;
const configuredOrigins = (process.env.CLIENT_URL || "")
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);
const localOrigins = [
  "http://localhost:3000",
  "http://localhost:3001",
  "http://127.0.0.1:3000",
  "http://127.0.0.1:3001"
];

const isProd = process.env.NODE_ENV === "production" || Boolean(process.env.VERCEL);
const primaryClient = configuredOrigins[0];

export const betterAuthInstance = betterAuth({
  secret: process.env.BETTER_AUTH_SECRET || process.env.JWT_SECRET,
  baseURL: betterAuthUrl,
  basePath: "/api/better-auth",
  trustedOrigins: [
    ...localOrigins,
    ...configuredOrigins,
    ...(betterAuthUrl ? [betterAuthUrl] : []),
    ...(vercelUrl ? [vercelUrl] : [])
  ],
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
  advanced: {
    defaultCookieAttributes: {
      sameSite: isProd ? "none" : "lax",
      secure: isProd,
      partitioned: isProd
    }
  },
  onAPIError: {
    errorURL: primaryClient ? `${primaryClient}/login` : undefined
  },
  plugins: [jwt()]
});

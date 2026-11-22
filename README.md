# Equiply Server

**Project name:** Equiply — Equipment Rental Platform API  
**Purpose:** Express + MongoDB backend for authentication, equipment listings, bookings, Stripe payments, favorites, and role-based admin/owner/customer APIs.

## Live URL

- Local: [http://localhost:5001](http://localhost:5001)
- Health check: [http://localhost:5001/api/health](http://localhost:5001/api/health)
- Production: _Add your deployed server URL here after hosting (Vercel/Railway recommended)._

## Key Features

- Email/password registration and login with JWT
- Google social login via BetterAuth + app user bridge (default Customer role)
- RBAC middlewares: `verifyToken`, `verifyRenter`, `verifyOwner`, `verifyAdmin`
- Equipment CRUD with Pending / Approved / Rejected workflow
- Server-side equipment search, filter, sort, and featured limit (6)
- Booking creation with availability checks and total amount calculation
- Stripe Checkout + payment verification into `payments` collection
- Favorites, profile updates, owner analytics, admin analytics
- CORS-safe multi-origin support for local and production clients

## Tech Stack / NPM Packages

- `express` — HTTP API
- `mongoose`, `mongodb` — database and BetterAuth adapter access
- `dotenv` — environment configuration
- `cors` — cross-origin requests
- `bcryptjs` — password hashing
- `jsonwebtoken` — access tokens
- `better-auth`, `@better-auth/mongo-adapter` — Google social auth
- `google-auth-library` — Google ID token verification path
- `stripe` — secure payment checkout

## Environment Variables

Copy `.env.example` to `.env`:

```env
PORT=5001
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/equiply
MONGODB_DATABASE=equiply
CLIENT_URL=http://localhost:3000
JWT_SECRET=replace-with-a-long-random-secret
BETTER_AUTH_SECRET=replace-with-another-long-random-secret
BETTER_AUTH_URL=http://localhost:5001
GOOGLE_CLIENT_ID=your-google-oauth-client-id
GOOGLE_CLIENT_SECRET=your-google-oauth-client-secret
STRIPE_SECRET_KEY=sk_test_...
```

## Getting Started

```bash
npm install
npm run dev
```

API base: `http://localhost:5001/api`

## Main API Groups

- Auth: `/api/auth/register`, `/login`, `/google`, `/google-session`, `/me`
- Profile: `PUT /api/profile`
- Equipment: `/api/equipment`, `/featured`, `/:id`
- Favorites: `/api/favorites`
- Bookings / rentals: `/api/bookings`, `/customer/rentals`, `/owner/rentals`
- Payments: `/api/payments/checkout`, `/verify`
- Owner: `/api/owner/equipment`, `/owner/analytics`
- Admin: `/api/admin/users`, `/admin/equipment`, `/admin/rentals`, `/admin/analytics`
- BetterAuth: `/api/better-auth/*`

## Scripts

- `npm run dev` — watch mode
- `npm start` — production start

## Security Notes

- MongoDB credentials and Stripe/Google secrets stay in `.env`
- Password rules: uppercase + lowercase + minimum 6 characters
- Private routes require Bearer JWT
- Admin cannot demote their own Admin role by accident

# 🔐 Passwordless Auth Demo

Simple passwordless authentication with Node.js, Prisma, and magic links.

## Quick Start

1. **Install dependencies**
   ```bash
   npm install
   ```

2. **Set up environment**
   ```bash
   cp env.example .env
   # Edit .env with your Gmail and database credentials
   ```

3. **Setup database**
   ```bash
   npx prisma generate
   npx prisma migrate dev --name init
   ```

4. **Start server**
   ```bash
   npm run dev
   ```

## API Endpoints

- `POST /api/auth/signup` - Create account
- `POST /api/auth/login` - Send login link  
- `GET /api/auth/verify` - Verify magic link
- `POST /api/auth/logout` - Logout
- `GET /api/me` - Get current user

## Environment Variables

```env
DATABASE_URL="your-database-url"
JWT_SECRET="your-jwt-secret"
EMAIL_USER="your-gmail@gmail.com"
EMAIL_PASS="your-app-password"
BASE_URL="http://localhost:3000"
PORT=5000
```

## Features

- ✅ Magic link authentication
- ✅ JWT tokens with HTTP-only cookies
- ✅ Gmail SMTP integration
- ✅ Prisma ORM
- ✅ Auto cleanup of expired tokens 
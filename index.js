// CORE NODE.JS MODULES
import crypto from "crypto"; // For generating secure random tokens

// THIRD-PARTY LIBRARIES
import express from "express"; // Web framework for building APIs
import jwt from "jsonwebtoken"; // For creating and verifying JWT tokens
import nodemailer from "nodemailer"; // For sending emails
import cookieParser from "cookie-parser"; // For parsing cookies
import cors from "cors"; // For handling Cross-Origin Resource Sharing

// DATABASE & CONFIGURATION
import { PrismaClient } from "@prisma/client"; // Database ORM client
import dotenv from "dotenv"; // For loading environment variables

// Load environment variables from .env file
dotenv.config();

// DATABASE INITIALIZATION
const prisma = new PrismaClient();
const app = express();

// Middleware
app.use(express.json());
app.use(cookieParser());

app.use(
  cors({
    origin: process.env.FRONTEND_BASE_URL,
    credentials: true,
  })
);

// ==========================================
// EMAIL FUNCTION
// ==========================================

const sendMagicLinkEmail = async (email, name, magicLinkUrl) => {
  // EMAIL CONFIGURATION
  const transporter = nodemailer.createTransport({
    service: "gmail",
    host: "smtp.gmail.com",
    port: 465,
    secure: true,
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });

  const mailOptions = {
    from: process.env.EMAIL_FROM || process.env.EMAIL_USER,
    to: email,
    subject: "Your Login Link",
    text: `Hi${name ? ` ${name}` : ""}!

Click this link to log in: ${magicLinkUrl}

This link expires in 15 minutes.

If you didn't request this, please ignore this email.`,
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log(`Magic link sent to ${email}`);
  } catch (error) {
    console.error("Email sending failed:", error);
    throw new Error("Failed to send email");
  }
};

// ==========================================
// SIGNUP ENDPOINT
// ==========================================

app.post("/api/auth/signup", async (req, res) => {
  try {
    const { email, name } = req.body;

    // Validate input
    if (!email || !email.includes("@")) {
      return res.status(400).json({
        success: false,
        message: "Valid email is required",
      });
    }

    // Check if user exists
    let user = await prisma.user.findUnique({
      where: { email },
    });

    if (user && user.verified) {
      return res.status(409).json({
        success: false,
        message: "Account already exists and verified",
      });
    }

    // Generate magic link token
    const token = crypto.randomBytes(32).toString("hex");
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes

    if (user) {
      // Update existing unverified user
      user = await prisma.user.update({
        where: { email },
        data: {
          name: name || user.name,
          magicLinkToken: token,
          magicLinkExpires: expiresAt,
          magicLinkUsed: false,
        },
      });
    } else {
      // Create new user
      user = await prisma.user.create({
        data: {
          email,
          name,
          magicLinkToken: token,
          magicLinkExpires: expiresAt,
          magicLinkUsed: false,
        },
      });
    }

    // Send magic link email
    const magicLinkUrl = `${process.env.API_BASE_URL}/verify?token=${token}`;
    await sendMagicLinkEmail(email, name, magicLinkUrl);

    res.json({
      success: true,
      message: "Verification link sent to your email! Check your inbox.",
      data: {
        email: user.email,
        name: user.name,
      },
    });
  } catch (error) {
    console.error("Signup error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to create account. Please try again.",
    });
  }
});

// ==========================================
// LOGIN ENDPOINT
// ==========================================

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email } = req.body;

    // Validate input
    if (!email || !email.includes("@")) {
      return res.status(400).json({
        success: false,
        message: "Valid email is required",
      });
    }

    const user = await prisma.user.findUnique({
      where: { email },
    });

    if (!user || !user.verified) {
      return res.status(404).json({
        success: false,
        message: "No verified account found with this email",
      });
    }

    // Generate new magic link token
    const token = crypto.randomBytes(32).toString("hex");
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes

    await prisma.user.update({
      where: { email },
      data: {
        magicLinkToken: token,
        magicLinkExpires: expiresAt,
        magicLinkUsed: false,
      },
    });

    // Send magic link email
    const magicLinkUrl = `${process.env.API_BASE_URL}/verify?token=${token}`;
    await sendMagicLinkEmail(email, user.name, magicLinkUrl);

    res.json({
      success: true,
      message: "Login link sent to your email! Check your inbox.",
      data: {
        email: user.email,
        name: user.name,
      },
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to send login link. Please try again.",
    });
  }
});

// ==========================================
// VERIFICATION ENDPOINT
// ==========================================

app.get("/api/auth/verify", async (req, res) => {
  try {
    const { token } = req.query;

    if (!token) {
      return res.status(400).json({
        success: false,
        message: "Verification token is required",
      });
    }

    // Find user with valid token
    const user = await prisma.user.findFirst({
      where: {
        magicLinkToken: token,
        magicLinkUsed: false,
        magicLinkExpires: {
          gt: new Date(),
        },
      },
    });

    if (!user) {
      return res.status(400).json({
        success: false,
        message: "Invalid or expired verification link",
      });
    }

    // Mark user as verified and clear magic link
    const updatedUser = await prisma.user.update({
      where: { id: user.id },
      data: {
        verified: true,
        magicLinkToken: null,
        magicLinkExpires: null,
        magicLinkUsed: true,
      },
    });

    // Generate JWT token
    const jwtToken = jwt.sign(
      {
        userId: user.id,
        email: user.email,
        verified: true,
      },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    // Set HTTP-only cookie
    res.cookie("auth_token", jwtToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    // Redirect to success page or return JSON
    res.json({
      success: true,
      message: "Successfully authenticated! Welcome back!",
      data: {
        user: {
          id: updatedUser.id,
          email: updatedUser.email,
          name: updatedUser.name,
          verified: updatedUser.verified,
        },
      },
    });
  } catch (error) {
    console.error("Verification error:", error);
    res.status(500).json({
      success: false,
      message: "Verification failed. Please try again.",
    });
  }
});

// ==========================================
// RESEND VERIFICATION ENDPOINT
// ==========================================

app.post("/api/auth/resend-verification", async (req, res) => {
  try {
    const { email } = req.body;

    // Validate input
    if (!email || !email.includes("@")) {
      return res.status(400).json({
        success: false,
        message: "Valid email is required",
      });
    }

    const user = await prisma.user.findUnique({
      where: { email },
    });

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "No account found with this email",
      });
    }

    if (user.verified) {
      return res.status(400).json({
        success: false,
        message: "Account is already verified",
      });
    }

    // Generate new magic link token
    const token = crypto.randomBytes(32).toString("hex");
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes

    await prisma.user.update({
      where: { email },
      data: {
        magicLinkToken: token,
        magicLinkExpires: expiresAt,
        magicLinkUsed: false,
      },
    });

    // Send magic link email
    const magicLinkUrl = `${process.env.API_BASE_URL}/verify?token=${token}`;
    await sendMagicLinkEmail(email, user.name, magicLinkUrl);

    res.json({
      success: true,
      message: "New verification link sent to your email!",
      data: {
        email: user.email,
        name: user.name,
      },
    });
  } catch (error) {
    console.error("Resend verification error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to send verification link. Please try again.",
    });
  }
});

// ==========================================
// LOGOUT ENDPOINT
// ==========================================

app.post("/api/auth/logout", (req, res) => {
  res.clearCookie("auth_token");
  res.json({
    success: true,
    message: "Successfully logged out",
  });
});

// ==========================================
// GET CURRENT USER
// ==========================================

app.get("/api/me", async (req, res) => {
  try {
    const token = req.cookies.auth_token;

    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Authentication required",
      });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await prisma.user.findUnique({
      where: { id: decoded.userId },
    });

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "User not found",
      });
    }

    res.json({
      success: true,
      data: {
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          verified: user.verified,
          createdAt: user.createdAt,
        },
      },
    });
  } catch (error) {
    console.error("Profile error:", error);
    res.status(401).json({
      success: false,
      message: "Invalid token",
    });
  }
});

// ==========================================
// CLEANUP EXPIRED TOKENS
// ==========================================

const cleanupExpiredTokens = async () => {
  try {
    const result = await prisma.user.updateMany({
      where: {
        magicLinkExpires: {
          lt: new Date(),
        },
        magicLinkToken: {
          not: null,
        },
      },
      data: {
        magicLinkToken: null,
        magicLinkExpires: null,
        magicLinkUsed: false,
      },
    });

    if (result.count > 0) {
      console.log(`🧹 Cleaned up ${result.count} expired magic links`);
    }
  } catch (error) {
    console.error("Cleanup error:", error);
  }
};

// Run cleanup every hour
setInterval(cleanupExpiredTokens, 60 * 60 * 1000);

// ==========================================
// SERVER STARTUP
// ==========================================

app.listen(process.env.PORT, () => {
  console.log(
    `🚀 Passwordless Auth Server running on port ${process.env.PORT}`
  );
});

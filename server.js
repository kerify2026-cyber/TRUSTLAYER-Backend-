/**
 * TrustLayer Backend — single-file server for Render deployment
 * ----------------------------------------------------------------
 * This file merges everything that was provided:
 *   - db.js (Prisma/Neon client)
 *   - cloudinary.js, openai.js, mailer.js, stripe.js  (3rd party clients)
 *   - rateLimit.js, sanitize.js, logger.js, upload.js  (middleware)
 *   - auth.js, errorHandler.js                         (middleware)
 *   - app.js                                           (express app wiring)
 *   - server.js                                        (bootstrap)
 *
 * NOT included (not provided in the upload), stubbed instead:
 *   - routes/*.js  (authRoutes, userRoutes, scanRoutes, historyRoutes,
 *                   dashboardRoutes, subscriptionRoutes, webhookRoutes,
 *                   adminRoutes)
 *   - controllers/*.js backing those routes
 *   - utils/catchAsync.js, utils/AppError.js, utils/jwt.js
 *     (minimal, standard-pattern versions are reimplemented below so the
 *     app actually boots — swap in your real ones if they differ)
 *
 * Every stubbed route responds 501 with a clear message so you know
 * exactly what still needs wiring in. Search for "TODO:" to find them.
 * ----------------------------------------------------------------
 */

require('dotenv').config();

const path = require('path');
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const compression = require('compression');
const cookieParser = require('cookie-parser');
const morgan = require('morgan');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const xss = require('xss');
const multer = require('multer');

// ============================================================================
// utils/AppError.js  (minimal reimplementation — original not provided)
// ============================================================================
class AppError extends Error {
  constructor(message, statusCode) {
    super(message);
    this.statusCode = statusCode;
    this.isOperational = true;
    Error.captureStackTrace(this, this.constructor);
  }
}

// ============================================================================
// utils/catchAsync.js  (minimal reimplementation — original not provided)
// ============================================================================
const catchAsync = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

// ============================================================================
// utils/jwt.js  (minimal reimplementation — original not provided)
// ============================================================================
const signAccessToken = (payload) =>
  jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '15m' });

const signRefreshToken = (payload) =>
  jwt.sign(payload, process.env.JWT_REFRESH_SECRET, { expiresIn: '30d' });

const verifyAccessToken = (token) => jwt.verify(token, process.env.JWT_SECRET);

const verifyRefreshToken = (token) =>
  jwt.verify(token, process.env.JWT_REFRESH_SECRET);

// ============================================================================
// config/db.js — Prisma / Neon PostgreSQL client singleton
// ============================================================================
const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient({
  log: process.env.NODE_ENV === 'development' ? ['warn', 'error'] : ['error'],
});

const connectDB = async () => {
  try {
    await prisma.$connect();
    console.log('[Postgres/Prisma] Connected to Neon PostgreSQL');
  } catch (error) {
    console.error(`[Postgres/Prisma] Initial connection failed: ${error.message}`);
    process.exit(1);
  }
};

const disconnectDB = async () => {
  await prisma.$disconnect();
};

// ============================================================================
// config/cloudinary.js
// ============================================================================
const { v2: cloudinaryLib } = require('cloudinary');

cloudinaryLib.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
  secure: true,
});

// ============================================================================
// config/openai.js
// ============================================================================
const OpenAI = require('openai');

if (!process.env.OPENAI_API_KEY) {
  console.warn('[OpenAI] OPENAI_API_KEY is not set. AI scan endpoints will fail until it is configured.');
}

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

// ============================================================================
// config/mailer.js
// ============================================================================
const nodemailer = require('nodemailer');

const mailTransporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: Number(process.env.EMAIL_PORT) || 587,
  secure: Number(process.env.EMAIL_PORT) === 465,
  auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
});

mailTransporter.verify((error) => {
  if (error) console.warn('[Nodemailer] Transport verification failed:', error.message);
  else console.log('[Nodemailer] Ready to send emails.');
});

// ============================================================================
// config/stripe.js
// ============================================================================
const Stripe = require('stripe');

if (!process.env.STRIPE_SECRET_KEY) {
  console.warn('[Stripe] STRIPE_SECRET_KEY is not set. Subscription endpoints will fail until it is configured.');
}

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY, { apiVersion: '2024-06-20' });

// ============================================================================
// middleware/logger.js
// ============================================================================
const logsDir = path.join(process.cwd(), 'logs');
if (!fs.existsSync(logsDir)) fs.mkdirSync(logsDir, { recursive: true });

const accessLogPath = path.join(logsDir, 'access.log');
const accessLogStream = fs.createWriteStream(accessLogPath, { flags: 'a' });
const consoleLogger = morgan('dev');
const fileLogger = morgan('combined', { stream: accessLogStream });

const requestLogger = (req, res, next) => {
  fileLogger(req, res, () => {
    if (process.env.NODE_ENV !== 'production') return consoleLogger(req, res, next);
    next();
  });
};

const errorLogFile = path.join(logsDir, 'error.log');
const logErrorToFile = (err, req) => {
  const entry = `[${new Date().toISOString()}] ${req.method} ${req.originalUrl} - ${err.message}\n${err.stack}\n\n`;
  fs.appendFile(errorLogFile, entry, (writeErr) => {
    if (writeErr) console.error('[ErrorHandler] Failed to write error log:', writeErr.message);
  });
};

// ============================================================================
// middleware/sanitize.js
// ============================================================================
const sanitizeValue = (value) => {
  if (typeof value === 'string') return xss(value);
  if (Array.isArray(value)) return value.map(sanitizeValue);
  if (value && typeof value === 'object') {
    const clean = {};
    for (const key of Object.keys(value)) {
      clean[key] = sanitizeValue(value[key]);
    }
    return clean;
  }
  return value;
};

const sanitizeInputs = (req, res, next) => {
  if (req.body && typeof req.body === 'object') req.body = sanitizeValue(req.body);
  if (req.params && typeof req.params === 'object') {
    for (const key of Object.keys(req.params)) req.params[key] = sanitizeValue(req.params[key]);
  }
  // req.query is left untouched (read-only getter in newer Express versions);
  // query values are validated per-route via express-validator instead.
  next();
};

// ============================================================================
// middleware/rateLimit.js
// ============================================================================
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: 'Too many requests. Please try again later.' },
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: 'Too many auth attempts. Please try again later.' },
});

const scanLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 15,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: 'Scan rate limit exceeded. Please slow down.' },
});

// ============================================================================
// middleware/upload.js
// ============================================================================
const uploadStorage = multer.memoryStorage();
const ALLOWED_MIME_TYPES = ['image/jpeg', 'image/png', 'image/webp', 'image/gif'];

const upload = multer({
  storage: uploadStorage,
  fileFilter: (req, file, cb) => {
    if (!ALLOWED_MIME_TYPES.includes(file.mimetype)) {
      return cb(new AppError(`Unsupported file type: ${file.mimetype}`, 400));
    }
    cb(null, true);
  },
  limits: { fileSize: 8 * 1024 * 1024 },
});

// ============================================================================
// middleware/auth.js
// ============================================================================
const SAFE_USER_SELECT = {
  id: true,
  name: true,
  email: true,
  avatarUrl: true,
  avatarPublicId: true,
  verified: true,
  plan: true,
  scansRemaining: true,
  subscriptionStatus: true,
  stripeCustomerId: true,
  stripeSubscriptionId: true,
  role: true,
  createdAt: true,
  updatedAt: true,
};

const authenticate = catchAsync(async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return next(new AppError('Authentication required', 401));
  }
  const token = authHeader.split(' ')[1];
  let decoded;
  try {
    decoded = verifyAccessToken(token);
  } catch (err) {
    return next(new AppError('Invalid or expired token', 401));
  }
  const user = await prisma.user.findUnique({ where: { id: decoded.id }, select: SAFE_USER_SELECT });
  if (!user) return next(new AppError('User no longer exists', 401));
  req.user = user;
  next();
});

const optionalAuthenticate = catchAsync(async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) return next();
  const token = authHeader.split(' ')[1];
  try {
    const decoded = verifyAccessToken(token);
    const user = await prisma.user.findUnique({ where: { id: decoded.id }, select: SAFE_USER_SELECT });
    if (user) req.user = user;
  } catch (err) {
    // Invalid token on an optional route just means "treat as guest"
  }
  next();
});

const requireAdmin = (req, res, next) => {
  if (!req.user) return next(new AppError('Authentication required', 401));
  if (req.user.role !== 'admin') return next(new AppError('Admin access required', 403));
  next();
};

// ============================================================================
// middleware/errorHandler.js
// ============================================================================
const notFound = (req, res, next) => {
  next(new AppError(`Route not found: ${req.originalUrl}`, 404));
};

// Normalizes Prisma Client errors (Postgres) into AppError.
//   P2002 - unique constraint violation
//   P2025 - record not found for update/delete
//   P2003 - foreign key constraint violation
//   P2023 - malformed ID (e.g. invalid UUID passed as a lookup key)
const normalizeError = (err) => {
  if (err.name === 'PrismaClientKnownRequestError') {
    switch (err.code) {
      case 'P2002': {
        const field = Array.isArray(err.meta?.target) ? err.meta.target[0] : err.meta?.target || 'field';
        return new AppError(`Duplicate value for ${field}`, 409);
      }
      case 'P2025':
        return new AppError('Record not found', 404);
      case 'P2003':
        return new AppError('Related record not found', 400);
      case 'P2023':
        return new AppError('Invalid identifier format', 400);
      default:
        return new AppError('Database request error', 400);
    }
  }
  if (err.name === 'PrismaClientValidationError') {
    return new AppError('Invalid data provided to the database layer', 400);
  }
  if (err.name === 'JsonWebTokenError') return new AppError('Invalid token', 401);
  if (err.name === 'TokenExpiredError') return new AppError('Token expired', 401);
  if (err.name === 'MulterError') return new AppError(`Upload error: ${err.message}`, 400);
  return err;
};

const errorHandler = (err, req, res, next) => {
  const normalized = normalizeError(err);
  const statusCode = normalized.statusCode || 500;
  const isOperational = normalized.isOperational || false;
  if (!isOperational) console.error('[UNEXPECTED ERROR]', err);
  logErrorToFile(err, req);
  res.status(statusCode).json({
    success: false,
    message: isOperational ? normalized.message : 'Internal server error',
    ...(normalized.errors ? { errors: normalized.errors } : {}),
    ...(process.env.NODE_ENV === 'development' && !isOperational ? { stack: err.stack } : {}),
  });
};

// ============================================================================
// routes/* — STUBS
// ----------------------------------------------------------------------------
// TODO: The real routers (authRoutes, userRoutes, scanRoutes, historyRoutes,
// dashboardRoutes, subscriptionRoutes, webhookRoutes, adminRoutes) and the
// controllers behind them were not part of the upload, so they could not be
// merged. Each stub below responds 501 so misrouted requests are obvious
// instead of silently 404ing. Replace the router bodies with your real
// route handlers (you already have `prisma`, `stripe`, `openai`, `upload`,
// `mailTransporter`, `cloudinaryLib`, `authenticate`, `requireAdmin`,
// `catchAsync`, `AppError`, `authLimiter`, `scanLimiter`, etc. all in scope).
// ============================================================================
const notImplemented = (name) => (req, res) => {
  res.status(501).json({
    success: false,
    message: `TODO: ${name} route not implemented in this merged build. Wire up the real handler here.`,
  });
};

const authRoutes = express.Router();
authRoutes.all('*', notImplemented('auth'));

const userRoutes = express.Router();
userRoutes.all('*', notImplemented('user'));

const scanRoutes = express.Router(); // exposes /api/scan/* and /api/check/phone
scanRoutes.all('*', notImplemented('scan'));

const historyRoutes = express.Router();
historyRoutes.all('*', notImplemented('history'));

const dashboardRoutes = express.Router();
dashboardRoutes.all('*', notImplemented('dashboard'));

const subscriptionRoutes = express.Router();
subscriptionRoutes.all('*', notImplemented('subscribe'));

const webhookRoutes = express.Router();
webhookRoutes.all('*', notImplemented('webhook'));

const adminRoutes = express.Router();
adminRoutes.all('*', notImplemented('admin'));

// ============================================================================
// app.js — express app wiring
// ============================================================================
const app = express();

app.set('trust proxy', 1);

app.use(helmet());
app.use(cors({ origin: process.env.CLIENT_URL || '*', credentials: true }));
app.use(compression());
app.use(requestLogger);

/* ---- Mount: Stripe webhook BEFORE the JSON body parser (needs raw body) ---- */
app.use('/api/webhook', webhookRoutes);

/* ---- Standard body parsing for every other route ---- */
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true, limit: '2mb' }));
app.use(cookieParser());
app.use(sanitizeInputs);

/* ---- Global API rate limiting ---- */
app.use('/api', apiLimiter);

/* ---- Health check ---- */
app.get('/api/health', (req, res) => {
  res.status(200).json({ success: true, message: 'TrustLayer API is healthy', timestamp: new Date().toISOString() });
});

/* ---- Mount remaining routers ---- */
app.use('/api/auth', authRoutes);
app.use('/api/user', userRoutes);
app.use('/api', scanRoutes);
app.use('/api/history', historyRoutes);
app.use('/api/dashboard', dashboardRoutes);
app.use('/api/subscribe', subscriptionRoutes);
app.use('/api/admin', adminRoutes);

/* ---- Static files ---- */
app.use('/public', express.static(path.join(__dirname, 'public')));

/* ---- 404 + centralized error handling (must be mounted last) ---- */
app.use(notFound);
app.use(errorHandler);

// ============================================================================
// server.js — bootstrap
// ============================================================================
const PORT = process.env.PORT || 5000;

let server;

(async () => {
  await connectDB();

  server = app.listen(PORT, () => {
    console.log(`[Server] TrustLayer API running on port ${PORT} in ${process.env.NODE_ENV || 'development'} mode`);
  });
})();

process.on('SIGTERM', () => {
  console.log('[Server] SIGTERM received. Shutting down gracefully.');
  if (server) {
    server.close(async () => {
      await disconnectDB();
      process.exit(0);
    });
  }
});

process.on('unhandledRejection', (reason) => {
  console.error('[Server] Unhandled Promise Rejection:', reason);
});

module.exports = app;

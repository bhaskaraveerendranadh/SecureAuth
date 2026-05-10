// SecureAuth - Main Server
// A Cyberattack-Resistant Authentication System

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const path = require('path');
require('dotenv').config();

const { sanitizeInputs } = require('./middleware/validation');

// Import routes
const authRoutes = require('./routes/authRoutes');
const userRoutes = require('./routes/userRoutes');
const adminRoutes = require('./routes/adminRoutes');

const app = express();
const PORT = process.env.PORT || 3000;

// ============================================================
// SECURITY MIDDLEWARE
// ============================================================

// Helmet - Sets various HTTP security headers
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'"]
        }
    },
    crossOriginEmbedderPolicy: false
}));

// Rate Limiting - Global (prevents DDoS / brute force)
const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    message: { success: false, message: 'Too many requests, please try again later.' },
    standardHeaders: true,
    legacyHeaders: false
});

// Strict rate limit for auth routes (brute force protection)
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 20, // Only 20 auth attempts per 15 min
    message: { success: false, message: 'Too many authentication attempts. Please try again after 15 minutes.' },
    standardHeaders: true,
    legacyHeaders: false
});

app.use(globalLimiter);

// CORS configuration
app.use(cors({
    origin: true,
    credentials: true
}));

// Body parsing middleware
app.use(express.json({ limit: '10kb' })); // Limit body size
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// Cookie parser
app.use(cookieParser());

// Global input sanitization (XSS prevention)
app.use(sanitizeInputs);

// ============================================================
// SERVE STATIC FRONTEND FILES
// ============================================================
app.use(express.static(path.join(__dirname, '..', 'frontend')));

// ============================================================
// API ROUTES
// ============================================================
app.use('/api/auth', authLimiter, authRoutes);
app.use('/api/user', userRoutes);
app.use('/api/admin', adminRoutes);

// ============================================================
// PAGE ROUTES
// ============================================================
app.get('/', (req, res) => {
    res.redirect('/login.html');
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'frontend', 'login.html'));
});

app.get('/signup', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'frontend', 'signup.html'));
});

app.get('/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'frontend', 'dashboard.html'));
});

app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'frontend', 'admin.html'));
});

app.get('/leak-checker', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'frontend', 'leak-checker.html'));
});

// ============================================================
// 404 HANDLER
// ============================================================
app.use((req, res) => {
    res.status(404).json({
        success: false,
        message: 'Route not found.'
    });
});

// ============================================================
// ERROR HANDLER
// ============================================================
app.use((err, req, res, next) => {
    console.error('Server error:', err);
    res.status(500).json({
        success: false,
        message: 'Internal server error.'
    });
});

// ============================================================
// START SERVER
// ============================================================
app.listen(PORT, () => {
    console.log(`
    ╔═══════════════════════════════════════════════╗
    ║     🔒 SecureAuth Server Running              ║
    ║     📡 Port: ${PORT}                            ║
    ║     🌐 URL: http://localhost:${PORT}             ║
    ║     🛡️  Security: ENABLED                      ║
    ╚═══════════════════════════════════════════════╝
    `);
});

module.exports = app;

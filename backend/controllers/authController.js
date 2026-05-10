// Authentication Controller - Handles Login, Signup, Logout
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const validator = require('validator');
const UserModel = require('../models/userModel');
const { generateCSRFToken } = require('../middleware/csrfProtection');
require('dotenv').config();

const JWT_SECRET = process.env.JWT_SECRET || 'secureauth_jwt_secret_key_2024';
const SALT_ROUNDS = 10;
const MAX_LOGIN_ATTEMPTS = 5; // Brute force protection

const authController = {
    // POST /api/auth/signup
    async signup(req, res) {
        try {
            let { name, email, password } = req.body;

            // Unescape for processing (was escaped by sanitize middleware)
            name = validator.unescape(name);
            email = validator.unescape(email);
            password = validator.unescape(password);

            // Check if user already exists
            const existingUser = await UserModel.findByEmail(email);
            if (existingUser) {
                return res.status(409).json({ 
                    success: false, 
                    message: 'An account with this email already exists.' 
                });
            }

            // Hash password with bcrypt
            const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

            // Create user with prepared statement (SQL injection safe)
            await UserModel.create(name, email, hashedPassword);

            res.status(201).json({ 
                success: true, 
                message: 'Account created successfully! Please login.' 
            });

        } catch (error) {
            console.error('Signup error:', error);
            res.status(500).json({ 
                success: false, 
                message: 'Server error during signup. Please try again.' 
            });
        }
    },

    // POST /api/auth/login
    async login(req, res) {
        try {
            let { email, password } = req.body;

            // Unescape for processing
            email = validator.unescape(email);
            password = validator.unescape(password);

            const ipAddress = req.ip || req.connection.remoteAddress;

            // Brute force protection - check recent attempts
            const recentAttempts = await UserModel.countRecentAttempts(ipAddress, email);
            if (recentAttempts >= MAX_LOGIN_ATTEMPTS) {
                return res.status(429).json({ 
                    success: false, 
                    message: `Too many login attempts. Account locked for 15 minutes. (${recentAttempts}/${MAX_LOGIN_ATTEMPTS} attempts used)` 
                });
            }

            // Record this attempt
            await UserModel.recordLoginAttempt(ipAddress, email);

            // Find user by email (prepared statement - SQL injection safe)
            const user = await UserModel.findByEmail(email);
            if (!user) {
                await UserModel.logLogin(null, ipAddress, 'fail');
                return res.status(401).json({ 
                    success: false, 
                    message: 'Invalid email or password.' 
                });
            }

            // Check if user is blocked
            if (user.is_blocked) {
                await UserModel.logLogin(user.id, ipAddress, 'fail');
                return res.status(403).json({ 
                    success: false, 
                    message: 'Your account has been blocked. Contact administrator.' 
                });
            }

            // Compare password with bcrypt hash
            const isPasswordValid = await bcrypt.compare(password, user.password);
            if (!isPasswordValid) {
                await UserModel.logLogin(user.id, ipAddress, 'fail');
                return res.status(401).json({ 
                    success: false, 
                    message: 'Invalid email or password.' 
                });
            }

            // Log successful login
            await UserModel.logLogin(user.id, ipAddress, 'success');

            // Generate JWT token
            const token = jwt.sign(
                { 
                    id: user.id, 
                    email: user.email, 
                    role: user.role, 
                    name: user.name 
                },
                JWT_SECRET,
                { expiresIn: '24h' }
            );

            // Generate CSRF token
            const csrfToken = generateCSRFToken();

            // Set secure cookie with JWT
            res.cookie('token', token, {
                httpOnly: true,        // Prevents XSS from stealing cookie
                secure: false,         // Set to true in production (HTTPS)
                sameSite: 'Strict',    // Prevents CSRF
                maxAge: 24 * 60 * 60 * 1000 // 24 hours
            });

            // Set CSRF token cookie (readable by JS for double-submit)
            res.cookie('csrfToken', csrfToken, {
                httpOnly: false,       // Must be readable by JS
                secure: false,         // Set to true in production (HTTPS)
                sameSite: 'Strict',
                maxAge: 24 * 60 * 60 * 1000
            });

            res.json({ 
                success: true, 
                message: 'Login successful!',
                user: {
                    id: user.id,
                    name: user.name,
                    email: user.email,
                    role: user.role
                },
                csrfToken: csrfToken
            });

        } catch (error) {
            console.error('Login error:', error);
            res.status(500).json({ 
                success: false, 
                message: 'Server error during login. Please try again.' 
            });
        }
    },

    // POST /api/auth/logout
    async logout(req, res) {
        try {
            // Clear cookies
            res.clearCookie('token');
            res.clearCookie('csrfToken');

            res.json({ 
                success: true, 
                message: 'Logged out successfully.' 
            });
        } catch (error) {
            console.error('Logout error:', error);
            res.status(500).json({ 
                success: false, 
                message: 'Error during logout.' 
            });
        }
    },

    // GET /api/auth/me - Get current user info
    async getMe(req, res) {
        try {
            const user = await UserModel.findById(req.user.id);
            if (!user) {
                return res.status(404).json({ 
                    success: false, 
                    message: 'User not found.' 
                });
            }

            res.json({ 
                success: true, 
                user 
            });
        } catch (error) {
            console.error('GetMe error:', error);
            res.status(500).json({ 
                success: false, 
                message: 'Error fetching user info.' 
            });
        }
    },

    // GET /api/auth/csrf-token - Get a fresh CSRF token
    async getCsrfToken(req, res) {
        const csrfToken = generateCSRFToken();
        
        res.cookie('csrfToken', csrfToken, {
            httpOnly: false,
            secure: false,
            sameSite: 'Strict',
            maxAge: 24 * 60 * 60 * 1000
        });

        res.json({ success: true, csrfToken });
    }
};

module.exports = authController;

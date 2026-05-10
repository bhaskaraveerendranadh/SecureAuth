// Input Validation Middleware - Prevents XSS and validates input
const validator = require('validator');
const xss = require('xss');

// Sanitize all string inputs in request body to prevent XSS
const sanitizeInputs = (req, res, next) => {
    if (req.body) {
        for (let key in req.body) {
            if (typeof req.body[key] === 'string') {
                // Strip XSS payloads
                req.body[key] = xss(req.body[key]);
                // Also escape HTML entities
                req.body[key] = validator.escape(req.body[key]);
            }
        }
    }

    // Sanitize query parameters
    if (req.query) {
        for (let key in req.query) {
            if (typeof req.query[key] === 'string') {
                req.query[key] = xss(req.query[key]);
                req.query[key] = validator.escape(req.query[key]);
            }
        }
    }

    next();
};

// Validate signup input
const validateSignup = (req, res, next) => {
    const { name, email, password } = req.body;
    const errors = [];

    // Validate name
    if (!name || name.trim().length < 2) {
        errors.push('Name must be at least 2 characters long');
    }
    if (name && name.length > 100) {
        errors.push('Name must be less than 100 characters');
    }

    // Validate email
    if (!email || !validator.isEmail(validator.unescape(email))) {
        errors.push('Please provide a valid email address');
    }

    // Validate password strength
    if (!password) {
        errors.push('Password is required');
    } else {
        const unescapedPassword = validator.unescape(password);
        if (unescapedPassword.length < 8) {
            errors.push('Password must be at least 8 characters long');
        }
        if (!/[A-Z]/.test(unescapedPassword)) {
            errors.push('Password must contain at least one uppercase letter');
        }
        if (!/[a-z]/.test(unescapedPassword)) {
            errors.push('Password must contain at least one lowercase letter');
        }
        if (!/[0-9]/.test(unescapedPassword)) {
            errors.push('Password must contain at least one number');
        }
        if (!/[!@#$%^&*(),.?":{}|<>]/.test(unescapedPassword)) {
            errors.push('Password must contain at least one special character');
        }
    }

    if (errors.length > 0) {
        return res.status(400).json({ success: false, message: errors.join(', ') });
    }

    next();
};

// Validate login input
const validateLogin = (req, res, next) => {
    const { email, password } = req.body;
    const errors = [];

    if (!email || !validator.isEmail(validator.unescape(email))) {
        errors.push('Please provide a valid email address');
    }

    if (!password || password.trim().length === 0) {
        errors.push('Password is required');
    }

    if (errors.length > 0) {
        return res.status(400).json({ success: false, message: errors.join(', ') });
    }

    next();
};

// Validate profile update input
const validateProfileUpdate = (req, res, next) => {
    const { name, email } = req.body;
    const errors = [];

    if (!name || name.trim().length < 2) {
        errors.push('Name must be at least 2 characters long');
    }

    if (!email || !validator.isEmail(validator.unescape(email))) {
        errors.push('Please provide a valid email address');
    }

    if (errors.length > 0) {
        return res.status(400).json({ success: false, message: errors.join(', ') });
    }

    next();
};

// Validate leak checker input
const validateLeakCheck = (req, res, next) => {
    const { email } = req.body;

    // For the demo/testing ground, we allow non-email strings so users 
    // can test how the system handles SQL injection and XSS payloads.
    if (!email || email.trim().length === 0) {
        return res.status(400).json({ 
            success: false, 
            message: 'Please provide an email or payload to check' 
        });
    }

    next();
};

module.exports = { 
    sanitizeInputs, 
    validateSignup, 
    validateLogin, 
    validateProfileUpdate, 
    validateLeakCheck 
};

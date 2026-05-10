// Authentication Middleware - JWT Token Verification
const jwt = require('jsonwebtoken');
require('dotenv').config();

const JWT_SECRET = process.env.JWT_SECRET || 'secureauth_jwt_secret_key_2024';

// Verify JWT token from cookie or Authorization header
const authenticateToken = (req, res, next) => {
    // Get token from cookie or Authorization header
    const token = req.cookies?.token || req.headers['authorization']?.split(' ')[1];

    if (!token) {
        return res.status(401).json({ 
            success: false, 
            message: 'Access denied. No token provided. Please login first.' 
        });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(403).json({ 
            success: false, 
            message: 'Invalid or expired token. Please login again.' 
        });
    }
};

// Role-based access control middleware
const authorizeRole = (...roles) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({ 
                success: false, 
                message: 'Authentication required.' 
            });
        }

        if (!roles.includes(req.user.role)) {
            return res.status(403).json({ 
                success: false, 
                message: 'Access denied. Insufficient permissions.' 
            });
        }

        next();
    };
};

module.exports = { authenticateToken, authorizeRole };

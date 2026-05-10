// CSRF Protection Middleware
const crypto = require('crypto');

// Generate CSRF token
const generateCSRFToken = () => {
    return crypto.randomBytes(32).toString('hex');
};

// CSRF protection middleware
const csrfProtection = (req, res, next) => {
    // Skip CSRF for GET, HEAD, OPTIONS requests (they should be safe/idempotent)
    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
        return next();
    }

    // Get CSRF token from request header or body
    const csrfToken = req.headers['x-csrf-token'] || req.body?._csrf;
    
    // Get the stored CSRF token from cookie
    const storedToken = req.cookies?.csrfToken;

    if (!csrfToken || !storedToken) {
        return res.status(403).json({ 
            success: false, 
            message: 'CSRF token missing. Request rejected for security.' 
        });
    }

    // Use timing-safe comparison to prevent timing attacks
    try {
        const tokenBuffer = Buffer.from(csrfToken, 'utf8');
        const storedBuffer = Buffer.from(storedToken, 'utf8');
        
        if (tokenBuffer.length !== storedBuffer.length || 
            !crypto.timingSafeEqual(tokenBuffer, storedBuffer)) {
            return res.status(403).json({ 
                success: false, 
                message: 'Invalid CSRF token. Request rejected for security.' 
            });
        }
    } catch (err) {
        return res.status(403).json({ 
            success: false, 
            message: 'CSRF validation failed. Request rejected.' 
        });
    }

    next();
};

module.exports = { generateCSRFToken, csrfProtection };

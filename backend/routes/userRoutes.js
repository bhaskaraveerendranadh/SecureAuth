// User Routes
const express = require('express');
const router = express.Router();
const userController = require('../controllers/userController');
const { authenticateToken } = require('../middleware/authMiddleware');
const { csrfProtection } = require('../middleware/csrfProtection');
const { validateProfileUpdate, validateLeakCheck } = require('../middleware/validation');

// All user routes require authentication
router.use(authenticateToken);

// Profile update (with CSRF + validation)
router.put('/profile', csrfProtection, validateProfileUpdate, userController.updateProfile);

// Leak checker (with CSRF + validation)
router.post('/check-leak', csrfProtection, validateLeakCheck, userController.checkLeak);

// Login logs
router.get('/login-logs', userController.getLoginLogs);

// Dashboard stats
router.get('/dashboard-stats', userController.getDashboardStats);

module.exports = router;

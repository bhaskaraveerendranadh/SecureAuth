// Authentication Routes
const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const { authenticateToken } = require('../middleware/authMiddleware');
const { validateSignup, validateLogin } = require('../middleware/validation');
const { csrfProtection } = require('../middleware/csrfProtection');

// Public routes (no auth required)
router.post('/signup', validateSignup, authController.signup);
router.post('/login', validateLogin, authController.login);
router.get('/csrf-token', authController.getCsrfToken);

// Protected routes (auth required)
router.post('/logout', authenticateToken, authController.logout);
router.get('/me', authenticateToken, authController.getMe);

module.exports = router;

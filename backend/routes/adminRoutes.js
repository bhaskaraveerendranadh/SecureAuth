// Admin Routes
const express = require('express');
const router = express.Router();
const UserModel = require('../models/userModel');
const { authenticateToken, authorizeRole } = require('../middleware/authMiddleware');
const { csrfProtection } = require('../middleware/csrfProtection');

// All admin routes require authentication + admin role
router.use(authenticateToken);
router.use(authorizeRole('admin'));

// GET /api/admin/users - Get all users
router.get('/users', async (req, res) => {
    try {
        const users = await UserModel.findAll();
        res.json({ success: true, users });
    } catch (error) {
        console.error('Admin get users error:', error);
        res.status(500).json({ success: false, message: 'Error fetching users.' });
    }
});

// GET /api/admin/logs - Get all login logs
router.get('/logs', async (req, res) => {
    try {
        const logs = await UserModel.getAllLoginLogs();
        res.json({ success: true, logs });
    } catch (error) {
        console.error('Admin get logs error:', error);
        res.status(500).json({ success: false, message: 'Error fetching logs.' });
    }
});

// PUT /api/admin/users/:id/block - Block a user
router.put('/users/:id/block', csrfProtection, async (req, res) => {
    try {
        const userId = parseInt(req.params.id);
        if (isNaN(userId)) {
            return res.status(400).json({ success: false, message: 'Invalid user ID.' });
        }

        // Prevent admin from blocking themselves
        if (userId === req.user.id) {
            return res.status(400).json({ success: false, message: 'Cannot block yourself.' });
        }

        await UserModel.toggleBlock(userId, 1);
        res.json({ success: true, message: 'User blocked successfully.' });
    } catch (error) {
        console.error('Admin block user error:', error);
        res.status(500).json({ success: false, message: 'Error blocking user.' });
    }
});

// PUT /api/admin/users/:id/unblock - Unblock a user
router.put('/users/:id/unblock', csrfProtection, async (req, res) => {
    try {
        const userId = parseInt(req.params.id);
        if (isNaN(userId)) {
            return res.status(400).json({ success: false, message: 'Invalid user ID.' });
        }

        await UserModel.toggleBlock(userId, 0);
        res.json({ success: true, message: 'User unblocked successfully.' });
    } catch (error) {
        console.error('Admin unblock user error:', error);
        res.status(500).json({ success: false, message: 'Error unblocking user.' });
    }
});

// DELETE /api/admin/users/:id - Delete a user
router.delete('/users/:id', csrfProtection, async (req, res) => {
    try {
        const userId = parseInt(req.params.id);
        if (isNaN(userId)) {
            return res.status(400).json({ success: false, message: 'Invalid user ID.' });
        }

        // Prevent admin from deleting themselves
        if (userId === req.user.id) {
            return res.status(400).json({ success: false, message: 'Cannot delete yourself.' });
        }

        await UserModel.delete(userId);
        res.json({ success: true, message: 'User deleted successfully.' });
    } catch (error) {
        console.error('Admin delete user error:', error);
        res.status(500).json({ success: false, message: 'Error deleting user.' });
    }
});

module.exports = router;

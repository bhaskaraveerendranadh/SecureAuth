// User Controller - Handles profile updates, leak checker, admin operations
const validator = require('validator');
const UserModel = require('../models/userModel');

const userController = {
    // PUT /api/user/profile - Update user profile
    async updateProfile(req, res) {
        try {
            let { name, email } = req.body;

            // Unescape for processing
            name = validator.unescape(name);
            email = validator.unescape(email);

            const userId = req.user.id;

            // Check if email is already taken by another user
            const existingUser = await UserModel.findByEmail(email);
            if (existingUser && existingUser.id !== userId) {
                return res.status(409).json({ 
                    success: false, 
                    message: 'This email is already used by another account.' 
                });
            }

            // Update profile (prepared statement - SQL injection safe)
            await UserModel.updateProfile(userId, name, email);

            res.json({ 
                success: true, 
                message: 'Profile updated successfully!' 
            });

        } catch (error) {
            console.error('Profile update error:', error);
            res.status(500).json({ 
                success: false, 
                message: 'Error updating profile.' 
            });
        }
    },

    // POST /api/user/check-leak - Check email in breach database
    async checkLeak(req, res) {
        try {
            let { email } = req.body;

            // Unescape for processing
            email = validator.unescape(email);

            // Check breach database (prepared statement - SQL injection safe)
            const breaches = await UserModel.checkBreach(email);

            // For demonstration: Detect if an attack pattern was sent
            const attackPatterns = [/' OR/i, /--/i, /DROP/i, /<script/i, /onmouseover/i];
            const attackDetected = attackPatterns.some(pattern => pattern.test(email));

            if (breaches.length > 0) {
                res.json({ 
                    success: true, 
                    found: true,
                    message: `⚠️ This email was found in ${breaches.length} data breach(es)!`,
                    breaches: breaches.map(b => ({
                        email: b.email,
                        breach_name: b.breach_name
                    }))
                });
            } else {
                res.json({ 
                    success: true, 
                    found: false,
                    attackDetected,
                    message: attackDetected 
                        ? '🛡️ Attack Pattern Detected & Neutralized! No data was leaked.' 
                        : '✅ Good news! This email was NOT found in any known data breaches.',
                    breaches: []
                });
            }

        } catch (error) {
            console.error('Leak check error:', error);
            res.status(500).json({ 
                success: false, 
                message: 'Error checking for data breaches.' 
            });
        }
    },

    // GET /api/user/login-logs - Get user's login history
    async getLoginLogs(req, res) {
        try {
            const logs = await UserModel.getLoginLogs(req.user.id);
            res.json({ success: true, logs });
        } catch (error) {
            console.error('Login logs error:', error);
            res.status(500).json({ 
                success: false, 
                message: 'Error fetching login logs.' 
            });
        }
    },

    // GET /api/user/dashboard-stats - Get dashboard statistics
    async getDashboardStats(req, res) {
        try {
            const user = await UserModel.findById(req.user.id);
            const logs = await UserModel.getLoginLogs(req.user.id);
            
            const failedAttempts = logs.filter(l => l.status === 'fail').length;
            const successfulLogins = logs.filter(l => l.status === 'success').length;
            const lastLogin = logs.find(l => l.status === 'success');

            res.json({ 
                success: true, 
                stats: {
                    user,
                    totalLogins: successfulLogins,
                    failedAttempts,
                    lastLogin: lastLogin ? lastLogin.login_time : null,
                    recentActivity: logs.slice(0, 10)
                }
            });
        } catch (error) {
            console.error('Dashboard stats error:', error);
            res.status(500).json({ 
                success: false, 
                message: 'Error fetching dashboard stats.' 
            });
        }
    }
};

module.exports = userController;

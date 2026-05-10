// User Model - All database operations use PREPARED STATEMENTS to prevent SQL Injection
const pool = require('../config/db');

const UserModel = {
    // Create a new user - uses parameterized query
    async create(name, email, hashedPassword, role = 'user') {
        const sql = 'INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)';
        const [result] = await pool.execute(sql, [name, email, hashedPassword, role]);
        return result;
    },

    // Find user by email - uses parameterized query
    async findByEmail(email) {
        const sql = 'SELECT * FROM users WHERE email = ?';
        const [rows] = await pool.execute(sql, [email]);
        return rows[0];
    },

    // Find user by ID - uses parameterized query
    async findById(id) {
        const sql = 'SELECT id, name, email, role, is_blocked, created_at FROM users WHERE id = ?';
        const [rows] = await pool.execute(sql, [id]);
        return rows[0];
    },

    // Get all users (admin) - no user input needed
    async findAll() {
        const sql = 'SELECT id, name, email, role, is_blocked, created_at FROM users';
        const [rows] = await pool.execute(sql);
        return rows;
    },

    // Update user profile - uses parameterized query
    async updateProfile(id, name, email) {
        const sql = 'UPDATE users SET name = ?, email = ? WHERE id = ?';
        const [result] = await pool.execute(sql, [name, email, id]);
        return result;
    },

    // Block/unblock user - uses parameterized query
    async toggleBlock(id, isBlocked) {
        const sql = 'UPDATE users SET is_blocked = ? WHERE id = ?';
        const [result] = await pool.execute(sql, [isBlocked, id]);
        return result;
    },

    // Delete user - uses parameterized query
    async delete(id) {
        const sql = 'DELETE FROM users WHERE id = ?';
        const [result] = await pool.execute(sql, [id]);
        return result;
    },

    // Log login attempt - uses parameterized query
    async logLogin(userId, ipAddress, status) {
        const sql = 'INSERT INTO login_logs (user_id, ip_address, status) VALUES (?, ?, ?)';
        const [result] = await pool.execute(sql, [userId, ipAddress, status]);
        return result;
    },

    // Get login logs for a user - uses parameterized query
    async getLoginLogs(userId) {
        const sql = 'SELECT * FROM login_logs WHERE user_id = ? ORDER BY login_time DESC LIMIT 20';
        const [rows] = await pool.execute(sql, [userId]);
        return rows;
    },

    // Get all login logs (admin) - no user input needed
    async getAllLoginLogs() {
        const sql = `SELECT ll.*, u.name, u.email 
                     FROM login_logs ll 
                     LEFT JOIN users u ON ll.user_id = u.id 
                     ORDER BY ll.login_time DESC LIMIT 100`;
        const [rows] = await pool.execute(sql);
        return rows;
    },

    // Check breach data - uses parameterized query
    async checkBreach(email) {
        const sql = 'SELECT * FROM breach_data WHERE email = ?';
        const [rows] = await pool.execute(sql, [email]);
        return rows;
    },

    // Record login attempt for brute force tracking - uses parameterized query
    async recordLoginAttempt(ipAddress, email) {
        const sql = 'INSERT INTO login_attempts (ip_address, email) VALUES (?, ?)';
        const [result] = await pool.execute(sql, [ipAddress, email]);
        return result;
    },

    // Count recent login attempts (brute force check) - uses parameterized query
    async countRecentAttempts(ipAddress, email, minutes = 15) {
        const sql = `SELECT COUNT(*) as count FROM login_attempts 
                     WHERE ip_address = ? AND email = ? 
                     AND attempt_time > DATE_SUB(NOW(), INTERVAL ? MINUTE)`;
        const [rows] = await pool.execute(sql, [ipAddress, email, minutes]);
        return rows[0].count;
    },

    // Clear old login attempts - no user input needed
    async clearOldAttempts() {
        const sql = 'DELETE FROM login_attempts WHERE attempt_time < DATE_SUB(NOW(), INTERVAL 1 HOUR)';
        const [result] = await pool.execute(sql);
        return result;
    }
};

module.exports = UserModel;

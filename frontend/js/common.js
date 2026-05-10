// SecureAuth - Common Utilities
const API_BASE = '/api';

// Get CSRF token from cookie
function getCSRFToken() {
    const match = document.cookie.match(/csrfToken=([^;]+)/);
    return match ? match[1] : '';
}

// API request helper with CSRF token
async function apiRequest(endpoint, method = 'GET', data = null) {
    const options = {
        method,
        headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': getCSRFToken()
        },
        credentials: 'include'
    };
    if (data && method !== 'GET') {
        options.body = JSON.stringify(data);
    }
    const response = await fetch(`${API_BASE}${endpoint}`, options);
    const result = await response.json();
    if (response.status === 401 || response.status === 403) {
        if (result.message && result.message.includes('token')) {
            window.location.href = '/login.html';
            return;
        }
    }
    return { status: response.status, ...result };
}

// Show alert message
function showAlert(elementId, message, type = 'error') {
    const el = document.getElementById(elementId);
    if (!el) return;
    el.className = `alert alert-${type} show`;
    el.textContent = message;
    if (type === 'success') {
        setTimeout(() => { el.classList.remove('show'); }, 4000);
    }
}

// Hide alert
function hideAlert(elementId) {
    const el = document.getElementById(elementId);
    if (el) el.classList.remove('show');
}

// Check if user is authenticated
async function checkAuth() {
    try {
        const result = await apiRequest('/auth/me');
        if (!result || !result.success) {
            window.location.href = '/login.html';
            return null;
        }
        return result.user;
    } catch {
        window.location.href = '/login.html';
        return null;
    }
}

// Check if user is admin
async function checkAdmin() {
    const user = await checkAuth();
    if (user && user.role !== 'admin') {
        window.location.href = '/dashboard.html';
        return null;
    }
    return user;
}

// Logout binding
document.addEventListener('DOMContentLoaded', () => {
    const logoutBtns = document.querySelectorAll('.logout-btn');
    logoutBtns.forEach(btn => {
        btn.addEventListener('click', async (e) => {
            e.preventDefault();
            try {
                await apiRequest('/auth/logout', 'POST');
            } catch (err) {
                console.error('Logout error:', err);
            } finally {
                window.location.href = '/login.html';
            }
        });
    });
});

// Format date
function formatDate(dateStr) {
    if (!dateStr) return 'N/A';
    return new Date(dateStr).toLocaleString();
}

// Escape HTML to prevent XSS in rendered content
function escapeHTML(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.appendChild(document.createTextNode(str));
    return div.innerHTML;
}

// Set user info in sidebar
function setSidebarUser(user) {
    const nameEl = document.getElementById('sidebar-user-name');
    const roleEl = document.getElementById('sidebar-user-role');
    const avatarEl = document.getElementById('sidebar-user-avatar');
    if (nameEl) nameEl.textContent = escapeHTML(user.name);
    if (roleEl) roleEl.textContent = user.role;
    if (avatarEl) avatarEl.textContent = user.name ? user.name.charAt(0).toUpperCase() : '?';
}

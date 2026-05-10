-- SecureAuth Database Schema
-- Database Management System: MySQL

CREATE DATABASE IF NOT EXISTS secureauth;
USE secureauth;

-- Users Table
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,  -- Stored as bcrypt hash
    role ENUM('user', 'admin') DEFAULT 'user',
    is_blocked TINYINT(1) DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Login Logs Table
CREATE TABLE IF NOT EXISTS login_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    ip_address VARCHAR(45) NOT NULL,
    login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status ENUM('success', 'fail') NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- Breach Data Table (for Leak Checker)
CREATE TABLE IF NOT EXISTS breach_data (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    breach_name VARCHAR(255) NOT NULL
);

-- Login Attempts Table (for Brute Force Protection)
CREATE TABLE IF NOT EXISTS login_attempts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    email VARCHAR(255) NOT NULL,
    attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- CSRF Tokens Table
CREATE TABLE IF NOT EXISTS csrf_tokens (
    id INT AUTO_INCREMENT PRIMARY KEY,
    token VARCHAR(255) NOT NULL,
    user_id INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Insert sample breach data for leak checker demo
INSERT INTO breach_data (email, breach_name) VALUES
('test@example.com', 'Adobe 2013 Breach'),
('test@example.com', 'LinkedIn 2016 Breach'),
('admin@example.com', 'Yahoo 2014 Breach'),
('user@gmail.com', 'Facebook 2019 Breach'),
('demo@test.com', 'Equifax 2017 Breach'),
('sample@mail.com', 'Marriott 2018 Breach'),
('hello@world.com', 'Capital One 2019 Breach'),
('victim@breach.com', 'SolarWinds 2020 Breach'),
('leaked@data.com', 'Twitter 2022 Breach'),
('compromised@email.com', 'LastPass 2022 Breach');

-- Insert default admin user (password: Admin@123)
-- The hash below is for 'Admin@123' using bcrypt
INSERT INTO users (name, email, password, role) VALUES
('Administrator', 'admin@secureauth.com', '$2b$10$H0YjFACqsz/CLjsXdVPRQOLrObs5Y3pFLUyhexpHYQqjcXbT7BeTS', 'admin');

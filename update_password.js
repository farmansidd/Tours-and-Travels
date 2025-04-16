const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
require('dotenv').config();

async function updatePassword() {
    const pool = mysql.createPool({
        host: process.env.DB_HOST,
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD,
        database: process.env.DB_NAME
    });

    const hashedPassword = '$2b$10$tu3xJ6ezVvxHvlouLSX7N.2xvb1X9hHRxZbLdPkGiCoKYUGWCyHxa';
    const email = 'testuser@example.com';

    try {
        await pool.query('UPDATE users SET password = ? WHERE email = ?', [hashedPassword, email]);
        console.log('Password updated successfully.');
    } catch (error) {
        console.error('Error updating password:', error);
    } finally {
        await pool.end();
    }
}

updatePassword();

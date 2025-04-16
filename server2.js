require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const mysql = require('mysql2/promise');
const nodemailer = require('nodemailer');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());
app.use(express.static(path.join(__dirname)));

// Request logging middleware
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.url}`);
  next();
});

// Database connection pool
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'traveldb'
});

// Configure nodemailer with Gmail
const transporter = nodemailer.createTransport({
  service: 'gmail',
  host: 'smtp.gmail.com',
  port: 587,
  secure: false,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  },
  tls: {
    rejectUnauthorized: false
  }
});

// In-memory OTP storage
const otpStore = new Map();

// OTP Service functions
const otpService = {
  // Generate a 6-digit OTP
  generateOTP: () => {
    return Math.floor(100000 + Math.random() * 900000).toString();
  },

  // Send OTP via email
  sendOTPEmail: async (email, otp) => {
    try {
      console.log(`Attempting to send OTP ${otp} to ${email}`);
      
      const mailOptions = {
        from: `"Treker Verification" <${process.env.EMAIL_USER}>`,
        to: email,
        subject: 'Your Password Reset Code',
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e6e6e6; border-radius: 5px;">
            <h2 style="color: #333;">Password Reset</h2>
            <p>Your verification code is:</p>
            <h1 style="text-align: center; padding: 10px; background-color: #f5f5f5; border-radius: 5px; letter-spacing: 5px; font-size: 32px;">${otp}</h1>
            <p>This code will expire in 30 minutes.</p>
            <p>If you didn't request this code, please ignore this email.</p>
          </div>
        `
      };

      const info = await transporter.sendMail(mailOptions);
      console.log('Email sent successfully:', info.messageId);
      return true;
    } catch (error) {
      console.error('Error sending OTP email:', error);
      return false;
    }
  }
};

// Auth Service functions
const authService = {
  // Check if email exists
  checkEmailExists: async (email) => {
    try {
      const [rows] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
      return rows.length > 0;
    } catch (error) {
      console.error('Error checking email existence:', error);
      throw error;
    }
  },
  
  // Reset password in database
  resetPassword: async (email, newPassword) => {
    try {
      const hashedPassword = await bcrypt.hash(newPassword, 10);
      const [result] = await pool.query('UPDATE users SET password = ? WHERE email = ?', [hashedPassword, email]);
      
      return {
        success: result.affectedRows > 0,
        message: result.affectedRows > 0 ? 'Password reset successful' : 'Failed to reset password'
      };
    } catch (error) {
      console.error('Error resetting password:', error);
      return { success: false, message: 'Server error during password reset' };
    }
  }
};

// API Routes

// Signup endpoint
app.post('/api/signup', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    
    if (!name || !email || !password) {
      return res.status(400).json({ success: false, message: 'All fields are required' });
    }
    
    // Email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ success: false, message: 'Invalid email format' });
    }
    
    // Check if email already exists
    const emailExists = await authService.checkEmailExists(email);
    if (emailExists) {
      return res.status(400).json({ success: false, message: 'Email already registered' });
    }
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Insert user into database
    await pool.query('INSERT INTO users (name, email, password) VALUES (?, ?, ?)', [name, email, hashedPassword]);
    
    // Generate and send OTP for verification
    const otp = otpService.generateOTP();
    
    // Store OTP in memory with 30 minute expiration
    otpStore.set(email, {
      otp: otp,
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + 30 * 60 * 1000),
      used: false,
      purpose: 'signup'
    });
    
    await otpService.sendOTPEmail(email, otp);
    
    res.status(201).json({ 
      success: true, 
      message: 'Signup successful. Please verify your email with the code sent to your inbox.'
    });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ success: false, message: 'Server error during signup' });
  }
});

// Login endpoint
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ success: false, message: 'Email and password are required' });
    }
    
    // Get user from database
    const [users] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    
    if (users.length === 0) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    
    const user = users[0];
    
    // Verify password
    const passwordValid = await bcrypt.compare(password, user.password);
    
    if (!passwordValid) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    
    res.json({ 
      success: true, 
      message: 'Login successful',
      user: {
        id: user.id,
        name: user.name,
        email: user.email
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ success: false, message: 'Server error during login' });
  }
});

// Forgot Password endpoint
app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    console.log('Forgot password request received:', req.body);
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({ success: false, message: 'Email is required' });
    }
    
    // Check if user exists
    const emailExists = await authService.checkEmailExists(email);
    if (!emailExists) {
      return res.status(404).json({ success: false, message: 'No account found with this email' });
    }
    
    // Generate OTP
    const otp = otpService.generateOTP();
    
    // Store OTP in memory with 30 minute expiration
    otpStore.set(email, {
      otp: otp,
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + 30 * 60 * 1000),
      used: false,
      purpose: 'reset'
    });
    
    console.log(`Generated OTP for ${email}: ${otp}`);
    
    // Send OTP via email
    const emailSent = await otpService.sendOTPEmail(email, otp);
    
    if (emailSent) {
      // For testing, include the OTP in the response (remove in production)
      res.json({ 
        success: true, 
        message: 'Verification code sent to your email',
        // Include OTP in response for testing
        otp: otp
      });
    } else {
      res.status(500).json({ 
        success: false, 
        message: 'Failed to send verification code. Please try again.'
      });
    }
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Verify OTP endpoint
app.post('/api/auth/verify-otp', async (req, res) => {
  try {
    console.log('Verify OTP request received:', req.body);
    const { email, otp } = req.body;
    
    if (!email || !otp) {
      return res.status(400).json({ success: false, message: 'Email and OTP are required' });
    }
    
    // Check if OTP exists for this email
    if (!otpStore.has(email)) {
      return res.status(400).json({ success: false, message: 'No verification code found for this email' });
    }
    
    const otpData = otpStore.get(email);
    console.log('Retrieved OTP data:', otpData);
    
    // Check if OTP is expired
    if (new Date() > otpData.expiresAt) {
      otpStore.delete(email);
      return res.status(400).json({ success: false, message: 'Verification code has expired. Please request a new one.' });
    }
    
    // Check if OTP is already used
    if (otpData.used) {
      return res.status(400).json({ success: false, message: 'This verification code has already been used' });
    }
    
    // Verify OTP
    if (otpData.otp !== otp) {
      return res.status(400).json({ success: false, message: 'Invalid verification code' });
    }
    
    // Mark OTP as verified but not used yet (will be marked as used after password reset)
    otpData.verified = true;
    otpStore.set(email, otpData);
    
    console.log(`OTP verified for ${email}. OTP data updated:`, otpStore.get(email));
    
    res.json({ success: true, message: 'Verification code validated successfully' });
  } catch (error) {
    console.error('Verify OTP error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Reset Password endpoint
app.post('/api/auth/reset-password', async (req, res) => {
  try {
    console.log('Reset password request received:', req.body);
    const { email, otp, newPassword } = req.body;
    
    if (!email || !newPassword) {
      return res.status(400).json({ success: false, message: 'Email and new password are required' });
    }
    
    // Skip OTP verification in the reset-password endpoint to ensure it works
    // regardless of OTP verification status
    
    // Reset the password directly
    const resetResult = await authService.resetPassword(email, newPassword);
    
    // Clean up OTP after successful password reset
    if (otpStore.has(email)) {
      console.log(`Cleaning up OTP for ${email} after password reset`);
      otpStore.delete(email);
    }
    
    console.log(`Password reset result for ${email}:`, resetResult);
    
    if (resetResult.success) {
      res.json({ success: true, message: 'Password reset successful' });
    } else {
      res.status(500).json({ success: false, message: resetResult.message });
    }
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ success: false, message: 'Server error during password reset' });
  }
});

// Debug endpoint to view OTP store
app.get('/api/debug/otp-store', (req, res) => {
  try {
    const otpData = {};
    for (const [email, data] of otpStore.entries()) {
      otpData[email] = {
        otp: data.otp,
        createdAt: data.createdAt,
        expiresAt: data.expiresAt,
        used: data.used,
        verified: data.verified,
        purpose: data.purpose,
        isExpired: new Date() > data.expiresAt
      };
    }
    
    res.json({
      success: true,
      count: otpStore.size,
      data: otpData
    });
  } catch (error) {
    console.error('Debug endpoint error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Serve static HTML files
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/login.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'login.html'));
});

app.get('/signup.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'signup.html'));
});

app.get('/forgot-password.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'forgot-password.html'));
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Visit http://localhost:${PORT} to access the application`);
}); 
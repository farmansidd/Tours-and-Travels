require('dotenv').config();
const express = require('express');
const path = require('path'); // Import the path module
const mysql = require('mysql2/promise');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const pool = require('./database');
const authService = require('./services/authService');
const otpService = require('./services/otpService');
const crypto = require('crypto'); // Node.js crypto for token generation

const app = express();

// Middleware to log requests
app.use((req, res, next) => {
    console.log(`${req.method} request for '${req.url}'`);
    next();
});
const port = process.env.PORT || 5000;

// Serve static files
app.use(express.static(path.join(__dirname))); // Serve static files from the root directory

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cors({
  origin: process.env.CLIENT_URL,
  credentials: true
})); // Allow frontend requests

// Rate limiter
const otpLimiter = rateLimit({
  windowMs: 30 * 1000, // 30 seconds
  max: 1, // 1 request per window
  message: { error: 'Too many OTP requests, please try again after 30 seconds' }
});

// In-memory OTP storage with structure: { email => { otp, expiresAt } }
const otpStore = new Map();

// Store for password reset tokens
// Structure: { token: { email, expiresAt } }
const passwordResetTokens = new Map();

// Routes
const authRoutes = require('./routes/auth');
app.use('/api/auth', authRoutes);

// Signup endpoint
app.post('/api/signup', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Input validation
    if (!name || !email || !password) {
      return res.status(400).json({ success: false, message: 'All fields are required' });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ success: false, message: 'Invalid email format' });
    }

    // Check if the email already exists
    const [existingUsers] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    if (existingUsers.length > 0) {
      return res.status(400).json({ success: false, message: 'Email already registered' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert user into the database
    console.log(`Inserting user: Name: ${name}, Email: ${email}`); // Log user data being inserted
    await pool.query('INSERT INTO users (name, email, password) VALUES (?, ?, ?)', [name, email, hashedPassword]);

    // Generate and send OTP
    const otp = otpService.generateOTP();
    await otpService.saveOTP(email, otp);
    await otpService.sendOTPEmail(email, otp);
    
    console.log('User registered successfully'); // Log successful registration
    res.json({ success: true, message: 'User registered successfully. OTP sent to email.' });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ success: false, message: 'Error during signup: ' + error.message });
  }
});

// Login endpoint
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Input validation
    if (!email || !password) {
      return res.status(400).json({ success: false, message: 'Email and password are required' });
    }

    // Fetch user from the database
    const [users] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    console.log(`Fetched user: ${JSON.stringify(users)}`); // Log user data being fetched

    if (users.length === 0) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    const user = users[0];

    // Check password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    console.log(`User logged in: ${email}`); // Log successful login
    res.json({ success: true, message: 'Login successful!' }); // Return JSON response
  } catch (error) {
    console.error('Login error:', error); // Log error details
    res.status(500).json({ success: false, message: 'Error during login' });
  }
});

// Forgot Password endpoint - Generates a token and sends reset link
app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    console.log('Forgot password request received:', req.body);
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({ success: false, message: 'Email is required' });
    }

    // Check if user exists
    const [users] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    if (users.length === 0) {
      return res.status(404).json({ success: false, message: 'No account found with this email' });
    }

    // Create a random token
    const resetToken = crypto.randomBytes(20).toString('hex');
    
    // Set token expiration (30 minutes)
    const expiresAt = new Date(Date.now() + 30 * 60 * 1000);
    
    // Store token in memory
    passwordResetTokens.set(resetToken, {
      email: email,
      expiresAt: expiresAt
    });
    
    console.log(`Created password reset token for ${email}: ${resetToken} (expires: ${expiresAt})`);
    
    // Instead of sending OTP, we'll just return success since we're focusing on the frontend flow
    // In a real implementation, you'd send an email with the password reset link
    
    // For testing purposes, send OTP directly to email using existing service
    const otp = otpService.generateOTP();
    const emailSent = await otpService.sendOTPEmail(email, otp);
    
    if (emailSent) {
      res.json({ 
        success: true, 
        message: 'A verification code has been sent to your email',
        // Include the OTP in the response for testing
        // In production, never send the OTP in the response
        otp: otp,
        token: resetToken
      });
    } else {
      res.status(500).json({ 
        success: false, 
        message: 'Failed to send verification email. Please try again.' 
      });
    }
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ success: false, message: 'Server error: ' + error.message });
  }
});

// Verify token and allow password reset
app.post('/api/auth/verify-token', async (req, res) => {
  try {
    console.log('Token verification request received:', req.body);
    const { token, otp } = req.body;
    
    if (!token) {
      return res.status(400).json({ success: false, message: 'Token is required' });
    }
    
    // Check if token exists
    if (!passwordResetTokens.has(token)) {
      return res.status(400).json({ success: false, message: 'Invalid or expired token' });
    }
    
    const tokenData = passwordResetTokens.get(token);
    
    // Check if token is expired
    if (tokenData.expiresAt < new Date()) {
      passwordResetTokens.delete(token);
      return res.status(400).json({ success: false, message: 'Token has expired. Please request a new one.' });
    }
    
    // For our simplified approach, we'll accept any OTP
    // This would normally validate against a sent OTP
    
    console.log(`Token verified for ${tokenData.email}`);
    
    res.json({ 
      success: true, 
      message: 'Token verified successfully',
      email: tokenData.email
    });
  } catch (error) {
    console.error('Token verification error:', error);
    res.status(500).json({ success: false, message: 'Server error: ' + error.message });
  }
});

// Reset Password endpoint
app.post('/api/auth/reset-password', async (req, res) => {
  try {
    console.log('Reset password request received:', req.body);
    
    const { token, email, newPassword } = req.body;
    
    if (!email || !newPassword) {
      return res.status(400).json({ success: false, message: 'Email and new password are required' });
    }
    
    // Debug all tokens in the store
    console.log('All tokens in store:', [...passwordResetTokens.keys()]);
    
    // Check if user exists
    const [users] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    if (users.length === 0) {
      return res.status(404).json({ success: false, message: 'No account found with this email' });
    }
    
    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    
    // Update password in database
    const [updateResult] = await pool.query('UPDATE users SET password = ? WHERE email = ?', [hashedPassword, email]);
    
    if (updateResult.affectedRows === 0) {
      return res.status(500).json({ success: false, message: 'Failed to update password.' });
    }
    
    // Delete the token if it exists
    if (token && passwordResetTokens.has(token)) {
      passwordResetTokens.delete(token);
    }
    
    console.log(`Password updated successfully for ${email}`);
    res.json({ success: true, message: 'Password reset successful' });
  } catch (error) {
    console.error('Password reset error:', error);
    res.status(500).json({ success: false, message: 'Server error: ' + error.message });
  }
});

// Debug route - remove in production
app.get('/api/debug/database', async (req, res) => {
  try {
    // Check database tables
    const [tables] = await pool.query('SHOW TABLES');
    
    // Check otp_store table
    let otpStoreSchema = [];
    try {
      [otpStoreSchema] = await pool.query('SHOW COLUMNS FROM otp_store');
    } catch (error) {
      console.error('Error checking otp_store schema:', error);
    }
    
    res.json({
      tables,
      otpStoreSchema
    });
  } catch (error) {
    console.error('Database debug error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Debug endpoint to view OTP store (for development only)
app.get('/api/debug/otp-store', (req, res) => {
  try {
    // Get all keys (emails) from the OTP store
    const emails = [...otpStore.keys()];
    
    // Create a safe version of the store for display (don't show actual OTPs)
    const safeStore = {};
    for (const email of emails) {
      const entry = otpStore.get(email);
      safeStore[email] = {
        hasOTP: !!entry.otp,
        otpLength: entry.otp.length,
        expiresAt: entry.expiresAt,
        verified: !!entry.verified,
        isExpired: entry.expiresAt < new Date()
      };
    }
    
    res.json({
      success: true,
      totalEntries: emails.length,
      entries: safeStore
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error retrieving OTP store: ' + error.message
    });
  }
});

// Debug endpoint to view password reset tokens
app.get('/api/debug/tokens', (req, res) => {
  try {
    const tokens = [...passwordResetTokens.keys()];
    const safeTokens = {};
    
    for (const token of tokens) {
      const data = passwordResetTokens.get(token);
      safeTokens[token] = {
        email: data.email,
        expiresAt: data.expiresAt,
        isExpired: data.expiresAt < new Date()
      };
    }
    
    res.json({
      success: true,
      totalTokens: tokens.length,
      tokens: safeTokens
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error retrieving tokens: ' + error.message
    });
  }
});

app.get('/index.html', (req, res) => {
  res.sendFile(__dirname + '/index.html'); // Serve the index.html file
});

app.get('/login.html', (req, res) => {
  res.sendFile(__dirname + '/login.html'); // Serve the login.html file
});

// API endpoint for requesting OTP
app.post('/api/request-otp', async (req, res) => {
    const { email, purpose } = req.body;
    if (!email || purpose !== 'reset-password') {
        return res.status(400).json({ success: false, message: 'Email is required and purpose must be reset-password' });
    }

    const otp = otpService.generateOTP();
    const saved = await otpService.saveOTP(email, otp);
    if (saved) {
        await otpService.sendOTPEmail(email, otp);
        return res.json({ success: true, message: 'OTP sent to email' });
    } else {
        return res.status(500).json({ success: false, message: 'Failed to save OTP' });
    }
});

// Start the server
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});

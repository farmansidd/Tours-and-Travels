const express = require('express');
const router = express.Router();
const nodemailer = require('nodemailer');
const { User } = require('../models');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
require('dotenv').config();

// In-memory OTP storage (for simplicity)
const otpStore = {};

// Mail transporter setup
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Step 1: Send OTP
router.post('/send-otp', async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ where: { email } });

  if (!user) return res.status(404).json({ success: false, msg: 'Email not registered' });

  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  otpStore[email] = { otp, expires: Date.now() + 5 * 60 * 1000 };

  await transporter.sendMail({
    from: `"Treker App" <${process.env.EMAIL_USER}>`,
    to: email,
    subject: 'Your OTP Code',
    html: `<h3>Your OTP is: ${otp}</h3><p>Valid for 5 minutes.</p>`
  });

  res.json({ success: true, msg: 'OTP sent successfully' });
});

// Step 2: Verify OTP
router.post('/verify-otp', (req, res) => {
  const { email, otp } = req.body;
  const stored = otpStore[email];

  if (!stored || stored.otp !== otp || Date.now() > stored.expires) {
    return res.status(400).json({ success: false, msg: 'Invalid or expired OTP' });
  }

  res.json({ success: true, msg: 'OTP verified' });
});

// Step 3: Reset Password
router.post('/reset-password', async (req, res) => {
  const { email, newPassword } = req.body;
  const hashedPassword = await bcrypt.hash(newPassword, 10);

  const user = await User.findOne({ where: { email } });
  if (!user) return res.status(404).json({ success: false, msg: 'User not found' });

  user.password = hashedPassword;
  await user.save();

  delete otpStore[email]; // Clean up
  res.json({ success: true, msg: 'Password reset successful' });
});

module.exports = router;

const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const dotenv = require('dotenv');
const path = require('path');
const userRoutes = require('./routes/userRoutes');
const payRoutes = require('./routes/pay');

dotenv.config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use('/api/users', userRoutes);
app.use('/api', payRoutes);
app.get('/api/get-razorpay-key', (req, res) => {
  res.json({ key: process.env.RAZORPAY_KEY_ID });
});

const bookingRoutes = require('./routes/bookings');
app.use('/api/bookings', bookingRoutes);

const razorpayRoutes = require('./routes/razorpay');
app.use('/api', razorpayRoutes);

app.use('/forgot-password', require('./routes/forgotPassword'));

// Static files (your template)
app.use(express.static(path.join(__dirname, 'public')));

// Test Route
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public/index.html'));
});

module.exports = app;

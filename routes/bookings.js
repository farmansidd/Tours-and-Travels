const express = require('express');
const router = express.Router();
const { Booking } = require('../models');
const transporter = require('../utils/mailer');

router.post('/create', async (req, res) => {
  const { username, email, phone, date, guests, trekName, paymentId } = req.body;

  try {
    await Booking.create({
      username,
      email,
      phone,
      date,
      guests,
      trek_name: trekName,
      payment_id: paymentId
    });

    await transporter.sendMail({
      from: `"Treker Team" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: '✅ Booking Confirmed',
      html: `
        <h3>Hi ${username},</h3>
        <p>Your booking for <strong>${trekName}</strong> has been confirmed.</p>
        <p><strong>Booking ID:</strong> ${paymentId}</p>
        <p><strong>Date:</strong> ${date}</p>
        <p><strong>Guests:</strong> ${guests}</p>
        <br>
        <p>Thank you for choosing Treker!</p>
      `
    });

    res.json({ success: true, msg: 'Booking saved and email sent!' });
  } catch (error) {
    console.error('Booking Save Error:', error);
    res.status(500).json({ success: false, msg: 'Failed to save booking' });
  }
});

module.exports = router;

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

// API endpoint for verifying OTP
app.post('/api/verify-otp', async (req, res) => {
    const { email, otp, purpose } = req.body;
    if (!email || !otp || purpose !== 'reset-password') {
        return res.status(400).json({ success: false, message: 'Email and OTP are required' });
    }

    const verificationResult = await otpService.verifyOTP(email, otp);
    if (verificationResult.valid) {
        return res.json({ success: true, message: 'OTP verified' });
    } else {
        return res.status(400).json({ success: false, message: verificationResult.message });
    }
});

// API endpoint for resetting password
app.post('/api/reset-password', async (req, res) => {
    const { email, otp, newPassword } = req.body;
    if (!email || !otp || !newPassword) {
        return res.status(400).json({ success: false, message: 'Email, OTP, and new password are required' });
    }

    const result = await otpService.updatePassword(email, newPassword, otp);
    if (result.success) {
        return res.json({ success: true, message: 'Password updated successfully' });
    } else {
        return res.status(400).json({ success: false, message: result.message });
    }
});

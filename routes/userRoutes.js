const express = require('express');
const router = express.Router();
const { registerUser, loginUser } = require('../controllers/userController');
const auth = require('../middlewares/authMiddleware');

router.post('/register', registerUser);
router.post('/login', loginUser);

router.get('/profile', auth, (req, res) => {
    res.json({ msg: 'Secure profile data', user: req.user });
});

module.exports = router;

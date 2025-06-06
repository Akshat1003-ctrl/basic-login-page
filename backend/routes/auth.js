const express = require('express');
const router = express.Router();
const { register, login, refreshToken, forgotPassword, resetPassword, verifyEmail } = require('../controllers/authController');
const { protect, admin } = require('../middleware/authMiddleware');

// @route   POST api/auth/register
// @desc    Register a new user
// @access  Public
router.post('/register', register);

// @route   POST api/auth/login
// @desc    Authenticate user and get token
// @access  Public
router.post('/login', login);

// @route   POST api/auth/refresh-token
// @desc    Refresh access token
// @access  Public
router.post('/refresh-token', refreshToken);

// @route   POST api/auth/forgot-password
// @desc    Forgot password
// @access  Public
router.post('/forgot-password', forgotPassword);

// @route   POST api/auth/reset-password
// @desc    Reset password
// @access  Public
router.post('/reset-password', resetPassword);

// @route   GET api/auth/verify-email/:token
// @desc    Verify email
// @access  Public
router.get('/verify-email/:token', verifyEmail);

// @route   GET api/auth/admin
// @desc    Example admin route
// @access  Private/Admin
router.get('/admin', protect, admin, (req, res) => {
    res.status(200).json({ message: 'Welcome to the admin dashboard' });
});

module.exports = router;
// backend/controllers/authController.js
const User = require('../models/User');
const Role = require('../models/Role');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const sendEmail = require('../utils/sendEmail');

// Generate Token
const generateToken = (id) => {
    return jwt.sign({ id }, process.env.JWT_SECRET, {
        expiresIn: '15m',
    });
};

// Generate Refresh Token
const generateRefreshToken = (id) => {
    return jwt.sign({ id }, process.env.JWT_REFRESH_SECRET, {
        expiresIn: '7d',
    });
};

// Register User
exports.register = async (req, res) => {
    const { username, email, password } = req.body;

    try {
        const userExists = await User.findOne({ email });

        if (userExists) {
            return res.status(400).json({ message: 'User already exists' });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const userRole = await Role.findOne({ name: 'user' });

        const user = await User.create({
            username,
            email,
            password: hashedPassword,
            roles: [userRole._id],
        });

        // Email Verification
        const emailVerificationToken = crypto.randomBytes(32).toString('hex');
        user.emailVerificationToken = crypto.createHash('sha256').update(emailVerificationToken).digest('hex');
        await user.save();

        const verificationUrl = `${req.protocol}://${req.get('host')}/api/auth/verify-email/${emailVerificationToken}`;

        const message = `
            <h1>Please verify your email address</h1>
            <p>Please click the link below to verify your email address:</p>
            <a href="${verificationUrl}" clicktracking=off>${verificationUrl}</a>
        `;

        await sendEmail({
            to: user.email,
            subject: 'Email Verification',
            text: message,
        });

        res.status(201).json({
            message: 'User registered successfully. Please check your email to verify your account.',
        });

    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
};

// Login User
exports.login = async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ email }).populate('roles');

        if (user && (await bcrypt.compare(password, user.password))) {
            if (!user.isEmailVerified) {
                return res.status(400).json({ message: 'Please verify your email to login' });
            }

            const token = generateToken(user._id);
            const refreshToken = generateRefreshToken(user._id);

            res.json({
                _id: user._id,
                username: user.username,
                email: user.email,
                roles: user.roles.map((role) => role.name),
                token,
                refreshToken,
            });
        } else {
            res.status(401).json({ message: 'Invalid email or password' });
        }
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
};

// Refresh Token
exports.refreshToken = async (req, res) => {
    const { refreshToken } = req.body;

    if (!refreshToken) {
        return res.status(401).json({ message: 'No refresh token provided' });
    }

    try {
        const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
        const user = await User.findById(decoded.id);

        if (!user) {
            return res.status(401).json({ message: 'Invalid refresh token' });
        }

        const token = generateToken(user._id);

        res.json({ token });
    } catch (error) {
        res.status(401).json({ message: 'Invalid refresh token' });
    }
};

// Forgot Password
exports.forgotPassword = async (req, res) => {
    const { email } = req.body;

    try {
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        const resetToken = crypto.randomBytes(32).toString('hex');
        user.passwordResetToken = crypto.createHash('sha256').update(resetToken).digest('hex');
        user.passwordResetExpires = Date.now() + 10 * 60 * 1000; // 10 minutes

        await user.save();

        const resetUrl = `${req.protocol}://${req.get('host')}/reset-password/${resetToken}`;

        const message = `
            <h1>You have requested a password reset</h1>
            <p>Please go to this link to reset your password:</p>
            <a href="${resetUrl}" clicktracking=off>${resetUrl}</a>
        `;

        await sendEmail({
            to: user.email,
            subject: 'Password Reset Request',
            text: message,
        });

        res.status(200).json({ message: 'Email sent' });
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
};

// Reset Password
exports.resetPassword = async (req, res) => {
    const { resetToken, password } = req.body;

    try {
        const hashedToken = crypto.createHash('sha256').update(resetToken).digest('hex');

        const user = await User.findOne({
            passwordResetToken: hashedToken,
            passwordResetExpires: { $gt: Date.now() },
        });

        if (!user) {
            return res.status(400).json({ message: 'Invalid token' });
        }

        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(password, salt);
        user.passwordResetToken = undefined;
        user.passwordResetExpires = undefined;

        await user.save();

        res.status(200).json({ message: 'Password reset successful' });
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
};

// Verify Email
exports.verifyEmail = async (req, res) => {
    try {
        const hashedToken = crypto.createHash('sha256').update(req.params.token).digest('hex');

        const user = await User.findOne({ emailVerificationToken: hashedToken });

        if (!user) {
            return res.status(400).json({ message: 'Invalid token' });
        }

        user.isEmailVerified = true;
        user.emailVerificationToken = undefined;
        await user.save();

        res.status(200).json({ message: 'Email verified successfully' });
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
};

const Admin = require('../models/Admin');
const { validationResult } = require('express-validator');
const crypto = require('crypto');

// Helper function to send token response
const sendTokenResponse = (admin, statusCode, res) => {
    // Create token
    const token = admin.getSignedJwtToken();
    const refreshToken = admin.getSignedRefreshToken();

    // Set cookie options
    const accessOptions = {
        expires: new Date(
            Date.now() + process.env.JWT_EXPIRE.match(/(\d+)h/)[1] * 60 * 60 * 1000
        ),
        httpOnly: true
    };

    const refreshOptions = {
        expires: new Date(
            Date.now() + process.env.JWT_REFRESH_EXPIRE.match(/(\d+)d/)[1] * 24 * 60 * 60 * 1000
        ),
        httpOnly: true
    };

    if (process.env.NODE_ENV === 'production') {
        accessOptions.secure = true;
        refreshOptions.secure = true;
    }

    res
        .status(statusCode)
        .cookie('token', token, accessOptions)
        .cookie('refreshToken', refreshToken, refreshOptions)
        .json({
            success: true,
            token,
            admin: {
                id: admin._id,
                name: admin.name,
                email: admin.email
            }
        });
};

// @desc    Register admin
// @route   POST /api/auth/register
// @access  Public
exports.register = async (req, res, next) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                success: false, 
                errors: errors.array() 
            });
        }

        const { name, email, password } = req.body;

        // Check if admin with email already exists
        const adminExists = await Admin.findOne({ email });
        if (adminExists) {
            return res.status(400).json({
                success: false,
                message: 'Email is already registered'
            });
        }

        // Create admin
        const admin = await Admin.create({
            name,
            email,
            password
        });

        sendTokenResponse(admin, 201, res);
    } catch (err) {
        next(err);
    }
};

// @desc    Login admin
// @route   POST /api/auth/login
// @access  Public
exports.login = async (req, res, next) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                success: false, 
                errors: errors.array() 
            });
        }

        const { email, password } = req.body;

        // Check for admin
        const admin = await Admin.findOne({ email }).select('+password');
        if (!admin) {
            return res.status(401).json({
                success: false,
                message: 'Invalid credentials'
            });
        }

        // Check if password matches
        const isMatch = await admin.matchPassword(password);
        if (!isMatch) {
            return res.status(401).json({
                success: false,
                message: 'Invalid credentials'
            });
        }

        sendTokenResponse(admin, 200, res);
    } catch (err) {
        next(err);
    }
};

// @desc    Get current logged in admin
// @route   GET /api/auth/me
// @access  Private
exports.getMe = async (req, res, next) => {
    try {
        const admin = await Admin.findById(req.admin.id);

        res.status(200).json({
            success: true,
            data: admin
        });
    } catch (err) {
        next(err);
    }
};

// @desc    Log admin out / clear cookie
// @route   GET /api/auth/logout
// @access  Private
exports.logout = (req, res, next) => {
    res.cookie('token', 'none', {
        expires: new Date(Date.now() + 10 * 1000),
        httpOnly: true
    });

    res.cookie('refreshToken', 'none', {
        expires: new Date(Date.now() + 10 * 1000),
        httpOnly: true
    });

    res.status(200).json({
        success: true,
        message: 'Logged out successfully'
    });
};

// @desc    Change admin password
// @route   PUT /api/auth/change-password
// @access  Private
exports.changePassword = async (req, res, next) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                success: false, 
                errors: errors.array() 
            });
        }

        const { currentPassword, newPassword } = req.body;

        // Get admin with password
        const admin = await Admin.findById(req.admin.id).select('+password');

        // Check current password
        const isMatch = await admin.matchPassword(currentPassword);
        if (!isMatch) {
            return res.status(401).json({
                success: false,
                message: 'Current password is incorrect'
            });
        }

        // Set new password
        admin.password = newPassword;
        await admin.save();

        sendTokenResponse(admin, 200, res);
    } catch (err) {
        next(err);
    }
};

// @desc    Forgot password - generate token
// @route   POST /api/auth/forgot-password
// @access  Public
exports.forgotPassword = async (req, res, next) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                success: false, 
                errors: errors.array() 
            });
        }

        const { email } = req.body;

        // Find admin by email
        const admin = await Admin.findOne({ email });
        if (!admin) {
            return res.status(404).json({
                success: false,
                message: 'No admin found with that email'
            });
        }

        // Get reset token
        const resetToken = admin.getResetPasswordToken();

        // Save admin with reset token
        await admin.save({ validateBeforeSave: false });

        // In a real application, you would send an email with the reset token
        // For this demo, we'll just return the token
        
        res.status(200).json({
            success: true,
            resetToken,
            message: 'Password reset token generated'
        });
    } catch (err) {
        next(err);
    }
};

// @desc    Reset password
// @route   PUT /api/auth/reset-password/:resetToken
// @access  Public
exports.resetPassword = async (req, res, next) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                success: false, 
                errors: errors.array() 
            });
        }

        // Get hashed token
        const resetPasswordToken = crypto
            .createHash('sha256')
            .update(req.params.resetToken)
            .digest('hex');

        // Find admin by token and check if token is valid
        const admin = await Admin.findOne({
            resetPasswordToken,
            resetPasswordExpire: { $gt: Date.now() }
        });

        if (!admin) {
            return res.status(400).json({
                success: false,
                message: 'Invalid or expired token'
            });
        }

        // Set new password
        admin.password = req.body.password;
        admin.resetPasswordToken = undefined;
        admin.resetPasswordExpire = undefined;
        await admin.save();

        sendTokenResponse(admin, 200, res);
    } catch (err) {
        next(err);
    }
};
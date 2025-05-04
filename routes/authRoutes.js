const express = require('express');
const { check } = require('express-validator');
const { 
    register, 
    login, 
    getMe, 
    logout, 
    changePassword, 
    forgotPassword, 
    resetPassword 
} = require('../controllers/authController');
const { protect, refreshToken } = require('../middleware/auth');

const router = express.Router();

// Registration route with validation
router.post('/register', [
    check('name', 'Name is required').notEmpty(),
    check('email', 'Please include a valid email').isEmail(),
    check('password', 'Password must be at least 6 characters').isLength({ min: 6 })
], register);

// Login route with validation
router.post('/login', [
    check('email', 'Please include a valid email').isEmail(),
    check('password', 'Password is required').exists()
], login);

// Get current admin route (protected)
router.get('/me', protect, getMe);

// Logout route
router.get('/logout', logout);

// Change password route (protected)
router.put('/change-password', [
    check('currentPassword', 'Current password is required').exists(),
    check('newPassword', 'New password must be at least 6 characters').isLength({ min: 6 })
], protect, changePassword);

// Forgot password route
router.post('/forgot-password', [
    check('email', 'Please include a valid email').isEmail()
], forgotPassword);

// Reset password route
router.put('/reset-password/:resetToken', [
    check('password', 'Password must be at least 6 characters').isLength({ min: 6 })
], resetPassword);

// Refresh token route
router.post('/refresh-token', refreshToken);

module.exports = router;
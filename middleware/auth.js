const jwt = require('jsonwebtoken');
const Admin = require('../models/Admin');

// Protect routes
exports.protect = async (req, res, next) => {
    let token;

    // Get token from authorization header
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    } 
    // Get token from cookie if not in header
    else if (req.cookies.token) {
        token = req.cookies.token;
    }

    // Make sure token exists
    if (!token) {
        return res.status(401).json({
            success: false,
            message: 'Not authorized to access this route'
        });
    }

    try {
        // Verify token
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        // Set user in request
        req.admin = await Admin.findById(decoded.id);

        next();
    } catch (err) {
        return res.status(401).json({
            success: false,
            message: 'Not authorized to access this route'
        });
    }
};

// Verify refresh token and issue new access token
exports.refreshToken = async (req, res) => {
    const refreshToken = req.cookies.refreshToken;

    if (!refreshToken) {
        return res.status(401).json({
            success: false,
            message: 'No refresh token provided'
        });
    }

    try {
        // Verify refresh token
        const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);

        // Get admin from token id
        const admin = await Admin.findById(decoded.id);

        if (!admin) {
            return res.status(401).json({
                success: false,
                message: 'Invalid refresh token'
            });
        }

        // Generate new access token
        const accessToken = admin.getSignedJwtToken();

        // Set new access token in cookie
        const cookieOptions = {
            expires: new Date(Date.now() + 60 * 60 * 1000), // 1 hour
            httpOnly: true
        };

        if (process.env.NODE_ENV === 'production') {
            cookieOptions.secure = true;
        }

        res.cookie('token', accessToken, cookieOptions);

        res.status(200).json({
            success: true,
            accessToken
        });
    } catch (err) {
        return res.status(401).json({
            success: false,
            message: 'Invalid refresh token'
        });
    }
};
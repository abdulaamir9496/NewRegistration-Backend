const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const dotenv = require("dotenv");
const cookieParser = require("cookie-parser");
const authRoutes = require("./routes/authRoutes");

// Load environment variables
dotenv.config();

const app = express();

// Middleware
app.use(express.json());
app.use(cookieParser());
app.use(
    cors({
        origin: process.env.CLIENT_URL || "http://localhost:5173",
        credentials: true,
    })
);

// Connect to MongoDB with error handling and retry logic
const connectDB = async () => {
    try {
        const conn = await mongoose.connect(process.env.MONGO_URI, {
            retryWrites: true,
            w: "majority",
        });
        console.log(`MongoDB connected: ${conn.connection.host}`);
    } catch (error) {
        console.error("MongoDB connection error:", error);
        // Retry connection after 5 seconds
        setTimeout(connectDB, 5000);
    }
};

connectDB();

// Routes
app.use("/api/auth", authRoutes);

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({
        success: false,
        message: "Server Error",
        error:
            process.env.NODE_ENV === "development"
                ? err.message
                : "An unexpected error occurred",
    });
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});


// const express = require('express');
// const mongoose = require('mongoose');
// const cors = require('cors');
// const AdminModel = require('./models/Admin');

// const app = express();
// app.use(express.json());
// app.use(cors());

// mongoose.connect("mongodb://localhost:27017/admin");

// app.post('./login', (req, res) => {
//     const { email, password } = req.body;
//     AdminModel.findOne({ email: email, password: password })
//     .then(user => {
//         if(user) {
//             if(user.password === password) {
//                 res.status(200).json("success");
//             } else {
//                 res.status(400).json("Invalid Credentials");
//             }
//         } else {
//             res.json("User not found");
//         }
//     })
// });

// app.post('/register', (req, res) => {
//     AdminModel.create(req.body)
//     .then(admins => res.json(admins))
//     .catch(err => res.json(err));
// });

// app.listen(5000, () => {
//     console.log('Server is running on http://localhost:5000');
//     console.log('MongoDB connected');
// });

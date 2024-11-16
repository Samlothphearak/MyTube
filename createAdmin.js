const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
const User = require('./models/User'); // Ensure this path is correct for your User model

// MongoDB connection
mongoose.connect('mongodb://localhost:27017/your-db-name', { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => {
        console.log('MongoDB Connected');
        createAdmin(); // Create the admin once connected to the database
    })
    .catch((err) => {
        console.log('Error connecting to MongoDB:', err);
    });

// Function to create the admin user
const createAdmin = async () => {
    try {
        // Generate a salt and hash the password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash('adminpassword', salt);

        // Create a new admin user
        const admin = new User({
            email: 'admin',
            password: 123,
            isAdmin: true,
        });

        // Save the admin user to the database
        await admin.save();
        console.log('Admin created');
    } catch (err) {
        console.log('Error creating admin:', err);
    } finally {
        mongoose.disconnect(); // Disconnect from the database after execution
    }
};

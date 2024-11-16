const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const dotenv = require('dotenv');
const path = require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const fs = require('fs');

// Load environment variables
dotenv.config();

// Create Express app
const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json()); // To parse JSON data
app.use(express.static(path.join(__dirname, 'public'))); // To serve static files (e.g., images, CSS, JS)

// Set EJS as the view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// MongoDB connection
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('MongoDB Connected'))
    .catch((err) => console.log(err));

// Video Schema
const videoSchema = new mongoose.Schema({
    title: String,
    description: String,
    channel: String,
    videoUrl: String,
    thumbnailUrl: String,
});

const Video = mongoose.model('Video', videoSchema);

// User Schema (for Admin authentication)
const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    isAdmin: { type: Boolean, default: false },
});

const User = mongoose.model('User', userSchema);

// JWT secret for signing tokens
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret';

// Middleware to verify admin JWT
const verifyAdmin = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1]; // Extract token

    if (!token) {
        return res.status(401).json({ message: 'No token, authorization denied' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        if (!req.user.isAdmin) {
            return res.status(403).json({ message: 'Not authorized as admin' });
        }
        next();
    } catch (err) {
        res.status(401).json({ message: 'Token is not valid' });
    }
};

// Multer setup for file uploads (videos and thumbnails)
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadDir = path.join(__dirname, 'uploads');
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir);
        }
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname)); // Unique filename
    },
});

const upload = multer({ storage });

// Routes

// Homepage (display list of videos)
app.get('/', async (req, res) => {
    try {
        const videos = await Video.find();
        res.render('index', { videos });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

// Route to display login page (for rendering a login form)
app.get('/login', (req, res) => {
    res.render('login');  // You'll need to create a login.ejs view
});

// Route to display sign-up page
app.get('/sign-up', (req, res) => {
    res.render('sign-up');  // You'll need to create a signup.ejs view
});

// Route to display FYP page
app.get('/FYP', (req, res) => {
    res.render('FYP');  // You'll need to create a signup.ejs view
});

// Route to handle login submission
// Route to handle login submission
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        // Check if user exists
        const user = await User.findOne({ email });
        if (!user) {
            return res.render('login', { error: 'Invalid credentials' });
        }

        // Check if the password is correct
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.render('login', { error: 'Invalid credentials' });
        }

        // Generate JWT token
        const token = jwt.sign({ userId: user._id, isAdmin: user.isAdmin }, JWT_SECRET, { expiresIn: '1h' });

        // Save token in the session or send back to the user
        // For example, save token in a cookie or send it as response
        res.json({ token });

    } catch (err) {
        res.status(500).json({ message: 'Server error' });
    }
});


// Route to handle sign-up submission
app.post('/sign-up', async (req, res) => {
    const { email, password, isAdmin } = req.body;

    try {
        // Check if the email already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            // Render the sign-up page with an error message
            return res.render('sign-up', { error: 'Email is already in use' });
        }

        // Hash the password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Create a new user
        const user = new User({
            email,
            password: hashedPassword,
            isAdmin: isAdmin || false,  // Default is false
        });

        // Save the user to the database
        await user.save();

        // Redirect to login page or show success message
        res.redirect('/login');  // You can redirect or show a success message
    } catch (err) {
        // Render the sign-up page with a generic error message
        res.render('sign-up', { error: 'Server error, please try again later.' });
    }
});

// Route to handle forgot password submission
app.post('/FYP', async (req, res) => {
    const { email } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.render('FYP', { error: 'Email not found' });
        }

        // Here you would normally generate a password reset token and send it via email
        // For demonstration, we will just send a success message.
        // const resetToken = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1h' });
        // sendResetEmail(user.email, resetToken);

        res.render('FYP', { success: 'Password reset link sent to your email!' });
    } catch (err) {
        res.status(500).json({ message: 'Server error' });
    }
});


// Route to handle video upload (admin only)
app.post('/upload-video', verifyAdmin, upload.fields([{ name: 'video' }, { name: 'thumbnail' }]), async (req, res) => {
    const { title, description, channel } = req.body;
    const videoUrl = req.files['video'][0].path;
    const thumbnailUrl = req.files['thumbnail'][0].path;

    try {
        const video = new Video({
            title,
            description,
            channel,
            videoUrl,
            thumbnailUrl,
        });

        await video.save();
        res.status(201).json({ message: 'Video uploaded successfully' });
    } catch (err) {
        res.status(500).json({ message: 'Error uploading video' });
    }
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
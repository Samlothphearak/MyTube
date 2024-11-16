const express = require('express');
const Video = require('../models/Video');
const { verifyAdmin } = require('./auth'); // Import verifyAdmin middleware
const router = express.Router();

// Video upload route (protected)
router.post('/upload', verifyAdmin, async (req, res) => {
    const { title, description, channel, videoUrl, thumbnailUrl } = req.body;

    try {
        const newVideo = new Video({
            title,
            description,
            channel,
            videoUrl,
            thumbnailUrl,
        });

        await newVideo.save();
        res.status(201).json({ message: 'Video uploaded successfully', video: newVideo });
    } catch (err) {
        res.status(400).json({ message: 'Failed to upload video' });
    }
});

module.exports = router;

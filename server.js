const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));

// Create uploads directory if it doesn't exist
const uploadsDir = path.join(__dirname, 'uploads');
const profilesDir = path.join(uploadsDir, 'profiles');
const galleryDir = path.join(uploadsDir, 'gallery');

if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir);
if (!fs.existsSync(profilesDir)) fs.mkdirSync(profilesDir);
if (!fs.existsSync(galleryDir)) fs.mkdirSync(galleryDir);

// Database Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/vexachat2026', {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log('✅ Connected to MongoDB'))
.catch(err => console.error('❌ MongoDB connection error:', err));

// File Upload Configuration
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        if (file.fieldname === 'profile_pic') {
            cb(null, 'uploads/profiles/');
        } else if (file.fieldname === 'gallery_images') {
            cb(null, 'uploads/gallery/');
        }
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
    fileFilter: (req, file, cb) => {
        const allowedTypes = /jpeg|jpg|png|gif|webp/;
        const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = allowedTypes.test(file.mimetype);
        
        if (mimetype && extname) {
            return cb(null, true);
        } else {
            cb(new Error('Only image files are allowed'));
        }
    }
});

// User Schema - Updated for 2026
const userSchema = new mongoose.Schema({
    user_id: { type: String, unique: true, required: true },
    username: { type: String, unique: true, required: true },
    password: { type: String, required: true },
    age: { type: Number, min: 18, required: true },
    gender: { type: String, enum: ['male', 'female', 'other'], required: true },
    language: { type: String, enum: ['en', 'ar', 'th', 'ru'], default: 'en' },
    phone_number: { type: String, unique: true, sparse: true },
    whatsapp_number: { type: String },
    country: { type: String },
    city: { type: String },
    bio: { type: String, maxlength: 500, default: '' },
    profile_pic: { type: String },
    gallery: [{ type: String }],
    social_links: {
        instagram: String,
        twitter: String,
        facebook: String,
        telegram: String,
        tiktok: String
    },
    preferences: {
        show_whatsapp: { type: Boolean, default: false },
        show_phone: { type: Boolean, default: false },
        show_gallery: { type: Boolean, default: true },
        show_profile: { type: Boolean, default: true }
    },
    is_verified: { type: Boolean, default: false },
    verification_code: { type: String },
    last_login: { type: Date },
    last_active: { type: Date },
    is_active: { type: Boolean, default: true },
    is_online: { type: Boolean, default: false },
    is_banned: { type: Boolean, default: false },
    created_at: { type: Date, default: Date.now },
    membership: {
        type: { type: String, enum: ['free', 'premium'], default: 'free' },
        expires_at: Date
    }
});

const User = mongoose.model('User', userSchema);

// Message Schema
const messageSchema = new mongoose.Schema({
    sender_id: { type: String, required: true },
    receiver_id: { type: String, required: true },
    message: { type: String, required: true },
    message_type: { type: String, enum: ['text', 'image', 'video', 'voice'], default: 'text' },
    media_url: { type: String },
    is_read: { type: Boolean, default: false },
    read_at: { type: Date },
    created_at: { type: Date, default: Date.now }
});

const Message = mongoose.model('Message', messageSchema);

// Admin Schema
const adminSchema = new mongoose.Schema({
    username: { type: String, unique: true, required: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['super_admin', 'admin', 'moderator'], default: 'admin' },
    permissions: [String],
    last_login: { type: Date },
    created_at: { type: Date, default: Date.now }
});

const Admin = mongoose.model('Admin', adminSchema);

// Generate User ID for 2026
function generateUserId() {
    const year = '26'; // 2026
    const timestamp = Date.now().toString().slice(-6);
    const random = Math.floor(Math.random() * 10000).toString().padStart(4, '0');
    return `VEXA${year}${timestamp}${random}`;
}

// ============================================
// NEW: SEO & Sitemap Routes
// ============================================

// Serve sitemap.xml
app.get('/sitemap.xml', (req, res) => {
    const sitemap = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xsi:schemaLocation="http://www.sitemaps.org/schemas/sitemap/0.9
        http://www.sitemaps.org/schemas/sitemap/0.9/sitemap.xsd">
    
    <!-- Homepage (Coming Soon) -->
    <url>
        <loc>https://vexachat.world/</loc>
        <lastmod>2025-12-01</lastmod>
        <changefreq>daily</changefreq>
        <priority>1.0</priority>
    </url>
    
    <!-- Platform Pages (Protected) -->
    <url>
        <loc>https://vexachat.world/platform</loc>
        <lastmod>2025-12-01</lastmod>
        <changefreq>always</changefreq>
        <priority>0.9</priority>
    </url>
    
    <!-- Language Versions -->
    <url>
        <loc>https://vexachat.world/?lang=en</loc>
        <lastmod>2025-12-01</lastmod>
        <changefreq>daily</changefreq>
        <priority>0.6</priority>
    </url>
    
    <url>
        <loc>https://vexachat.world/?lang=ar</loc>
        <lastmod>2025-12-01</lastmod>
        <changefreq>daily</changefreq>
        <priority>0.6</priority>
    </url>
    
    <url>
        <loc>https://vexachat.world/?lang=th</loc>
        <lastmod>2025-12-01</lastmod>
        <changefreq>daily</changefreq>
        <priority>0.6</priority>
    </url>
    
    <url>
        <loc>https://vexachat.world/?lang=ru</loc>
        <lastmod>2025-12-01</lastmod>
        <changefreq>daily</changefreq>
        <priority>0.6</priority>
    </url>
    
</urlset>`;
    
    res.header('Content-Type', 'application/xml');
    res.send(sitemap);
});

// Serve robots.txt
app.get('/robots.txt', (req, res) => {
    const robots = `User-agent: *
Allow: /
Disallow: /admin
Disallow: /platform
Disallow: /uploads/
Disallow: /api/
Disallow: /node_modules/

Sitemap: https://vexachat.world/sitemap.xml

# Crawl delay to prevent server overload
Crawl-delay: 2

# Admin panel access (blocked for crawlers)
User-agent: *
Disallow: /admin-panel
Disallow: /dashboard
Disallow: /control-panel

# Allow specific crawlers
User-agent: Googlebot
Allow: /
Crawl-delay: 1

User-agent: Bingbot
Allow: /
Crawl-delay: 2

# Block bad bots
User-agent: AhrefsBot
Disallow: /

User-agent: SemrushBot
Disallow: /

User-agent: MJ12bot
Disallow: /

User-agent: DotBot
Disallow: /`;
    
    res.header('Content-Type', 'text/plain');
    res.send(robots);
});

// Serve humans.txt
app.get('/humans.txt', (req, res) => {
    const humans = `/* TEAM */
Owner: VeXachat Team
Email: vexa@vexachat.world
Twitter: @vexachat
Website: https://vexachat.world

/* THANKS */
Thanks to all our users and contributors.

/* TECHNOLOGY */
Frontend: HTML5, CSS3, JavaScript
Backend: Node.js, Express.js
Database: MongoDB
Server: VPS/Hosting
Languages: English, Arabic, Thai, Russian

/* STANDARDS */
HTML5, CSS3, ES6+
W3C Validated
Mobile Responsive
GDPR Compliant (18+)

/* LAUNCH */
Launched: 2024
Current Version: 2026
Platform Status: Coming Soon`;
    
    res.header('Content-Type', 'text/plain');
    res.send(humans);
});

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({
        status: 'online',
        year: 2026,
        language: 'en',
        platform: 'VeXachat',
        version: '1.0.0',
        uptime: process.uptime(),
        timestamp: new Date().toISOString()
    });
});

// ============================================
// API Routes
// ============================================

// User Registration for 2026
app.post('/api/register', async (req, res) => {
    try {
        const { username, password, age, gender, phone_number, language } = req.body;
        
        // Validate age for 18+
        if (age < 18) {
            return res.status(400).json({ 
                success: false, 
                message: 'Must be 18 years or older' 
            });
        }
        
        // Validate language
        const validLanguages = ['en', 'ar', 'th', 'ru'];
        if (language && !validLanguages.includes(language)) {
            return res.status(400).json({ 
                success: false, 
                message: 'Invalid language selection' 
            });
        }
        
        // Check if username exists
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(400).json({ 
                success: false, 
                message: 'Username already exists' 
            });
        }
        
        // Check if phone number exists
        if (phone_number) {
            const existingPhone = await User.findOne({ phone_number });
            if (existingPhone) {
                return res.status(400).json({ 
                    success: false, 
                    message: 'Phone number already registered' 
                });
            }
        }
        
        // Hash password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        
        // Generate user ID for 2026
        const user_id = generateUserId();
        
        // Create user
        const user = new User({
            user_id,
            username,
            password: hashedPassword,
            age,
            gender,
            language: language || 'en',
            phone_number,
            created_at: new Date(),
            membership: {
                type: 'free',
                expires_at: new Date('2027-01-01') // Free until 2027
            }
        });
        
        await user.save();
        
        res.json({ 
            success: true, 
            message: 'Registration successful',
            user_id,
            username,
            language: user.language
        });
        
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error' 
        });
    }
});

// User Login
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        // Find user
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(400).json({ 
                success: false, 
                message: 'Invalid username or password' 
            });
        }
        
        // Check if banned
        if (user.is_banned) {
            return res.status(403).json({ 
                success: false, 
                message: 'Account is temporarily suspended' 
            });
        }
        
        // Check password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ 
                success: false, 
                message: 'Invalid username or password' 
            });
        }
        
        // Update login status
        user.last_login = new Date();
        user.last_active = new Date();
        user.is_online = true;
        await user.save();
        
        // Don't send password in response
        const userData = user.toObject();
        delete userData.password;
        
        res.json({ 
            success: true, 
            message: 'Login successful',
            user: userData
        });
        
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error' 
        });
    }
});

// Admin Login
app.post('/api/admin/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        // For demo, use hardcoded admin
        if (username === 'admin' && password === 'VexaChat2026!') {
            return res.json({
                success: true,
                message: 'Admin login successful',
                admin: {
                    username: 'admin',
                    role: 'super_admin',
                    permissions: ['all']
                }
            });
        }
        
        // In production, check Admin collection
        const admin = await Admin.findOne({ username });
        if (!admin) {
            return res.status(400).json({ 
                success: false, 
                message: 'Invalid admin credentials' 
            });
        }
        
        const isMatch = await bcrypt.compare(password, admin.password);
        if (!isMatch) {
            return res.status(400).json({ 
                success: false, 
                message: 'Invalid admin credentials' 
            });
        }
        
        admin.last_login = new Date();
        await admin.save();
        
        const adminData = admin.toObject();
        delete adminData.password;
        
        res.json({ 
            success: true, 
            message: 'Admin login successful',
            admin: adminData
        });
        
    } catch (error) {
        console.error('Admin login error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error' 
        });
    }
});

// Get Online Users
app.get('/api/users/online', async (req, res) => {
    try {
        const onlineUsers = await User.find({ 
            is_online: true,
            is_active: true,
            is_banned: false 
        })
        .select('user_id username age gender country city profile_pic language')
        .sort({ last_active: -1 })
        .limit(50);
        
        res.json({ 
            success: true, 
            users: onlineUsers 
        });
        
    } catch (error) {
        console.error('Get online users error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error' 
        });
    }
});

// Update User Language
app.post('/api/user/language', async (req, res) => {
    try {
        const { user_id, language } = req.body;
        
        const validLanguages = ['en', 'ar', 'th', 'ru'];
        if (!validLanguages.includes(language)) {
            return res.status(400).json({ 
                success: false, 
                message: 'Invalid language' 
            });
        }
        
        const user = await User.findOneAndUpdate(
            { user_id },
            { language },
            { new: true }
        ).select('-password');
        
        if (!user) {
            return res.status(404).json({ 
                success: false, 
                message: 'User not found' 
            });
        }
        
        res.json({ 
            success: true, 
            message: 'Language updated',
            language: user.language 
        });
        
    } catch (error) {
        console.error('Update language error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error' 
        });
    }
});

// Update Profile
app.post('/api/profile/update', upload.fields([
    { name: 'profile_pic', maxCount: 1 },
    { name: 'gallery_images', maxCount: 10 }
]), async (req, res) => {
    try {
        const { user_id, bio, whatsapp_number, country, city, preferences } = req.body;
        
        const user = await User.findOne({ user_id });
        if (!user) {
            return res.status(404).json({ 
                success: false, 
                message: 'User not found' 
            });
        }
        
        // Update fields
        if (bio !== undefined) user.bio = bio;
        if (whatsapp_number !== undefined) user.whatsapp_number = whatsapp_number;
        if (country !== undefined) user.country = country;
        if (city !== undefined) user.city = city;
        if (preferences) {
            try {
                user.preferences = JSON.parse(preferences);
            } catch (e) {
                console.error('Preferences parse error:', e);
            }
        }
        
        // Handle profile picture upload
        if (req.files && req.files.profile_pic) {
            // Delete old profile picture if exists
            if (user.profile_pic) {
                const oldPath = path.join(__dirname, user.profile_pic);
                if (fs.existsSync(oldPath)) {
                    fs.unlinkSync(oldPath);
                }
            }
            user.profile_pic = req.files.profile_pic[0].path;
        }
        
        // Handle gallery uploads
        if (req.files && req.files.gallery_images) {
            const galleryPaths = req.files.gallery_images.map(file => file.path);
            user.gallery.push(...galleryPaths);
            
            // Limit gallery to 20 images
            if (user.gallery.length > 20) {
                user.gallery = user.gallery.slice(-20);
            }
        }
        
        await user.save();
        
        // Don't send password in response
        const userData = user.toObject();
        delete userData.password;
        
        res.json({ 
            success: true, 
            message: 'Profile updated',
            user: userData 
        });
        
    } catch (error) {
        console.error('Profile update error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error' 
        });
    }
});

// Get User Profile
app.get('/api/profile/:user_id', async (req, res) => {
    try {
        const user = await User.findOne({ 
            user_id: req.params.user_id,
            is_active: true,
            is_banned: false 
        }).select('-password -verification_code');
        
        if (!user) {
            return res.status(404).json({ 
                success: false, 
                message: 'User not found' 
            });
        }
        
        // Check if user allows profile viewing
        if (!user.preferences.show_profile) {
            return res.status(403).json({ 
                success: false, 
                message: 'Profile is private' 
            });
        }
        
        res.json({ 
            success: true, 
            user 
        });
        
    } catch (error) {
        console.error('Get profile error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error' 
        });
    }
});

// Send WhatsApp Link
app.get('/api/whatsapp/:user_id', async (req, res) => {
    try {
        const user = await User.findOne({ 
            user_id: req.params.user_id,
            is_active: true 
        }).select('whatsapp_number preferences');
        
        if (!user || !user.whatsapp_number) {
            return res.status(404).json({ 
                success: false, 
                message: 'WhatsApp number not available' 
            });
        }
        
        // Check if user allows WhatsApp sharing
        if (!user.preferences.show_whatsapp) {
            return res.status(403).json({ 
                success: false, 
                message: 'WhatsApp sharing not allowed' 
            });
        }
        
        const phone = user.whatsapp_number.replace(/[^\d+]/g, '');
        const whatsappUrl = `https://wa.me/${phone}`;
        
        res.json({ 
            success: true, 
            whatsapp_url: whatsappUrl 
        });
        
    } catch (error) {
        console.error('WhatsApp link error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error' 
        });
    }
});

// Search Users by Language
app.get('/api/users/search', async (req, res) => {
    try {
        const { language, gender, country, min_age, max_age, online_only } = req.query;
        
        let query = { 
            is_active: true, 
            is_banned: false 
        };
        
        if (language) query.language = language;
        if (gender) query.gender = gender;
        if (country) query.country = country;
        if (online_only === 'true') query.is_online = true;
        if (min_age || max_age) {
            query.age = {};
            if (min_age) query.age.$gte = parseInt(min_age);
            if (max_age) query.age.$lte = parseInt(max_age);
        }
        
        const users = await User.find(query)
            .select('user_id username age gender country city bio profile_pic language is_online')
            .sort({ last_active: -1 })
            .limit(100);
        
        res.json({ 
            success: true, 
            users 
        });
        
    } catch (error) {
        console.error('Search users error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error' 
        });
    }
});

// Send Message
app.post('/api/messages/send', async (req, res) => {
    try {
        const { sender_id, receiver_id, message, message_type } = req.body;
        
        // Check if users exist
        const sender = await User.findOne({ user_id: sender_id, is_active: true });
        const receiver = await User.findOne({ user_id: receiver_id, is_active: true });
        
        if (!sender || !receiver) {
            return res.status(404).json({ 
                success: false, 
                message: 'User not found' 
            });
        }
        
        const newMessage = new Message({
            sender_id,
            receiver_id,
            message,
            message_type: message_type || 'text',
            created_at: new Date()
        });
        
        await newMessage.save();
        
        // Update sender's last active
        await User.findOneAndUpdate(
            { user_id: sender_id },
            { last_active: new Date() }
        );
        
        res.json({ 
            success: true, 
            message: 'Message sent',
            message_id: newMessage._id 
        });
        
    } catch (error) {
        console.error('Send message error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error' 
        });
    }
});

// Get Messages between Users
app.get('/api/messages/:user1/:user2', async (req, res) => {
    try {
        const messages = await Message.find({
            $or: [
                { sender_id: req.params.user1, receiver_id: req.params.user2 },
                { sender_id: req.params.user2, receiver_id: req.params.user1 }
            ]
        }).sort({ created_at: 1 }).limit(200);
        
        res.json({ 
            success: true, 
            messages 
        });
        
    } catch (error) {
        console.error('Get messages error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error' 
        });
    }
});

// Mark Message as Read
app.post('/api/messages/read', async (req, res) => {
    try {
        const { message_id } = req.body;
        
        await Message.findByIdAndUpdate(message_id, {
            is_read: true,
            read_at: new Date()
        });
        
        res.json({ 
            success: true, 
            message: 'Message marked as read' 
        });
        
    } catch (error) {
        console.error('Mark as read error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error' 
        });
    }
});

// Get Unread Message Count
app.get('/api/messages/unread/:user_id', async (req, res) => {
    try {
        const count = await Message.countDocuments({
            receiver_id: req.params.user_id,
            is_read: false
        });
        
        res.json({ 
            success: true, 
            unread_count: count 
        });
        
    } catch (error) {
        console.error('Get unread count error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error' 
        });
    }
});

// ============================================
// ADMIN ROUTES (Protected)
// ============================================

// Admin Statistics for 2026
app.get('/api/admin/stats', async (req, res) => {
    try {
        // Basic auth check (in production, use JWT)
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ 
                success: false, 
                message: 'Unauthorized' 
            });
        }
        
        const totalUsers = await User.countDocuments();
        const onlineUsers = await User.countDocuments({ is_online: true });
        const todayUsers = await User.countDocuments({
            created_at: { $gte: new Date(new Date().setHours(0, 0, 0, 0)) }
        });
        
        const languageStats = await User.aggregate([
            { $group: { _id: '$language', count: { $sum: 1 } } }
        ]);
        
        const genderStats = await User.aggregate([
            { $group: { _id: '$gender', count: { $sum: 1 } } }
        ]);
        
        const totalMessages = await Message.countDocuments();
        const todayMessages = await Message.countDocuments({
            created_at: { $gte: new Date(new Date().setHours(0, 0, 0, 0)) }
        });
        
        res.json({
            success: true,
            stats: {
                total_users: totalUsers,
                online_users: onlineUsers,
                new_users_today: todayUsers,
                language_distribution: languageStats,
                gender_distribution: genderStats,
                total_messages: totalMessages,
                messages_today: todayMessages,
                year: 2026
            }
        });
        
    } catch (error) {
        console.error('Get stats error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error' 
        });
    }
});

// Get All Users (Admin)
app.get('/api/admin/users', async (req, res) => {
    try {
        const { page = 1, limit = 50, search = '' } = req.query;
        const skip = (page - 1) * limit;
        
        let query = {};
        if (search) {
            query = {
                $or: [
                    { username: { $regex: search, $options: 'i' } },
                    { user_id: { $regex: search, $options: 'i' } },
                    { phone_number: { $regex: search, $options: 'i' } }
                ]
            };
        }
        
        const users = await User.find(query)
            .select('-password -verification_code')
            .sort({ created_at: -1 })
            .skip(skip)
            .limit(parseInt(limit));
        
        const total = await User.countDocuments(query);
        
        res.json({ 
            success: true, 
            users,
            pagination: {
                page: parseInt(page),
                limit: parseInt(limit),
                total,
                pages: Math.ceil(total / limit)
            }
        });
        
    } catch (error) {
        console.error('Get users error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error' 
        });
    }
});

// Ban/Unban User (Admin)
app.post('/api/admin/user/:user_id/ban', async (req, res) => {
    try {
        const { action, reason } = req.body; // 'ban' or 'unban'
        
        const user = await User.findOne({ user_id: req.params.user_id });
        if (!user) {
            return res.status(404).json({ 
                success: false, 
                message: 'User not found' 
            });
        }
        
        user.is_banned = (action === 'ban');
        user.is_online = false;
        await user.save();
        
        res.json({ 
            success: true, 
            message: `User ${action === 'ban' ? 'banned' : 'unbanned'}`,
            reason: reason || 'No reason provided'
        });
        
    } catch (error) {
        console.error('Ban user error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error' 
        });
    }
});

// ============================================
// STATIC FILE SERVING
// ============================================

// Default route - serve coming-soon page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'coming-soon.html'));
});

// Serve admin panel
app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin.html'));
});

// Serve main platform
app.get('/platform', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Serve direct file access
app.get('/coming-soon.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'coming-soon.html'));
});

// Serve index.html directly
app.get('/index.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Serve admin.html directly
app.get('/admin.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin.html'));
});

// 404 Handler
app.use((req, res) => {
    res.status(404).sendFile(path.join(__dirname, 'coming-soon.html'));
});

// ============================================
// START SERVER
// ============================================

// Create default admin if not exists
async function createDefaultAdmin() {
    try {
        const adminCount = await Admin.countDocuments();
        if (adminCount === 0) {
            const hashedPassword = await bcrypt.hash('VexaChat2026!', 10);
            const admin = new Admin({
                username: 'admin',
                password: hashedPassword,
                role: 'super_admin',
                permissions: ['all'],
                created_at: new Date()
            });
            await admin.save();
            console.log('👑 Default admin created: admin / VexaChat2026!');
        }
    } catch (error) {
        console.error('Create admin error:', error);
    }
}

app.listen(PORT, async () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
    console.log(`📅 Year: 2026`);
    console.log(`🌍 Languages: English (default), Arabic, Thai, Russian`);
    console.log(`📁 Uploads: ${uploadsDir}`);
    console.log(`🔐 Admin: http://localhost:${PORT}/admin`);
    console.log(`💬 Platform: http://localhost:${PORT}/platform`);
    console.log(`👥 Coming Soon: http://localhost:${PORT}/`);
    console.log(`🗺️ Sitemap: http://localhost:${PORT}/sitemap.xml`);
    console.log(`🤖 Robots: http://localhost:${PORT}/robots.txt`);
    
    await createDefaultAdmin();
});

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const session = require('express-session');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const path = require('path');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname)));
app.use(session({
    secret: process.env.SESSION_SECRET || 'your-secret-key-change-in-production',
    resave: false,
    saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

// Database setup
const db = new sqlite3.Database('./users.db', (err) => {
    if (err) console.error('Database connection error:', err.message);
    else console.log('Connected to SQLite database');
});

// Create users table
db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    google_id TEXT UNIQUE,
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT,
    signup_method TEXT DEFAULT 'manual',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)`);

// Passport serialization
passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser((id, done) => {
    db.get('SELECT * FROM users WHERE id = ?', [id], (err, user) => {
        done(err, user);
    });
});

// Google OAuth Strategy
// NOTE: Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET environment variables
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: '/auth/google/callback'
}, (accessToken, refreshToken, profile, done) => {
    const googleId = profile.id;
    const email = profile.emails[0].value;
    const firstName = profile.name.givenName || 'Google';
    const lastName = profile.name.familyName || 'User';

    // Check if user already exists
    db.get('SELECT * FROM users WHERE google_id = ? OR email = ?', [googleId, email], (err, user) => {
        if (err) return done(err);
        
        if (user) {
            // Update google_id if user exists but was created manually
            if (!user.google_id) {
                db.run('UPDATE users SET google_id = ?, signup_method = ? WHERE id = ?', 
                    [googleId, 'google', user.id]);
                user.google_id = googleId;
                user.signup_method = 'google';
            }
            return done(null, user);
        }

        // Create new user
        const newUser = {
            google_id: googleId,
            first_name: firstName,
            last_name: lastName,
            email: email,
            password: null,
            signup_method: 'google'
        };

        db.run(`INSERT INTO users (google_id, first_name, last_name, email, password, signup_method) 
                VALUES (?, ?, ?, ?, ?, ?)`,
            [newUser.google_id, newUser.first_name, newUser.last_name, newUser.email, newUser.password, newUser.signup_method],
            function(err) {
                if (err) return done(err);
                newUser.id = this.lastID;
                return done(null, newUser);
            });
    });
}));

// Routes

// Register new user (manual)
app.post('/api/register', async (req, res) => {
    const { firstName, lastName, email, password } = req.body;

    if (!firstName || !lastName || !email || !password) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    // Check if email already exists
    db.get('SELECT email FROM users WHERE email = ?', [email], async (err, existingUser) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        
        if (existingUser) {
            return res.status(400).json({ error: 'Email already registered' });
        }

        try {
            const hashedPassword = await bcrypt.hash(password, 10);
            
            db.run(`INSERT INTO users (first_name, last_name, email, password, signup_method) 
                    VALUES (?, ?, ?, ?, 'manual')`,
                [firstName, lastName, email, hashedPassword],
                function(err) {
                    if (err) return res.status(500).json({ error: 'Registration failed' });
                    res.json({ message: 'Registration successful', userId: this.lastID });
                });
        } catch (error) {
            res.status(500).json({ error: 'Registration failed' });
        }
    });
});

// Get all users (for admin)
app.get('/api/users', (req, res) => {
    db.all('SELECT id, first_name, last_name, email, signup_method, created_at FROM users ORDER BY created_at DESC', 
        [], (err, users) => {
        if (err) return res.status(500).json({ error: 'Failed to fetch users' });
        res.json(users);
    });
});

// Get single user by ID
app.get('/api/users/id/:id', (req, res) => {
    const userId = req.params.id;
    db.get('SELECT id, first_name, last_name, email, signup_method, created_at FROM users WHERE id = ?', 
        [userId], (err, user) => {
        if (err) return res.status(500).json({ error: 'Failed to fetch user' });
        if (!user) return res.status(404).json({ error: 'User not found' });
        res.json(user);
    });
});

// Update user
app.put('/api/users/:id', (req, res) => {
    const userId = req.params.id;
    const { first_name, last_name, email } = req.body;
    
    if (!first_name || !last_name || !email) {
        return res.status(400).json({ error: 'First name, last name, and email are required' });
    }
    
    // First get the current user data to check if there are any changes
    db.get('SELECT first_name, last_name, email FROM users WHERE id = ?', [userId], (err, currentUser) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        if (!currentUser) return res.status(404).json({ error: 'User not found' });
        
        // Check if no changes were made
        if (currentUser.first_name === first_name && 
            currentUser.last_name === last_name && 
            currentUser.email === email) {
            return res.status(400).json({ error: 'No changes detected' });
        }
        
        // Check if email is already used by another user
        db.get('SELECT id FROM users WHERE email = ? AND id != ?', [email, userId], (err, existingUser) => {
            if (err) return res.status(500).json({ error: 'Database error' });
            
            if (existingUser) {
                return res.status(400).json({ error: 'Email already in use by another user' });
            }
            
            db.run('UPDATE users SET first_name = ?, last_name = ?, email = ? WHERE id = ?',
                [first_name, last_name, email, userId],
                function(err) {
                    if (err) return res.status(500).json({ error: 'Failed to update user' });
                    res.json({ message: 'User updated successfully' });
                });
        });
    });
});

// Get users by signup method
app.get('/api/users/:method', (req, res) => {
    const method = req.params.method;
    if (method !== 'google' && method !== 'manual') {
        return res.status(400).json({ error: 'Invalid method' });
    }
    
    db.all('SELECT id, first_name, last_name, email, signup_method, created_at FROM users WHERE signup_method = ? ORDER BY created_at DESC', 
        [method], (err, users) => {
        if (err) return res.status(500).json({ error: 'Failed to fetch users' });
        res.json(users);
    });
});

// Google OAuth routes
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback', 
    passport.authenticate('google', { failureRedirect: '/register.html?error=auth_failed' }),
    (req, res) => {
        res.redirect('/index.html?registered=true');
    }
);

// Logout
app.get('/logout', (req, res) => {
    req.logout(() => {
        res.redirect('/index.html');
    });
});

// Check auth status
app.get('/api/auth/status', (req, res) => {
    if (req.isAuthenticated()) {
        res.json({ authenticated: true, user: req.user });
    } else {
        res.json({ authenticated: false });
    }
});

// Serve static files - serve all files from current directory
app.use(express.static(path.join(__dirname)));

// Specific routes for HTML files
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/index.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/register.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'register.html'));
});

app.get('/admin.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin.html'));
});

app.get('/user-detail.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'user-detail.html'));
});

// Handle 404
app.use((req, res) => {
    res.status(404).send('Page not found');
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log(`Admin panel: http://localhost:${PORT}/admin.html`);
});

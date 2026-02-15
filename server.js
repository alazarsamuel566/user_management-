const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const { Pool } = require('pg');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const session = require('express-session');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const path = require('path');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3001;

// Check if DATABASE_URL is set (production on Render)
const isProduction = !!process.env.DATABASE_URL;

// Database setup
let db, pool;

if (isProduction) {
    // PostgreSQL for production (Render)
    pool = new Pool({
        connectionString: process.env.DATABASE_URL,
        ssl: { rejectUnauthorized: false }
    });
    
    // Create users table if not exists (PostgreSQL)
    pool.query(`
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            google_id TEXT UNIQUE,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT,
            signup_method TEXT DEFAULT 'manual',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    `).catch(err => console.log('Table creation error:', err.message));
    
    console.log('Connected to PostgreSQL database (PRODUCTION)');
} else {
    // SQLite for local development
    db = new sqlite3.Database('./users.db', (err) => {
        if (err) console.error('Database connection error:', err.message);
        else console.log('Connected to SQLite database (LOCAL)');
    });
    
    // Create users table if not exists (SQLite)
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
}

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

// Helper functions for database operations
function getUserById(id) {
    return new Promise((resolve, reject) => {
        if (isProduction) {
            pool.query('SELECT * FROM users WHERE id = $1', [id], (err, result) => {
                if (err) reject(err);
                else resolve(result.rows[0]);
            });
        } else {
            db.get('SELECT * FROM users WHERE id = ?', [id], (err, user) => {
                if (err) reject(err);
                else resolve(user);
            });
        }
    });
}

function getAllUsers() {
    return new Promise((resolve, reject) => {
        if (isProduction) {
            pool.query('SELECT id, first_name, last_name, email, signup_method, created_at FROM users ORDER BY created_at DESC', (err, result) => {
                if (err) reject(err);
                else resolve(result.rows);
            });
        } else {
            db.all('SELECT id, first_name, last_name, email, signup_method, created_at FROM users ORDER BY created_at DESC', [], (err, users) => {
                if (err) reject(err);
                else resolve(users);
            });
        }
    });
}

function getUserByEmail(email) {
    return new Promise((resolve, reject) => {
        if (isProduction) {
            pool.query('SELECT * FROM users WHERE email = $1', [email], (err, result) => {
                if (err) reject(err);
                else resolve(result.rows[0]);
            });
        } else {
            db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
                if (err) reject(err);
                else resolve(user);
            });
        }
    });
}

function getUserByGoogleIdOrEmail(googleId, email) {
    return new Promise((resolve, reject) => {
        if (isProduction) {
            pool.query('SELECT * FROM users WHERE google_id = $1 OR email = $2', [googleId, email], (err, result) => {
                if (err) reject(err);
                else resolve(result.rows[0]);
            });
        } else {
            db.get('SELECT * FROM users WHERE google_id = ? OR email = ?', [googleId, email], (err, user) => {
                if (err) reject(err);
                else resolve(user);
            });
        }
    });
}

// Passport serialization
passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser((id, done) => {
    getUserById(id).then(user => done(null, user)).catch(done);
});

// Google OAuth Strategy
const GOOGLE_CALLBACK_URL = isProduction 
    ? 'https://user-management-rok5.onrender.com/auth/google/callback'
    : 'http://localhost:3001/auth/google/callback';

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: GOOGLE_CALLBACK_URL
}, (accessToken, refreshToken, profile, done) => {
    const googleId = profile.id;
    const email = profile.emails[0].value;
    const firstName = profile.name.givenName || 'Google';
    const lastName = profile.name.familyName || 'User';

    getUserByGoogleIdOrEmail(googleId, email).then(user => {
        if (user) {
            if (!user.google_id) {
                if (isProduction) {
                    pool.query('UPDATE users SET google_id = $1, signup_method = $2 WHERE id = $3', [googleId, 'google', user.id]);
                } else {
                    db.run('UPDATE users SET google_id = ?, signup_method = ? WHERE id = ?', [googleId, 'google', user.id]);
                }
                user.google_id = googleId;
                user.signup_method = 'google';
            }
            return done(null, user);
        }

        const newUser = {
            google_id: googleId,
            first_name: firstName,
            last_name: lastName,
            email: email,
            password: null,
            signup_method: 'google'
        };

        if (isProduction) {
            pool.query(
                'INSERT INTO users (google_id, first_name, last_name, email, password, signup_method) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id',
                [newUser.google_id, newUser.first_name, newUser.last_name, newUser.email, newUser.password, newUser.signup_method],
                (err, result) => {
                    if (err) return done(err);
                    newUser.id = result.rows[0].id;
                    done(null, newUser);
                }
            );
        } else {
            db.run(`INSERT INTO users (google_id, first_name, last_name, email, password, signup_method) VALUES (?, ?, ?, ?, ?, ?)`,
                [newUser.google_id, newUser.first_name, newUser.last_name, newUser.email, newUser.password, newUser.signup_method],
                function(err) {
                    if (err) return done(err);
                    newUser.id = this.lastID;
                    done(null, newUser);
                });
        }
    }).catch(done);
}));

// Routes

// Register new user (manual)
app.post('/api/register', async (req, res) => {
    const { firstName, lastName, email, password } = req.body;

    if (!firstName || !lastName || !email || !password) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    getUserByEmail(email).then(existingUser => {
        if (existingUser) {
            return res.status(400).json({ error: 'Email already registered' });
        }

        bcrypt.hash(password, 10).then(hashedPassword => {
            if (isProduction) {
                pool.query(
                    'INSERT INTO users (first_name, last_name, email, password, signup_method) VALUES ($1, $2, $3, $4, $5) RETURNING id',
                    [firstName, lastName, email, hashedPassword, 'manual'],
                    (err, result) => {
                        if (err) return res.status(500).json({ error: 'Registration failed' });
                        res.json({ message: 'Registration successful', userId: result.rows[0].id });
                    }
                );
            } else {
                db.run(`INSERT INTO users (first_name, last_name, email, password, signup_method) VALUES (?, ?, ?, ?, 'manual')`,
                    [firstName, lastName, email, hashedPassword],
                    function(err) {
                        if (err) return res.status(500).json({ error: 'Registration failed' });
                        res.json({ message: 'Registration successful', userId: this.lastID });
                    });
            }
        }).catch(err => res.status(500).json({ error: 'Registration failed' }));
    }).catch(err => res.status(500).json({ error: 'Database error' }));
});

// Get all users (for admin)
app.get('/api/users', (req, res) => {
    getAllUsers().then(users => res.json(users)).catch(err => res.status(500).json({ error: 'Failed to fetch users' }));
});

// Get single user by ID
app.get('/api/users/id/:id', (req, res) => {
    const userId = req.params.id;
    getUserById(userId).then(user => {
        if (!user) return res.status(404).json({ error: 'User not found' });
        res.json(user);
    }).catch(err => res.status(500).json({ error: 'Failed to fetch user' }));
});

// Update user
app.put('/api/users/:id', (req, res) => {
    const userId = req.params.id;
    const { first_name, last_name, email } = req.body;
    
    if (!first_name || !last_name || !email) {
        return res.status(400).json({ error: 'First name, last name, and email are required' });
    }
    
    getUserById(userId).then(currentUser => {
        if (!currentUser) return res.status(404).json({ error: 'User not found' });
        
        if (currentUser.first_name === first_name && currentUser.last_name === last_name && currentUser.email === email) {
            return res.status(400).json({ error: 'No changes detected' });
        }
        
        getUserByEmail(email).then(existingUser => {
            if (existingUser && existingUser.id != userId) {
                return res.status(400).json({ error: 'Email already in use by another user' });
            }
            
            if (isProduction) {
                pool.query('UPDATE users SET first_name = $1, last_name = $2, email = $3 WHERE id = $4',
                    [first_name, last_name, email, userId],
                    function(err) {
                        if (err) return res.status(500).json({ error: 'Failed to update user' });
                        res.json({ message: 'User updated successfully' });
                    });
            } else {
                db.run('UPDATE users SET first_name = ?, last_name = ?, email = ? WHERE id = ?',
                    [first_name, last_name, email, userId],
                    function(err) {
                        if (err) return res.status(500).json({ error: 'Failed to update user' });
                        res.json({ message: 'User updated successfully' });
                    });
            }
        });
    }).catch(err => res.status(500).json({ error: 'Database error' }));
});

// Get users by signup method
app.get('/api/users/:method', (req, res) => {
    const method = req.params.method;
    if (method !== 'google' && method !== 'manual') {
        return res.status(400).json({ error: 'Invalid method' });
    }
    
    const sql = isProduction ? 
        'SELECT id, first_name, last_name, email, signup_method, created_at FROM users WHERE signup_method = $1 ORDER BY created_at DESC' :
        'SELECT id, first_name, last_name, email, signup_method, created_at FROM users WHERE signup_method = ? ORDER BY created_at DESC';
    
    const params = isProduction ? [method] : [method];
    
    if (isProduction) {
        pool.query(sql, params, (err, result) => {
            if (err) return res.status(500).json({ error: 'Failed to fetch users' });
            res.json(result.rows);
        });
    } else {
        db.all(sql, params, (err, users) => {
            if (err) return res.status(500).json({ error: 'Failed to fetch users' });
            res.json(users);
        });
    }
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

// Serve static files
app.use(express.static(path.join(__dirname)));

// Specific routes for HTML files
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/index.html', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/register.html', (req, res) => res.sendFile(path.join(__dirname, 'register.html')));
app.get('/admin.html', (req, res) => res.sendFile(path.join(__dirname, 'admin.html')));
app.get('/user-detail.html', (req, res) => res.sendFile(path.join(__dirname, 'user-detail.html')));

// Handle 404
app.use((req, res) => res.status(404).send('Page not found'));

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log(`Database: ${isProduction ? 'PostgreSQL (Production)' : 'SQLite (Local)'}`);
    console.log(`Admin panel: http://localhost:${PORT}/admin.html`);
});

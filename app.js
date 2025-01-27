// Import required modules
const express = require('express');
const session = require('express-session');
const fs = require('fs').promises;
const bcrypt = require('bcrypt');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const csrf = require('csurf');
const validator = require('validator');
const path = require('path');
const cookieParser = require('cookie-parser');

// Initialize express app
const app = express();
const PORT = process.env.PORT || 3000;
const DATA_FILE = path.join(__dirname, "database.json");

// Security middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'"],
            styleSrc: ["'self'"],
            imgSrc: ["'self'"],
            connectSrc: ["'self'"],
            fontSrc: ["'self'"],
            objectSrc: ["'none'"],
            mediaSrc: ["'self'"],
            frameSrc: ["'none'"]
        }
    }
}));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// Body parser middleware with size limits
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// Cookie parser middleware
app.use(cookieParser());

// Session configuration
app.use(session({
    secret: process.env.SESSION_SECRET || 'fallback_secret_key_change_in_production',
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
        sameSite: 'strict'
    }
}));

// CSRF protection with cookie
app.use(csrf({ 
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production'
    }
}));

// Expose CSRF token to all templates
app.use((req, res, next) => {
    res.locals.csrfToken = req.csrfToken();
    next();
});

// CSRF token endpoint
app.get('/csrf-token', (req, res) => {
    res.json({ csrfToken: req.csrfToken() });
});

// Error handler middleware
app.use((err, req, res, next) => {
    if (err.code === 'EBADCSRFTOKEN') {
        return res.status(403).json({ error: 'Invalid CSRF token' });
    }
    console.error(err.stack);
    res.status(500).json({ error: 'Internal server error' });
});

// Database operations with retries
async function readDatabase(retries = 3) {
    while (retries > 0) {
        try {
            const data = await fs.readFile(DATA_FILE, 'utf8');
            return JSON.parse(data);
        } catch (error) {
            if (retries === 1) throw error;
            retries--;
            await new Promise(resolve => setTimeout(resolve, 1000));
        }
    }
}

async function writeDatabase(data, retries = 3) {
    while (retries > 0) {
        try {
            await fs.writeFile(DATA_FILE, JSON.stringify(data, null, 2));
            return;
        } catch (error) {
            if (retries === 1) throw error;
            retries--;
            await new Promise(resolve => setTimeout(resolve, 1000));
        }
    }
}

// Input validation middleware
const validateInput = (input) => {
    return validator.escape(validator.trim(input));
};

// Authentication middleware
const requireAuth = (req, res, next) => {
    if (!req.session.user) {
        return res.status(401).json({ error: 'Authentication required' });
    }
    next();
};

// Serve static files
app.use('/public', express.static('public', {
    maxAge: '1d',
    setHeaders: (res) => {
        res.set('X-Content-Type-Options', 'nosniff');
    }
}));

app.use('/protected', requireAuth, express.static('private/protected', {
    maxAge: '1d',
    setHeaders: (res) => {
        res.set('X-Content-Type-Options', 'nosniff');
    }
}));

// Routes
app.get('/', (req, res) => {
    res.redirect(req.session.user ? '/protected/index.html' : '/public/login.html');
});

// Register endpoint with password requirements
app.post('/register', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Input validation
        if (!username || !password) {
            return res.status(400).json({ error: 'Missing required fields' });
        }

        if (!validator.isLength(password, { min: 8, max: 100 })) {
            return res.status(400).json({ error: 'Password must be between 8 and 100 characters' });
        }

        if (!validator.matches(password, /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/)) {
            return res.status(400).json({ 
                error: 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character' 
            });
        }

        const sanitizedUsername = validateInput(username);
        
        // Create database file if it doesn't exist
        try {
            await fs.access(DATA_FILE);
        } catch {
            await fs.writeFile(DATA_FILE, JSON.stringify({ users: [], tasks: [] }, null, 2));
        }

        const data = await readDatabase();

        if (data.users.some(u => u.username === sanitizedUsername)) {
            return res.status(400).json({ error: 'Username already exists' });
        }

        // Hash password
        const salt = await bcrypt.genSalt(12);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Save user
        data.users.push({
            id: Date.now().toString(),
            username: sanitizedUsername,
            password: hashedPassword,
            created: new Date().toISOString()
        });

        await writeDatabase(data);
        res.status(201).json({ message: 'Registration successful' });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Registration failed' });
    }
});

// Login endpoint with brute force protection
const loginAttempts = new Map();
const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_TIME = 15 * 60 * 1000; // 15 minutes

app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const ip = req.ip;

        // Check login attempts
        const attempts = loginAttempts.get(ip) || { count: 0, timestamp: Date.now() };
        if (attempts.count >= MAX_LOGIN_ATTEMPTS) {
            const timeLeft = LOCKOUT_TIME - (Date.now() - attempts.timestamp);
            if (timeLeft > 0) {
                return res.status(429).json({ 
                    error: `Too many login attempts. Try again in ${Math.ceil(timeLeft / 60000)} minutes` 
                });
            }
            loginAttempts.delete(ip);
        }

        if (!username || !password) {
            return res.status(400).json({ error: 'Missing credentials' });
        }

        const data = await readDatabase();
        const user = data.users.find(u => u.username === validateInput(username));

        if (!user || !(await bcrypt.compare(password, user.password))) {
            // Increment failed attempts
            attempts.count++;
            attempts.timestamp = Date.now();
            loginAttempts.set(ip, attempts);

            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Reset login attempts on successful login
        loginAttempts.delete(ip);

        // Set session
        req.session.user = {
            id: user.id,
            username: user.username
        };

        res.json({ 
            message: 'Login successful',
            csrfToken: req.csrfToken()
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// Task management endpoints
app.delete('/tasks/:id', requireAuth, async (req, res) => {
    try {
        const taskId = parseInt(req.params.id, 10);
        console.log('Attempting to delete task:', taskId);
        
        const data = await readDatabase();
        if (!data.tasks) {
            return res.status(404).json({ error: 'No tasks found' });
        }

        const taskIndex = data.tasks.findIndex(
            task => task.id === taskId && task.user === req.session.user.username
        );

        console.log('Task index:', taskIndex);

        if (taskIndex === -1) {
            return res.status(404).json({ error: 'Task not found or unauthorized' });
        }

        // Remove the task
        data.tasks.splice(taskIndex, 1);
        await writeDatabase(data);

        res.json({ message: 'Task deleted successfully' });
    } catch (error) {
        console.error('Task deletion error:', error);
        res.status(500).json({ error: 'Failed to delete task' });
    }
});

app.post('/tasks', requireAuth, async (req, res) => {
    try {
        const { title, description } = req.body;
        
        if (!title || !description) {
            return res.status(400).json({ error: 'Title and description are required' });
        }

        const data = await readDatabase();
        if (!data.tasks) {
            data.tasks = [];
        }

        // Create task with numeric ID
        const newTask = {
            id: Date.now(),
            task: `${validateInput(title)}: ${validateInput(description)}`,
            user: req.session.user.username
        };

        data.tasks.push(newTask);
        await writeDatabase(data);

        // Return the task in the format expected by the frontend
        res.status(201).json({
            id: newTask.id.toString(), // Convert ID to string for consistency
            title: validateInput(title),
            description: validateInput(description),
            user: newTask.user
        });
    } catch (error) {
        console.error('Task creation error:', error);
        res.status(500).json({ error: 'Failed to create task' });
    }
});

app.get('/tasks', requireAuth, async (req, res) => {
    try {
        const data = await readDatabase();
        if (!data.tasks) {
            data.tasks = [];
        }

        const userTasks = data.tasks.filter(task => task.user === req.session.user.username);
        
        // Transform tasks to match frontend format
        const transformedTasks = userTasks.map(task => {
            const [title, description] = task.task.split(': ');
            return {
                id: task.id.toString(), // Convert ID to string for consistency
                title: title || task.task,
                description: description || '',
                user: task.user
            };
        });

        res.json(transformedTasks);
    } catch (error) {
        console.error('Task retrieval error:', error);
        res.status(500).json({ error: 'Failed to retrieve tasks' });
    }
});

app.get('/dashboard', requireAuth, (req, res) => {
    res.redirect('/protected/dashboard.html');
});

// Logout route
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Logout error:', err);
            return res.status(500).json({ error: 'Logout failed' });
        }
        res.redirect('/public/login.html');
    });
});

// Start server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

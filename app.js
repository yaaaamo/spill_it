const express = require('express');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcrypt');
const SQLiteStore = require('connect-sqlite3')(session);
const http = require('http');
const socketIo = require('socket.io');

const app = express();
const port = 3000;
const server = http.createServer(app);
const io = socketIo(server);

const sessionMiddleware = session({
    store: new SQLiteStore(),
    secret: 'jedi',
    resave: false,
    saveUninitialized: true,
    cookie: { maxAge: 60000 } // Session expiration time (1 minute for example)
});

app.use(sessionMiddleware);

// Share session with Socket.IO
io.use((socket, next) => {
    sessionMiddleware(socket.request, socket.request.res || {}, next);
});

// Create SQLite database connection
const dbPath = path.join(__dirname, 'table', 'db.sqlite');
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('Error opening database:', err.message);
    } else {
        console.log('Connected to the database.');
    }
});

// Parse JSON and urlencoded request bodies
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static files (HTML, CSS, JS)
app.use(express.static(path.join(__dirname)));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'spillit.html'));
});

// Define route to serve signup form
app.get('/signup', (req, res) => {
    res.sendFile(path.join(__dirname, 'signup.html'));
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'login.html'));
});

// Define route to handle signup form submission
app.post('/signup', async (req, res) => {
    const { username, email, password } = req.body;

    try {
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert user data into the database
        const sql = `INSERT INTO Signup (username, email, password) VALUES (?, ?, ?)`;
        db.run(sql, [username, email, hashedPassword], (err) => {
            if (err) {
                console.error('Error inserting user into database:', err.message);
                return res.status(500).send('Internal Server Error');
            }
            console.log('User signed up successfully');
            // Redirect to the login page after successful signup
            res.redirect('/login');
        });
    } catch (err) {
        console.error('Error hashing password:', err.message);
        res.status(500).send('Internal Server Error');
    }
});

app.post('/login', (req, res) => {
    const { email, password } = req.body;

    // Query the database to verify the credentials
    const sql = "SELECT * FROM signup WHERE email = ?";
    db.get(sql, [email], async (err, row) => {
        if (err) {
            console.error('Error querying database:', err.message);
            return res.status(500).send('Internal Server Error');
        }

        if (!row) {
            // User not found
            return res.status(401).send('Invalid email or password');
        }

        try {
            const match = await bcrypt.compare(password, row.password);

            if (!match) {
                // Password doesn't match
                return res.status(401).send('Invalid email or password');
            }

            // Store user information in session
            req.session.user = row;

            // Redirect or respond with appropriate message based on authentication result
            res.redirect('/profile');
        } catch (err) {
            console.error('Error comparing passwords:', err.message);
            res.status(500).send('Internal Server Error');
        }
    });
});

function requireLogin(req, res, next) {
    if (req.session && req.session.user) {
        // User is authenticated
        next();
    } else {
        // User is not authenticated, redirect to login page or send an error response
        res.status(401).send('Unauthorized');
    }
}

app.set('view engine', 'ejs');

// Example route that requires authentication
app.get('/profile', requireLogin, (req, res) => {
    const userId = req.session.user.id;

    // Query the database to get user information
    db.get('SELECT username FROM signup WHERE id = ?', [userId], (err, row) => {
        if (err) {
            console.error('Error querying database:', err.message);
            res.status(500).send('Internal Server Error');
        } else {
            if (row) {
                // Render the profile page with the username
                res.render('profile', { username: row.username });

                // Log the username to the console
                console.log(`Welcome ${row.username}`);
            } else {
                res.status(404).send('User not found');
            }
        }
    });
});

// Keep track of connected users
const users = {};

io.on('connection', (socket) => {
    console.log('A user connected');

    // Store the session user information in the socket
    const session = socket.request.session;
    const user = session.user;

    if (!user) {
        console.error('No user found in session');
        return;
    }

    // Add the user to the list of connected users
    users[socket.id] = user.username;
    io.emit('user list', Object.values(users));

    // Listen for chat messages
    socket.on('chat message', (msg) => {
        // Broadcast the message along with the username to all connected clients
        io.emit('chat message', { username: user.username, message: msg });
    });

    // Handle user disconnects
    socket.on('disconnect', () => {
        console.log('A user disconnected');
        // Remove the user from the list of connected users
        delete users[socket.id];
        io.emit('user list', Object.values(users));
    });
});

// Start the server
server.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});

const express = require('express');
const session = require('express-session');

const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
const port = 3000;

app.use(session({
    secret: 'jedi',
    resave: false,
    saveUninitialized: true
}));


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
    res.sendFile(path.join(__dirname,'spillit.html'));
});

// Define route to serve signup form
app.get('/signup', (req, res) => {
    res.sendFile(path.join(__dirname,'signup.html'));
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname,'login.html'));
});



// Define route to handle signup form submission
app.post('/signup', (req, res) => {
    const { username, email, password } = req.body;

    // Insert user data into the database
    const sql = `INSERT INTO Signup (username, email, password) VALUES (?, ?, ?)`;
    db.run(sql, [username, email, password], (err) => {
        if (err) {
            return console.error(err.message);
        }
        console.log('User signed up successfully');
        // Redirect to the login page after successful signup
        res.redirect('/login');
    });
});


app.post('/login', (req, res) => {
    const { email, password } = req.body;

    // Query the database to verify the credentials
    const sql = "SELECT * FROM signup WHERE email = ? AND password = ?";
    db.get(sql, [email, password], (err, row) => {
        if (err) {
            console.error('Error querying database:', err.message);
            return res.status(500).send('Internal Server Error');
        }

        if (!row) {
            // User not found or password doesn't match
            return res.status(401).send('Invalid email or password');
        }

        // Store user information in session
        req.session.user = row;

        // Redirect or respond with appropriate message based on authentication result
        res.redirect('/profile');
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

// Example route that requires authentication
app.get('/profile', requireLogin, (req, res) => {
    // Access user information from session
    const user = req.session.user;
    res.send(`Welcome ${user.username}!`);
    console.log("User sent to the profile page");
});



// Start server
app.listen(port, () => {
    console.log(`Server is running at http://localhost:${port}`);
});

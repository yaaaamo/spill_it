const express = require('express');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcrypt');
const { body, validationResult } = require('express-validator'); // Import express-validator
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
    cookie: { maxAge: 10 * 60 * 1000 } // Session expiration time (1 minute for example)
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



// Define route to handle signup form submission with email validation
app.post('/signup', [
    body('email').isEmail().withMessage('Invalid email format') // Email validation
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

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

            // Redirect to the profile page with the user's ID
            res.redirect(`/profile/${row.id}`);
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
        res.redirect('/login');
    }
}

// Define route to handle editing user profile

app.set('view engine', 'ejs');

// Update the profile route to use the user ID
app.get('/profile/:id', requireLogin, (req, res) => {
    const userId = req.params.id;

    // Query the database to get user information
    db.get('SELECT username FROM signup WHERE id = ?', [userId], (err, row) => {
        if (err) {
            console.error('Error querying database:', err.message);
            res.status(500).send('Internal Server Error');
        } else {
            if (row) {
                // Render the profile page with the username
                res.render('profile', { username: row.username, id: userId });

                // Log the username to the console
                console.log(`Welcome ${row.username}`);
            } else {
                res.status(404).send('User not found');
            }
        }
    });
});

app.get('/modify/:id', requireLogin, (req, res) => {
    const userId = req.params.id;

    // Query the database to get user information
    db.get('SELECT username, email FROM signup WHERE id = ?', [userId], (err, row) => {
        if (err) {
            console.error('Error querying database:', err.message);
            res.status(500).send('Internal Server Error');
        } else {
            if (row) {
                // Render the edit profile page with the user's information
                res.render('edit-profile', { id: userId, username: row.username });
            } else {
                res.status(404).send('User not found');
            }
        }
    });
});

app.post('/modify/:id', requireLogin, async (req, res) => {
    const userId = req.params.id;
    const { username, password } = req.body;

    try {
        const hashedPassword = await bcrypt.hash(password, 10);

        // Update user information in the database
        const sql = `UPDATE signup SET username = ?, password = ? WHERE id = ?`;
        db.run(sql, [username, hashedPassword, userId], (err) => {
            if (err) {
                console.error('Error updating user information:', err.message);
                return res.status(500).send('Internal Server Error');
            }
            // Redirect to the login page after successful update
            console.log('Informations modified succesfully.')
            res.redirect('/login');
        });
    } catch (err) {
        console.error('Error hashing password:', err.message);
        res.status(500).send('Internal Server Error');
    }
});

app.get('/cp', requireLogin, (req, res) => {
    const user = req.session.user; // Assuming user information is stored in the session

    // Render the change-profile page with the user object
    res.render('change-profile', { user });
});



app.post('/save-profile', requireLogin, (req, res) => {
    const { name, surname, age, bio } = req.body;
    const userId = req.session.user.id; // Get the user's ID from the session

    // Check if the user already has profile information in the "infos" table
    db.get('SELECT * FROM infos WHERE user_id = ?', [userId], (err, row) => {
        if (err) {
            console.error('Error checking profile information:', err.message);
            return res.status(500).send('Internal Server Error');
        }

        if (row) {
            // Update the existing profile information
            const sql = 'UPDATE infos SET name = ?, surname = ?, age = ?, bio = ? WHERE user_id = ?';
            db.run(sql, [name, surname, age, bio, userId], (err) => {
                if (err) {
                    console.error('Error updating profile:', err.message);
                    res.status(500).send('Internal Server Error');
                } else {
                    // Profile updated successfully
                    res.redirect('/view-profile'); // Redirect to the view profile page
                }
            });
        } else {
            // Insert new profile information
            const insertSql = 'INSERT INTO infos (user_id, name, surname, age, bio) VALUES (?, ?, ?, ?, ?)';
            db.run(insertSql, [userId, name, surname, age, bio], (err) => {
                if (err) {
                    console.error('Error saving profile:', err.message);
                    res.status(500).send('Internal Server Error');
                } else {
                    // Profile saved successfully
                    res.redirect('/view-profile'); // Redirect to the view profile page
                }
            });
        }
    });
});



app.get('/view-profile', requireLogin, (req, res) => {
    const userId = req.session.user.id; // Get the user's ID from the session

    // Query the database to get the user's profile information
    const sql = `
        SELECT i.name, i.surname, i.age, i.bio
        FROM infos i
        WHERE i.user_id = ?
    `;
    db.get(sql, [userId], (err, row) => {
        if (err) {
            console.error('Error querying database:', err.message);
            res.status(500).send('Internal Server Error');
        } else {
            if (row) {
                // Render the view-profile page with the user's profile information
                res.render('view-profile', { user: row });
            } else {
                res.status(404).send('Profile not found');
            }
        }
    });
});


















































// Define route to display rooms
app.get('/rooms',requireLogin, (req, res) => {
    db.all('SELECT * FROM rooms', (err, rows) => {
        if (err) {
            console.error(err);
            res.status(500).send('Internal Server Error');
            return;
        }
        res.render('rooms', { rooms: rows });
    });
});





app.get('/rooms/:id',requireLogin, (req, res) => {
    const roomId = req.params.id;

    // Query the database to get room information
    db.get('SELECT * FROM rooms WHERE id = ?', [roomId], (err, room) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Internal Server Error');
        }

        if (!room) {
            return res.status(404).send('Room not found');
        }

        // Render the room-specific page
        res.render('room', { room });
    });
});


const users = {};  // To store users in rooms

io.on('connection', (socket) => {
    console.log('A user connected');

    // Store the session user information in the socket
    const session = socket.request.session;
    const user = session.user;

    if (!user) {
        console.error('No user found in session');
        return;
    }

        // Handle joining a room
    socket.on('joinRoom', ({ room }) => {
        socket.join(room);
        console.log(`User joined room: ${room}`);

        if (!users[room]) {
            users[room] = [];
        }

        users[room].push(user.username);
        io.to(room).emit('userList', users[room]);
        io.to(room).emit('message', { username: 'System', message: `${user.username} has joined the room.` });
    });

    // Handle user disconnects
    socket.on('disconnect', () => {
        console.log('A user disconnected');
        for (const room in users) {
            const index = users[room].indexOf(user.username);
            if (index !== -1) {
                users[room].splice(index, 1);
                io.to(room).emit('userList', users[room]);
                io.to(room).emit('message', { username: 'System', message: `${user.username} has left the room.` });
            }
        }
    });


    
    

    // Handle chat messages
    socket.on('chatMessage', ({ room, message }) => {
        io.to(room).emit('message', { username: user.username, message });
    });

    // Listen for room leave requests
    socket.on('leaveRoom', (room) => {
        const user = socket.request.session.user;
        if (user) {
            socket.leave(room);
            if (users[room]) {
                const index = users[room].indexOf(user.username);
                if (index !== -1) {
                    users[room].splice(index, 1);
                    io.to(room).emit('userList', users[room]);
                    io.to(room).emit('message', { username: 'System', message: `${user.username} has left the room.` });
                }
            }
    }
});

});





// Start the server
server.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});

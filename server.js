const express = require('express');
const bcrypt = require('bcrypt');
const session = require('express-session');
const { v4: uuidv4 } = require('uuid');

const app = express();

app.use(express.json());
app.use(session({
  genid: () => uuidv4(),
  secret: 'your-secret-key', // Change this to a secure random key in production
  resave: false,
  saveUninitialized: true
}));

const users = [];
const roles = { admin: 'admin', user: 'user' };

// Middleware to check if the user is authenticated
function isAuthenticated(req, res, next) {
  if (req.session.user) {
    return next();
  }
  res.status(401).send('Not authenticated');
}

// Middleware to check if the user has the required role
function checkRole(role) {
  return (req, res, next) => {
    if (req.session.user && req.session.user.role === role) {
      return next();
    }
    res.status(403).send('Access denied');
  };
}

// Root route
app.get('/', (req, res) => {
  res.send('Server is running');
});

// Users route (requires authentication)
app.get('/users', isAuthenticated, (req, res) => {
  res.json(users);
});

// Admin route (protected by checkRole middleware)
app.get('/admin', isAuthenticated, checkRole(roles.admin), (req, res) => {
  res.send('Welcome to the admin area');
});

// Post user route (Registration)
app.post('/users', async (req, res) => {
  try {
    const salt = await bcrypt.genSalt();
    const hashedPassword = await bcrypt.hash(req.body.password, salt);
    const user = {
      name: req.body.name,
      password: hashedPassword,
      role: req.body.role || roles.user // Default role is 'user'
    };
    users.push(user);
    res.status(201).send();
  } catch {
    res.status(500).send();
  }
});

// Login route
app.post('/users/login', async (req, res) => {
  const user = users.find(user => user.name === req.body.name);
  if (!user) {
    return res.status(400).send('Cannot find user');
  }
  try {
    if (await bcrypt.compare(req.body.password, user.password)) {
      req.session.user = { name: user.name, role: user.role };
      res.send('Login successful');
    } else {
      res.status(400).send('Login unsuccessful');
    }
  } catch {
    res.status(500).send();
  }
});

// Protected route (requires authentication)
app.get('/protected', isAuthenticated, (req, res) => {
  res.send('This is a protected route');
});

// Route to get hashed passwords (for debugging purposes only)
app.get('/hashes', isAuthenticated, checkRole(roles.admin), (req, res) => {
  res.json(users.map(user => ({ name: user.name, hashedPassword: user.password })));
});

// Catch-all route for undefined routes
app.use((req, res) => {
  res.status(404).send('Not Found');
});

const PORT = process.env.PORT || 4000;

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

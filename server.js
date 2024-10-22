const express = require('express');
const path = require('path');
const { open } = require('sqlite');
const sqlite3 = require('sqlite3');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const dbPath = path.join(__dirname, 'transaction.db');
const app = express();
const port = process.env.PORT || 4002;

app.use(express.json());
app.use(cors());

let dataBase = null;

const initializeDBAndServer = async () => {
    try {
        dataBase = await open({ filename: dbPath, driver: sqlite3.Database });
        app.listen(port, () => {
            console.log(`Server Running at ${port}`);
        });
    } catch (e) {
        console.log(`DB Error: ${e.message}`);
        process.exit(-1);
    }
};

initializeDBAndServer();

// Temporary user storage (replace with a database in production)
const users = [];

// User Registration Endpoint
app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    // Check if user already exists
    const existingUser = users.find(u => u.username === username);
    if (existingUser) {
        return res.status(400).json({ error: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    users.push({ username, password: hashedPassword });
    res.status(201).json({ message: 'User registered successfully' });
});

// User Login Endpoint
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username);

    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ username: user.username }, 'secret_key'); // Replace 'secret_key' with an environment variable in production
    res.json({ token });
});

// Middleware for Authenticating Routes
const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, 'secret_key', (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// Transactions Endpoints

// POST /transactions (Add a new transaction)
app.post('/transactions', authenticateToken, (req, res) => {
    const { type, category, amount, date, description } = req.body;
    const query = `INSERT INTO transactions (type, category, amount, date, description) VALUES (?, ?, ?, ?, ?)`;
    dataBase.run(query, [type, category, amount, date, description], function (err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ id: this.lastID });
    });
});

// GET /transactions (Retrieve all transactions with pagination)
app.get('/transactions', authenticateToken, (req, res) => {
    const { page = 1, limit = 10 } = req.query;
    const offset = (page - 1) * limit;

    const query = `SELECT * FROM transactions LIMIT ? OFFSET ?`;
    dataBase.all(query, [limit, offset], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ transactions: rows });
    });
});

// GET /transactions/:id (Retrieve a transaction by ID)
app.get('/transactions/:id', authenticateToken, (req, res) => {
    const { id } = req.params;
    const query = `SELECT * FROM transactions WHERE id = ?`;
    dataBase.get(query, [id], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!row) return res.status(404).json({ error: 'Transaction not found' });
        res.json({ transaction: row });
    });
});

// PUT /transactions/:id (Update a transaction by ID)
app.put('/transactions/:id', authenticateToken, (req, res) => {
    const { id } = req.params;
    const { type, category, amount, date, description } = req.body;
    const query = `UPDATE transactions SET type = ?, category = ?, amount = ?, date = ?, description = ? WHERE id = ?`;
    dataBase.run(query, [type, category, amount, date, description, id], function (err) {
        if (err) return res.status(500).json({ error: err.message });
        if (this.changes === 0) return res.status(404).json({ error: 'Transaction not found' });
        res.json({ updated: this.changes });
    });
});

// DELETE /transactions/:id (Delete a transaction by ID)
app.delete('/transactions/:id', authenticateToken, (req, res) => {
    const { id } = req.params;
    const query = `DELETE FROM transactions WHERE id = ?`;
    dataBase.run(query, [id], function (err) {
        if (err) return res.status(500).json({ error: err.message });
        if (this.changes === 0) return res.status(404).json({ error: 'Transaction not found' });
        res.json({ deleted: this.changes });
    });
});

// GET /summary (Summary of transactions)
app.get('/summary', authenticateToken, (req, res) => {
    const query = `
        SELECT 
            SUM(CASE WHEN type = 'income' THEN amount ELSE 0 END) as total_income,
            SUM(CASE WHEN type = 'expense' THEN amount ELSE 0 END) as total_expense,
            (SUM(CASE WHEN type = 'income' THEN amount ELSE 0 END) - 
             SUM(CASE WHEN type = 'expense' THEN amount ELSE 0 END)) as balance
        FROM transactions`;
    
    dataBase.get(query, [], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ summary: row });
    });
});

// GET /reports/monthly-category (Monthly spending by category)
app.get('/reports/monthly-category', authenticateToken, (req, res) => {
    const query = `
        SELECT category, SUM(amount) as total_spent
        FROM transactions
        GROUP BY category
    `;
    dataBase.all(query, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ monthly_spending: rows });
    });
});

module.exports = app;

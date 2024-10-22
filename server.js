const express = require('express');
const path = require('path');
const { open } = require('sqlite');
const sqlite3 = require('sqlite3');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const dbPath = path.join(__dirname, 'transaction.db');
const app = express();
const port = process.env.PORT || 4002;

app.use(express.json());
app.use(cors());

let dataBase = null;

const initializeDBAndServer = async () => {
    try {
        dataBase = await open({filename: dbPath, driver: sqlite3.Database});
        app.listen(port, () => {
            console.log(`Server Running at http://localhost:${port}`);
        });
    } catch (e) {
        console.error(`DB Error: ${e.message}`);
        process.exit(-1);
    }
};
initializeDBAndServer()

// Middleware for authentication
const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1]; // Bearer <token>
    if (!token) return res.sendStatus(401);
    
    jwt.verify(token, 'your_jwt_secret', (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user; // Attach user info to request
        next();
    });
};

// User registration
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const query = `INSERT INTO users (username, password) VALUES (?, ?)`;
    
    dataBase.run(query, [username, hashedPassword], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.status(201).json({ id: this.lastID });
    });
});

// User login
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const query = `SELECT * FROM users WHERE username = ?`;
    
    const user = await dataBase.get(query, [username]);
    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.sendStatus(401);
    }
    
    const token = jwt.sign({ id: user.id, username: user.username }, 'your_jwt_secret', { expiresIn: '1h' });
    res.json({ token });
});

// POST /transactions (Add a new transaction)
app.post('/transactions', authenticateToken, (req, res) => {
    const { type, category, amount, date, description } = req.body;
    const query = `INSERT INTO transactions (type, category, amount, date, description) 
                   VALUES (?, ?, ?, ?, ?)`;
    dataBase.run(query, [type, category, amount, date, description], function (err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ id: this.lastID });
    });
});

// GET /transactions (Retrieve all transactions) 
app.get('/transactions', authenticateToken, (req, res) => {
    const query = `SELECT * FROM transactions`;
    dataBase.all(query, [], (err, rows) => {
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
    const query = `UPDATE transactions 
                   SET type = ?, category = ?, amount = ?, date = ?, description = ?
                   WHERE id = ?`;
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
    const { fromDate, toDate, category } = req.query;
    let query = `SELECT 
                    SUM(CASE WHEN type = 'income' THEN amount ELSE 0 END) as total_income,
                    SUM(CASE WHEN type = 'expense' THEN amount ELSE 0 END) as total_expense,
                    (SUM(CASE WHEN type = 'income' THEN amount ELSE 0 END) - 
                     SUM(CASE WHEN type = 'expense' THEN amount ELSE 0 END)) as balance
                 FROM transactions`;
    
    const params = [];
    if (fromDate) {
        query += ` WHERE date >= ?`;
        params.push(fromDate);
    }
    if (toDate) {
        query += (params.length ? ' AND' : ' WHERE') + ` date <= ?`;
        params.push(toDate);
    }
    if (category) {
        query += (params.length ? ' AND' : ' WHERE') + ` category = ?`;
        params.push(category);
    }

    dataBase.get(query, params, (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ summary: row });
    });
});

module.exports = app;
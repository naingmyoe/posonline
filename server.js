// server.js
const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
const PORT = process.env.PORT || 8081;
const API_KEY = process.env.API_KEY || "my_secret_pos_key"; // VPS API Secret Key

app.use(cors());
app.use(express.json());

// Auth Middleware
function checkAuth(req, res, next) {
    const authHeader = req.headers['authorization'];
    const apiKeyHeader = req.headers['x-api-key'];
    const token = authHeader ? authHeader.replace('Bearer ', '') : apiKeyHeader;

    if (API_KEY && token !== API_KEY) {
        return res.status(401).json({ success: false, message: 'Unauthorized API Key' });
    }
    next();
}

// Database Setup (SQLite)
const dbPath = path.resolve(__dirname, 'pos_database.db');
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) console.error("Database Connection Error:", err.message);
    else console.log("Connected to POS SQLite Database on VPS.");
});

// Create Tables
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY,
        name TEXT,
        groupName TEXT,
        purchasePrice REAL,
        sellingPrice REAL,
        unit TEXT,
        note TEXT,
        trackStock INTEGER,
        barcode TEXT,
        quantity INTEGER,
        alertQuantity INTEGER,
        imageUri TEXT,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS vouchers (
        receiptNo TEXT PRIMARY KEY,
        timestamp INTEGER,
        cashierName TEXT,
        totalAmount REAL,
        totalItems INTEGER,
        customerName TEXT,
        paymentMethod TEXT,
        isCompleted INTEGER,
        paidAmount REAL,
        changeAmount REAL,
        balanceAmount REAL,
        note TEXT,
        discount REAL,
        fee REAL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
});

// 1. Connection Test Ping
app.get('/api/ping', (req, res) => {
    res.status(200).json({ status: "ok", message: "VPS POS Server is Running Online!" });
});
app.get('/ping', (req, res) => {
    res.status(200).json({ status: "ok", message: "VPS POS Server is Running Online!" });
});

// 2. Sync / Save Products
app.post('/api/products', checkAuth, (req, res) => {
    const p = req.body;
    const query = `INSERT INTO products (id, name, groupName, purchasePrice, sellingPrice, unit, note, trackStock, barcode, quantity, alertQuantity, imageUri)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(id) DO UPDATE SET
                   name=excluded.name, groupName=excluded.groupName, purchasePrice=excluded.purchasePrice,
                   sellingPrice=excluded.sellingPrice, unit=excluded.unit, note=excluded.note,
                   trackStock=excluded.trackStock, barcode=excluded.barcode, quantity=excluded.quantity,
                   alertQuantity=excluded.alertQuantity, imageUri=excluded.imageUri`;

    db.run(query, [
        p.id, p.name, p.groupName, p.purchasePrice, p.sellingPrice, p.unit, p.note,
        p.trackStock ? 1 : 0, p.barcode, p.quantity, p.alertQuantity, p.imageUri
    ], function(err) {
        if (err) return res.status(500).json({ success: false, error: err.message });
        res.json({ success: true, message: "Product synced to VPS successfully!" });
    });
});

// Get Products
app.get('/api/products', checkAuth, (req, res) => {
    db.all("SELECT * FROM products ORDER BY id DESC", [], (err, rows) => {
        if (err) return res.status(500).json({ success: false, error: err.message });
        res.json({ success: true, data: rows });
    });
});

// 3. Sync / Save Sales Voucher
app.post('/api/vouchers', checkAuth, (req, res) => {
    const v = req.body;
    const query = `INSERT INTO vouchers (receiptNo, timestamp, cashierName, totalAmount, totalItems, customerName, paymentMethod, isCompleted, paidAmount, changeAmount, balanceAmount, note, discount, fee)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(receiptNo) DO UPDATE SET
                   totalAmount=excluded.totalAmount, isCompleted=excluded.isCompleted, balanceAmount=excluded.balanceAmount`;

    db.run(query, [
        v.receiptNo, v.timestamp, v.cashierName, v.totalAmount, v.totalItems, v.customerName,
        v.paymentMethod, v.isCompleted ? 1 : 0, v.paidAmount, v.changeAmount, v.balanceAmount,
        v.note, v.discount, v.fee
    ], function(err) {
        if (err) return res.status(500).json({ success: false, error: err.message });
        res.json({ success: true, message: "Voucher synced to VPS successfully!" });
    });
});

// Get Vouchers
app.get('/api/vouchers', checkAuth, (req, res) => {
    db.all("SELECT * FROM vouchers ORDER BY timestamp DESC", [], (err, rows) => {
        if (err) return res.status(500).json({ success: false, error: err.message });
        res.json({ success: true, data: rows });
    });
});

app.listen(PORT, () => {
    console.log(`POS VPS API Server running on port ${PORT}`);
});

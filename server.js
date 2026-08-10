const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
const PORT = process.env.PORT || 8082;
const API_KEY = process.env.API_KEY || 'pos_secret_key_2026'; // သင့် API Key

app.use(cors());
app.use(express.json({ limit: '10mb' }));

// Database Connection
const db = new sqlite3.Database(path.join(__dirname, 'pos_cloud.db'), (err) => {
  if (err) {
    console.error('Database connection error:', err.message);
  } else {
    console.log('Connected to SQLite Database.');
  }
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
    quantity REAL,
    alertQuantity REAL,
    imageUri TEXT,
    updatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
    createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS customers (
    id INTEGER PRIMARY KEY,
    name TEXT,
    phone TEXT,
    address TEXT,
    note TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS suppliers (
    id INTEGER PRIMARY KEY,
    name TEXT,
    phone TEXT,
    address TEXT,
    note TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS expenses (
    id INTEGER PRIMARY KEY,
    categoryName TEXT,
    description TEXT,
    amount REAL,
    paymentMethod TEXT,
    note TEXT,
    timestamp INTEGER,
    dateString TEXT
  )`);
});

// Authentication Middleware (GET Request များကို Browser ကနေ တိုက်ရိုက် ကြည့်ခွင့်ပြုထားသည်)
const authenticate = (req, res, next) => {
  if (req.method === 'GET') {
    return next();
  }
  
  const reqKey = req.headers['x-api-key'] || req.headers['authorization']?.replace('Bearer ', '') || req.query.apiKey;
  if (reqKey && reqKey === API_KEY) {
    return next();
  }
  return res.status(401).json({ success: false, message: 'Unauthorized API Key' });
};

app.use(authenticate);

// Ping Endpoint
app.get('/ping', (req, res) => {
  res.json({ success: true, message: 'POS Cloud Server Active', timestamp: new Date() });
});

// --- PRODUCTS ---
app.get('/api/products', (req, res) => {
  db.all("SELECT * FROM products ORDER BY id DESC", [], (err, rows) => {
    if (err) return res.status(500).json({ success: false, error: err.message });
    res.json({ success: true, count: rows.length, data: rows });
  });
});

app.post('/api/products', (req, res) => {
  const p = req.body;
  const sql = `INSERT INTO products (id, name, groupName, purchasePrice, sellingPrice, unit, note, trackStock, barcode, quantity, alertQuantity, imageUri)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(id) DO UPDATE SET
               name=excluded.name, groupName=excluded.groupName, purchasePrice=excluded.purchasePrice,
               sellingPrice=excluded.sellingPrice, unit=excluded.unit, note=excluded.note,
               trackStock=excluded.trackStock, barcode=excluded.barcode, quantity=excluded.quantity,
               alertQuantity=excluded.alertQuantity, imageUri=excluded.imageUri`;
  
  db.run(sql, [p.id, p.name, p.groupName, p.purchasePrice, p.sellingPrice, p.unit, p.note, p.trackStock ? 1 : 0, p.barcode, p.quantity, p.alertQuantity, p.imageUri], function(err) {
    if (err) return res.status(500).json({ success: false, error: err.message });
    res.json({ success: true, id: p.id });
  });
});

// --- VOUCHERS ---
app.get('/api/vouchers', (req, res) => {
  db.all("SELECT * FROM vouchers ORDER BY timestamp DESC", [], (err, rows) => {
    if (err) return res.status(500).json({ success: false, error: err.message });
    res.json({ success: true, count: rows.length, data: rows });
  });
});

app.post('/api/vouchers', (req, res) => {
  const v = req.body;
  const sql = `INSERT INTO vouchers (receiptNo, timestamp, cashierName, totalAmount, totalItems, customerName, paymentMethod, isCompleted, paidAmount, changeAmount, balanceAmount, note, discount, fee)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(receiptNo) DO UPDATE SET
               totalAmount=excluded.totalAmount, totalItems=excluded.totalItems, paymentMethod=excluded.paymentMethod,
               isCompleted=excluded.isCompleted, paidAmount=excluded.paidAmount, changeAmount=excluded.changeAmount,
               balanceAmount=excluded.balanceAmount`;

  db.run(sql, [v.receiptNo, v.timestamp, v.cashierName, v.totalAmount, v.totalItems, v.customerName, v.paymentMethod, v.isCompleted ? 1 : 0, v.paidAmount, v.changeAmount, v.balanceAmount, v.note, v.discount, v.fee], function(err) {
    if (err) return res.status(500).json({ success: false, error: err.message });
    res.json({ success: true, receiptNo: v.receiptNo });
  });
});

// --- CUSTOMERS ---
app.get('/api/customers', (req, res) => {
  db.all("SELECT * FROM customers", [], (err, rows) => {
    if (err) return res.status(500).json({ success: false, error: err.message });
    res.json({ success: true, count: rows.length, data: rows });
  });
});

app.post('/api/customers', (req, res) => {
  const c = req.body;
  const sql = `INSERT INTO customers (id, name, phone, address, note) VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(id) DO UPDATE SET name=excluded.name, phone=excluded.phone, address=excluded.address, note=excluded.note`;
  db.run(sql, [c.id, c.name, c.phone, c.address, c.note], function(err) {
    if (err) return res.status(500).json({ success: false, error: err.message });
    res.json({ success: true, id: c.id });
  });
});

// --- SUPPLIERS ---
app.get('/api/suppliers', (req, res) => {
  db.all("SELECT * FROM suppliers", [], (err, rows) => {
    if (err) return res.status(500).json({ success: false, error: err.message });
    res.json({ success: true, count: rows.length, data: rows });
  });
});

app.post('/api/suppliers', (req, res) => {
  const s = req.body;
  const sql = `INSERT INTO suppliers (id, name, phone, address, note) VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(id) DO UPDATE SET name=excluded.name, phone=excluded.phone, address=excluded.address, note=excluded.note`;
  db.run(sql, [s.id, s.name, s.phone, s.address, s.note], function(err) {
    if (err) return res.status(500).json({ success: false, error: err.message });
    res.json({ success: true, id: s.id });
  });
});

// --- EXPENSES ---
app.get('/api/expenses', (req, res) => {
  db.all("SELECT * FROM expenses", [], (err, rows) => {
    if (err) return res.status(500).json({ success: false, error: err.message });
    res.json({ success: true, count: rows.length, data: rows });
  });
});

app.post('/api/expenses', (req, res) => {
  const e = req.body;
  const sql = `INSERT INTO expenses (id, categoryName, description, amount, paymentMethod, note, timestamp, dateString)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(id) DO UPDATE SET categoryName=excluded.categoryName, amount=excluded.amount, note=excluded.note`;
  db.run(sql, [e.id, e.categoryName, e.description, e.amount, e.paymentMethod, e.note, e.timestamp, e.dateString], function(err) {
    if (err) return res.status(500).json({ success: false, error: err.message });
    res.json({ success: true, id: e.id });
  });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`POS Cloud Server is running on port ${PORT}`);
});

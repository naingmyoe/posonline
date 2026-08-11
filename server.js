/**
 * POS Application Backend API Server
 * Runtime: Node.js (Express + SQLite3)
 * Default Port: 8082
 * 
 * Instructions to run on VPS:
 * 1. Install Node.js: sudo apt update && sudo apt install -y nodejs npm
 * 2. Install dependencies: npm install express cors sqlite3
 * 3. Start server: node server.js
 * 4. Or run with PM2: npm install -g pm2 && pm2 start server.js --name "pos-backend"
 */

const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
const PORT = process.env.PORT || 8082;

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Initialize SQLite Database
const dbPath = path.join(__dirname, 'pos_database.sqlite');
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('Error opening database:', err.message);
  } else {
    console.log('Connected to SQLite database at:', dbPath);
  }
});

// Helper for DB queries using Promises
const dbRun = (sql, params = []) => {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) reject(err);
      else resolve(this);
    });
  });
};

const dbAll = (sql, params = []) => {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });
};

const dbGet = (sql, params = []) => {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });
};

// Initialize Database Tables
async function initDatabase() {
  db.serialize(async () => {
    // 1. Users
    await dbRun(`
      CREATE TABLE IF NOT EXISTS users (
        phone_no TEXT PRIMARY KEY,
        username TEXT NOT NULL,
        business_name TEXT,
        business_type TEXT,
        address TEXT,
        role TEXT NOT NULL DEFAULT 'ADMIN',
        password_hash TEXT NOT NULL,
        device_id TEXT,
        status TEXT DEFAULT 'on',
        start_date TEXT,
        end_date TEXT,
        created_at INTEGER
      )
    `);

    // 2. Products
    await dbRun(`
      CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        group_name TEXT,
        purchase_price REAL DEFAULT 0,
        selling_price REAL DEFAULT 0,
        unit TEXT,
        note TEXT,
        track_stock INTEGER DEFAULT 1,
        barcode TEXT,
        quantity INTEGER DEFAULT 0,
        alert_quantity INTEGER DEFAULT 0,
        image_uri TEXT
      )
    `);

    // 3. Product Groups
    await dbRun(`
      CREATE TABLE IF NOT EXISTS product_groups (
        name TEXT PRIMARY KEY
      )
    `);

    // 4. Product Units
    await dbRun(`
      CREATE TABLE IF NOT EXISTS product_units (
        name TEXT PRIMARY KEY
      )
    `);

    // 5. Vouchers
    await dbRun(`
      CREATE TABLE IF NOT EXISTS vouchers (
        receipt_no TEXT PRIMARY KEY,
        timestamp INTEGER NOT NULL,
        cashier_name TEXT,
        total_amount REAL DEFAULT 0,
        total_items INTEGER DEFAULT 0,
        customer_name TEXT DEFAULT 'Not Register',
        payment_method TEXT DEFAULT 'CASH',
        is_completed INTEGER DEFAULT 1,
        is_purchase INTEGER DEFAULT 0,
        paid_amount REAL DEFAULT 0,
        change_amount REAL DEFAULT 0,
        balance_amount REAL DEFAULT 0,
        note TEXT,
        discount REAL DEFAULT 0,
        fee REAL DEFAULT 0
      )
    `);

    // 6. Voucher Items
    await dbRun(`
      CREATE TABLE IF NOT EXISTS voucher_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        voucher_id TEXT NOT NULL,
        product_id INTEGER,
        product_name TEXT,
        quantity INTEGER DEFAULT 1,
        purchase_price REAL DEFAULT 0,
        selling_price REAL DEFAULT 0
      )
    `);

    // 7. Customers
    await dbRun(`
      CREATE TABLE IF NOT EXISTS customers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        phone TEXT,
        address TEXT,
        note TEXT
      )
    `);

    // 8. Suppliers
    await dbRun(`
      CREATE TABLE IF NOT EXISTS suppliers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        phone TEXT,
        address TEXT,
        note TEXT
      )
    `);

    // 9. Payments
    await dbRun(`
      CREATE TABLE IF NOT EXISTS payments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        method TEXT NOT NULL,
        amount REAL DEFAULT 0,
        date INTEGER NOT NULL
      )
    `);

    // 10. Expense Categories
    await dbRun(`
      CREATE TABLE IF NOT EXISTS expense_categories (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        icon_name TEXT DEFAULT 'ShoppingCart'
      )
    `);

    // 11. Expenses
    await dbRun(`
      CREATE TABLE IF NOT EXISTS expenses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        category_name TEXT NOT NULL,
        description TEXT,
        amount REAL DEFAULT 0,
        payment_method TEXT,
        note TEXT,
        timestamp INTEGER NOT NULL,
        date_string TEXT,
        time_string TEXT
      )
    `);

    console.log('Database tables initialized successfully.');
  });
}

initDatabase();

// ----------------------------------------------------
// ROUTES
// ----------------------------------------------------

// Root Check
app.get('/', (req, res) => {
  res.json({ status: 'online', server: 'POS Backend API', port: PORT });
});

// 1. REGISTER USER
app.post('/api/register', async (req, res) => {
  try {
    const { phoneNo, username, businessName, businessType, address, role, password, deviceId, startDate, endDate } = req.body;

    if (!phoneNo || !username || !password) {
      return res.status(400).json({ success: false, message: 'Missing phoneNo, username, or password' });
    }

    const existing = await dbGet('SELECT * FROM users WHERE phone_no = ?', [phoneNo]);

    if (existing) {
      await dbRun(
        `UPDATE users SET username = ?, business_name = ?, business_type = ?, address = ?, role = ?, password_hash = ?, device_id = ?, status = 'on', start_date = ?, end_date = ? WHERE phone_no = ?`,
        [username, businessName || '', businessType || '', address || '', role || 'ADMIN', password, deviceId || '', startDate || '', endDate || '', phoneNo]
      );
      return res.json({
        success: true,
        message: 'User updated successfully',
        status: 'on',
        user: { phoneNo, username, businessName, businessType, address, role, deviceId, status: 'on', startDate, endDate }
      });
    }

    const now = Date.now();
    await dbRun(
      `INSERT INTO users (phone_no, username, business_name, business_type, address, role, password_hash, device_id, status, start_date, end_date, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'on', ?, ?, ?)`,
      [phoneNo, username, businessName || '', businessType || '', address || '', role || 'ADMIN', password, deviceId || '', startDate || '', endDate || '', now]
    );

    res.status(201).json({
      success: true,
      message: 'Registration successful',
      status: 'on',
      user: { phoneNo, username, businessName, businessType, address, role, deviceId, status: 'on', startDate, endDate }
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// 2. LOGIN USER
app.post('/api/login', async (req, res) => {
  try {
    const { phoneNo, password, deviceId } = req.body;

    const user = await dbGet('SELECT * FROM users WHERE phone_no = ?', [phoneNo]);
    if (!user) {
      return res.status(404).json({ success: false, message: 'Phone number not registered' });
    }

    if (user.password_hash !== password) {
      return res.status(401).json({ success: false, message: 'Incorrect password' });
    }

    res.json({
      success: true,
      status: user.status || 'on',
      user: {
        phoneNo: user.phone_no,
        username: user.username,
        businessName: user.business_name,
        businessType: user.business_type,
        address: user.address,
        role: user.role,
        deviceId: user.device_id || deviceId,
        status: user.status || 'on',
        startDate: user.start_date || '',
        endDate: user.end_date || ''
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// 3. GET ALL USERS
app.get('/api/users', async (req, res) => {
  try {
    const users = await dbAll('SELECT phone_no as phoneNo, username, business_name as businessName, business_type as businessType, address, role, device_id as deviceId, status, start_date as startDate, end_date as endDate FROM users');
    res.json({ success: true, users });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// 4. PRODUCTS API
app.get('/api/products', async (req, res) => {
  try {
    const products = await dbAll('SELECT id, name, group_name as groupName, purchase_price as purchasePrice, selling_price as sellingPrice, unit, note, track_stock as trackStock, barcode, quantity, alert_quantity as alertQuantity, image_uri as imageUri FROM products');
    res.json({ success: true, products });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/products', async (req, res) => {
  try {
    const p = req.body;
    const result = await dbRun(
      `INSERT INTO products (name, group_name, purchase_price, selling_price, unit, note, track_stock, barcode, quantity, alert_quantity, image_uri)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [p.name, p.groupName || '', p.purchasePrice || 0, p.sellingPrice || 0, p.unit || '', p.note || '', p.trackStock ? 1 : 0, p.barcode || '', p.quantity || 0, p.alertQuantity || 0, p.imageUri || '']
    );
    res.status(201).json({ success: true, id: result.lastID });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// 5. PRODUCT GROUPS
app.get('/api/product-groups', async (req, res) => {
  try {
    const groups = await dbAll('SELECT name FROM product_groups');
    res.json({ success: true, groups });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/product-groups', async (req, res) => {
  try {
    const { name } = req.body;
    if (name) {
      await dbRun('INSERT OR IGNORE INTO product_groups (name) VALUES (?)', [name]);
    }
    res.status(201).json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// 6. PRODUCT UNITS
app.get('/api/product-units', async (req, res) => {
  try {
    const units = await dbAll('SELECT name FROM product_units');
    res.json({ success: true, units });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/product-units', async (req, res) => {
  try {
    const { name } = req.body;
    if (name) {
      await dbRun('INSERT OR IGNORE INTO product_units (name) VALUES (?)', [name]);
    }
    res.status(201).json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// 7. VOUCHERS API
app.get('/api/vouchers', async (req, res) => {
  try {
    const vouchers = await dbAll('SELECT * FROM vouchers ORDER BY timestamp DESC');
    const voucherItems = await dbAll('SELECT * FROM voucher_items');
    res.json({ success: true, vouchers, voucherItems });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/vouchers', async (req, res) => {
  try {
    const v = req.body;
    await dbRun(
      `INSERT OR REPLACE INTO vouchers (receipt_no, timestamp, cashier_name, total_amount, total_items, customer_name, payment_method, is_completed, is_purchase, paid_amount, change_amount, balance_amount, note, discount, fee)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [v.receiptNo, v.timestamp || Date.now(), v.cashierName || '', v.totalAmount || 0, v.totalItems || 0, v.customerName || 'Not Register', v.paymentMethod || 'CASH', v.isCompleted ? 1 : 0, v.isPurchase ? 1 : 0, v.paidAmount || 0, v.changeAmount || 0, v.balanceAmount || 0, v.note || '', v.discount || 0, v.fee || 0]
    );

    if (v.items && Array.isArray(v.items)) {
      for (const item of v.items) {
        await dbRun(
          `INSERT INTO voucher_items (voucher_id, product_id, product_name, quantity, purchase_price, selling_price)
           VALUES (?, ?, ?, ?, ?, ?)`,
          [v.receiptNo, item.productId || 0, item.productName || '', item.quantity || 1, item.purchasePrice || 0, item.sellingPrice || 0]
        );
      }
    }
    res.status(201).json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// 8. CUSTOMERS
app.get('/api/customers', async (req, res) => {
  try {
    const customers = await dbAll('SELECT * FROM customers');
    res.json({ success: true, customers });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/customers', async (req, res) => {
  try {
    const c = req.body;
    const result = await dbRun(
      `INSERT INTO customers (name, phone, address, note) VALUES (?, ?, ?, ?)`,
      [c.name || '', c.phone || '', c.address || '', c.note || '']
    );
    res.status(201).json({ success: true, id: result.lastID });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// 9. SUPPLIERS
app.get('/api/suppliers', async (req, res) => {
  try {
    const suppliers = await dbAll('SELECT * FROM suppliers');
    res.json({ success: true, suppliers });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/suppliers', async (req, res) => {
  try {
    const s = req.body;
    const result = await dbRun(
      `INSERT INTO suppliers (name, phone, address, note) VALUES (?, ?, ?, ?)`,
      [s.name || '', s.phone || '', s.address || '', s.note || '']
    );
    res.status(201).json({ success: true, id: result.lastID });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// 10. EXPENSES & CATEGORIES
app.get('/api/expenses', async (req, res) => {
  try {
    const expenses = await dbAll('SELECT * FROM expenses ORDER BY timestamp DESC');
    res.json({ success: true, expenses });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/expenses', async (req, res) => {
  try {
    const e = req.body;
    const result = await dbRun(
      `INSERT INTO expenses (category_name, description, amount, payment_method, note, timestamp, date_string, time_string)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [e.categoryName || '', e.description || '', e.amount || 0, e.paymentMethod || '', e.note || '', e.timestamp || Date.now(), e.dateString || '', e.timeString || '']
    );
    res.status(201).json({ success: true, id: result.lastID });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// 11. PAYMENTS
app.get('/api/payments', async (req, res) => {
  try {
    const payments = await dbAll('SELECT * FROM payments');
    res.json({ success: true, payments });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/payments', async (req, res) => {
  try {
    const p = req.body;
    const result = await dbRun(
      `INSERT INTO payments (method, amount, date) VALUES (?, ?, ?)`,
      [p.method || '', p.amount || 0, p.date || Date.now()]
    );
    res.status(201).json({ success: true, id: result.lastID });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// 12. FULL SYNC ALL
app.get('/api/sync/all', async (req, res) => {
  try {
    const users = await dbAll('SELECT * FROM users');
    const products = await dbAll('SELECT * FROM products');
    const productGroups = await dbAll('SELECT * FROM product_groups');
    const productUnits = await dbAll('SELECT * FROM product_units');
    const vouchers = await dbAll('SELECT * FROM vouchers');
    const voucherItems = await dbAll('SELECT * FROM voucher_items');
    const customers = await dbAll('SELECT * FROM customers');
    const suppliers = await dbAll('SELECT * FROM suppliers');
    const expenses = await dbAll('SELECT * FROM expenses');
    const expenseCategories = await dbAll('SELECT * FROM expense_categories');
    const payments = await dbAll('SELECT * FROM payments');

    res.json({
      success: true,
      data: {
        users,
        products,
        productGroups,
        productUnits,
        vouchers,
        voucherItems,
        customers,
        suppliers,
        expenses,
        expenseCategories,
        payments
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Start Server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`========================================`);
  console.log(`POS Express Backend API is running!`);
  console.log(`Port: ${PORT}`);
  console.log(`Host: http://0.0.0.0:${PORT}`);
  console.log(`========================================`);
});

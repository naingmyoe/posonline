const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 8082;
const JWT_SECRET = process.env.JWT_SECRET || 'pos_jwt_secret_key_2026_super_secure';
const ADMIN_JWT_SECRET = process.env.ADMIN_JWT_SECRET || 'pos_admin_jwt_secret_2026';
const API_KEY = process.env.API_KEY || 'pos_secret_key_2026';

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Initialize SQLite Database
const dbPath = path.join(__dirname, 'pos_database.db');
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('Failed to connect to SQLite database:', err.message);
    } else {
        console.log('Connected to SQLite database at:', dbPath);
    }
});

// Database Initialization & Migrations
db.serialize(() => {
    // 0. Admins Table
    db.run(`CREATE TABLE IF NOT EXISTS admins (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        passwordHash TEXT NOT NULL,
        role TEXT DEFAULT 'SUPER_ADMIN',
        createdAt TEXT DEFAULT CURRENT_TIMESTAMP
    )`);

    // Seed default admin if missing
    db.get(`SELECT * FROM admins WHERE username = 'admin'`, [], async (err, row) => {
        if (!row) {
            const defaultHash = await bcrypt.hash('admin123', 10);
            db.run(`INSERT INTO admins (username, passwordHash, role) VALUES ('admin', ?, 'SUPER_ADMIN')`, [defaultHash]);
            console.log('Default Admin Account created: username="admin", password="admin123"');
        }
    });

    // 1. Users / Customers Table
    db.run(`CREATE TABLE IF NOT EXISTS users (
        phoneNo TEXT PRIMARY KEY,
        username TEXT NOT NULL,
        businessName TEXT,
        businessType TEXT,
        address TEXT,
        role TEXT DEFAULT 'ADMIN',
        passwordHash TEXT NOT NULL,
        deviceId TEXT,
        status TEXT DEFAULT 'on',
        createdAt TEXT DEFAULT CURRENT_TIMESTAMP,
        updatedAt TEXT DEFAULT CURRENT_TIMESTAMP
    )`);

    // 2. Licenses Table
    db.run(`CREATE TABLE IF NOT EXISTS licenses (
        licenseId INTEGER PRIMARY KEY AUTOINCREMENT,
        phoneNo TEXT UNIQUE NOT NULL,
        planName TEXT DEFAULT '7-Day Free Trial',
        startDate TEXT DEFAULT CURRENT_TIMESTAMP,
        expireDate TEXT NOT NULL,
        maxDevices INTEGER DEFAULT 5,
        status TEXT DEFAULT 'active',
        createdAt TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (phoneNo) REFERENCES users(phoneNo) ON DELETE CASCADE
    )`);

    // 3. Devices Table
    db.run(`CREATE TABLE IF NOT EXISTS devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        phoneNo TEXT NOT NULL,
        deviceId TEXT NOT NULL,
        deviceName TEXT DEFAULT 'Android Device',
        model TEXT,
        androidVersion TEXT,
        appVersion TEXT,
        lastSeen TEXT DEFAULT CURRENT_TIMESTAMP,
        status TEXT DEFAULT 'active',
        createdAt TEXT DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(phoneNo, deviceId)
    )`);

    // 4. Products Table (Multi-tenant)
    db.run(`CREATE TABLE IF NOT EXISTS products (
        id TEXT NOT NULL,
        syncId TEXT,
        phoneNo TEXT NOT NULL,
        name TEXT NOT NULL,
        price REAL DEFAULT 0,
        originalPrice REAL DEFAULT 0,
        stock INTEGER DEFAULT 0,
        category TEXT,
        barcode TEXT,
        imageUrl TEXT,
        isDeleted INTEGER DEFAULT 0,
        updatedAt TEXT DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id, phoneNo)
    )`);

    // 5. Vouchers / Sales Table (Multi-tenant)
    db.run(`CREATE TABLE IF NOT EXISTS vouchers (
        receiptNo TEXT NOT NULL,
        syncId TEXT,
        phoneNo TEXT NOT NULL,
        customerName TEXT,
        itemsJson TEXT NOT NULL,
        subtotal REAL DEFAULT 0,
        tax REAL DEFAULT 0,
        discount REAL DEFAULT 0,
        total REAL DEFAULT 0,
        paid REAL DEFAULT 0,
        changeAmount REAL DEFAULT 0,
        paymentType TEXT DEFAULT 'Cash',
        dateTime TEXT DEFAULT CURRENT_TIMESTAMP,
        isDeleted INTEGER DEFAULT 0,
        updatedAt TEXT DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (receiptNo, phoneNo)
    )`);

    // 6. Customers Table (Multi-tenant)
    db.run(`CREATE TABLE IF NOT EXISTS customers (
        id TEXT NOT NULL,
        syncId TEXT,
        phoneNo TEXT NOT NULL,
        name TEXT NOT NULL,
        customerPhone TEXT,
        address TEXT,
        debt REAL DEFAULT 0,
        isDeleted INTEGER DEFAULT 0,
        updatedAt TEXT DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id, phoneNo)
    )`);

    // 7. Suppliers Table (Multi-tenant)
    db.run(`CREATE TABLE IF NOT EXISTS suppliers (
        id TEXT NOT NULL,
        syncId TEXT,
        phoneNo TEXT NOT NULL,
        name TEXT NOT NULL,
        supplierPhone TEXT,
        company TEXT,
        payable REAL DEFAULT 0,
        isDeleted INTEGER DEFAULT 0,
        updatedAt TEXT DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id, phoneNo)
    )`);

    // 8. Expenses Table (Multi-tenant)
    db.run(`CREATE TABLE IF NOT EXISTS expenses (
        id TEXT NOT NULL,
        syncId TEXT,
        phoneNo TEXT NOT NULL,
        title TEXT NOT NULL,
        amount REAL DEFAULT 0,
        category TEXT,
        date TEXT,
        note TEXT,
        isDeleted INTEGER DEFAULT 0,
        updatedAt TEXT DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id, phoneNo)
    )`);

    // 9. System Logs Table
    db.run(`CREATE TABLE IF NOT EXISTS system_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        phoneNo TEXT,
        deviceId TEXT,
        action TEXT NOT NULL,
        message TEXT,
        createdAt TEXT DEFAULT CURRENT_TIMESTAMP
    )`);

    // 10. App Versions Table
    db.run(`CREATE TABLE IF NOT EXISTS app_versions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        versionName TEXT NOT NULL,
        versionCode INTEGER DEFAULT 1,
        downloadUrl TEXT NOT NULL,
        forceUpdate INTEGER DEFAULT 0,
        releaseNotes TEXT,
        createdAt TEXT DEFAULT CURRENT_TIMESTAMP
    )`);

    console.log('Database tables verified and ready.');
});

// Middleware: Route Authentication & Security
const securityMiddleware = (req, res, next) => {
    const publicRoutes = [
        '/api/register',
        '/api/auth/register',
        '/api/login',
        '/api/auth/login',
        '/api/admin/login',
        '/api/app/version',
        '/api/health',
        '/api/check-status',
        '/api/license/check'
    ];

    const reqPath = req.path.toLowerCase();
    if (publicRoutes.some(route => reqPath.endsWith(route) || reqPath === route)) {
        return next();
    }

    const apiKeyHeader = req.headers['x-api-key'];
    const authHeader = req.headers['authorization'];

    // 1. Allow X-API-KEY / Bearer with API_KEY
    if (apiKeyHeader === API_KEY || (authHeader && authHeader.includes(API_KEY))) {
        return next();
    }

    // 2. Check Admin JWT Token for Admin Routes (/api/admin/*)
    if (reqPath.startsWith('/api/admin')) {
        if (authHeader && authHeader.startsWith('Bearer ')) {
            const token = authHeader.split(' ')[1];
            try {
                const decoded = jwt.verify(token, ADMIN_JWT_SECRET);
                if (decoded && decoded.isAdmin) {
                    req.admin = decoded;
                    return next();
                }
            } catch (err) {
                try {
                    const userDecoded = jwt.verify(token, JWT_SECRET);
                    if (userDecoded && userDecoded.role === 'SUPER_ADMIN') {
                        req.user = userDecoded;
                        return next();
                    }
                } catch (e) {}
            }
        }
        return res.status(401).json({ success: false, message: 'Unauthorized: Admin authentication required' });
    }

    // 3. Regular JWT Token Verification for standard protected APIs
    if (authHeader && authHeader.startsWith('Bearer ')) {
        const token = authHeader.split(' ')[1];
        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            req.user = decoded;
            return next();
        } catch (err) {
            return res.status(401).json({ success: false, message: 'Unauthorized: Invalid or expired token' });
        }
    }

    // Fallback for mobile app backward compatibility
    next();
};

app.use(securityMiddleware);

// Helper Function: Log Activity
function logSystemAction(phoneNo, deviceId, action, message) {
    db.run(
        `INSERT INTO system_logs (phoneNo, deviceId, action, message) VALUES (?, ?, ?, ?)`,
        [phoneNo || 'SYSTEM', deviceId || 'N/A', action, message]
    );
}

// Helper Function: Check License Expiry
function checkAndGetLicense(phoneNo, callback) {
    db.get(`SELECT * FROM licenses WHERE phoneNo = ?`, [phoneNo], (err, license) => {
        if (err || !license) return callback(null, { isExpired: true, message: 'License not found' });
        
        const now = new Date();
        const exp = new Date(license.expireDate);
        if (license.status === 'blocked') {
            return callback(null, { isExpired: true, isBlocked: true, message: 'á€¡á€€á€±á€¬á€„á€·á€º á€¡á€žá€¯á€¶á€¸á€•á€¼á€¯á€á€½á€„á€·á€ºá€€á€­á€¯ á€•á€­á€á€ºá€‘á€¬á€¸á€•á€«á€žá€Šá€º (Account Blocked)' });
        }
        if (now > exp) {
            return callback(null, { isExpired: true, message: 'á€¡á€€á€±á€¬á€„á€·á€º á€žá€€á€ºá€á€™á€ºá€¸á€€á€¯á€”á€ºá€†á€¯á€¶á€¸á€žá€½á€¬á€¸á€•á€«á€•á€¼á€® (License Expired)' });
        }
        return callback(null, { isExpired: false, license });
    });
}

// ==========================================
// 1. ADMIN PANEL APIS
// ==========================================

// Admin Login
app.post('/api/admin/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ success: false, message: 'Username and password are required' });
    }

    db.get(`SELECT * FROM admins WHERE username = ?`, [username], async (err, admin) => {
        if (err || !admin) {
            return res.status(401).json({ success: false, message: 'Invalid admin credentials' });
        }

        const match = await bcrypt.compare(password, admin.passwordHash);
        if (!match) {
            return res.status(401).json({ success: false, message: 'Invalid admin credentials' });
        }

        const token = jwt.sign(
            { id: admin.id, username: admin.username, role: admin.role, isAdmin: true },
            ADMIN_JWT_SECRET,
            { expiresIn: '30d' }
        );

        logSystemAction('ADMIN', 'WEB', 'ADMIN_LOGIN', `Admin ${admin.username} logged in`);

        return res.json({
            success: true,
            message: 'Admin login successful',
            token,
            admin: {
                id: admin.id,
                username: admin.username,
                role: admin.role
            }
        });
    });
});

// Admin Dashboard Summary API
app.get('/api/admin/dashboard', (req, res) => {
    db.get(`SELECT COUNT(*) as totalCustomers FROM users`, [], (err, u) => {
        db.get(`SELECT COUNT(*) as activeLicenses FROM licenses WHERE status = 'active' AND datetime(expireDate) > datetime('now')`, [], (err, al) => {
            db.get(`SELECT COUNT(*) as expiredLicenses FROM licenses WHERE status = 'expired' OR datetime(expireDate) <= datetime('now')`, [], (err, el) => {
                db.get(`SELECT COUNT(*) as blockedAccounts FROM users WHERE status = 'off' OR phoneNo IN (SELECT phoneNo FROM licenses WHERE status = 'blocked')`, [], (err, ba) => {
                    db.get(`SELECT COUNT(*) as totalDevices FROM devices`, [], (err, td) => {
                        db.get(`SELECT COALESCE(SUM(total), 0) as todaySales FROM vouchers WHERE date(dateTime) = date('now') AND isDeleted = 0`, [], (err, ts) => {
                            db.get(`SELECT COALESCE(SUM(total), 0) as monthlySales FROM vouchers WHERE strftime('%Y-%m', dateTime) = strftime('%Y-%m', 'now') AND isDeleted = 0`, [], (err, ms) => {
                                res.json({
                                    success: true,
                                    totalCustomers: u ? u.totalCustomers : 0,
                                    activeLicenses: al ? al.activeLicenses : 0,
                                    expiredLicenses: el ? el.expiredLicenses : 0,
                                    blockedAccounts: ba ? ba.blockedAccounts : 0,
                                    totalDevices: td ? td.totalDevices : 0,
                                    todaySales: ts ? ts.todaySales : 0,
                                    monthlySales: ms ? ms.monthlySales : 0
                                });
                            });
                        });
                    });
                });
            });
        });
    });
});

// GET /api/admin/users (List all customers with license and device counts)
app.get(['/api/admin/users', '/api/admin/customers'], (req, res) => {
    db.all(
        `SELECT u.phoneNo, u.username, u.businessName, u.businessType, u.address, u.role, u.status as accountStatus, u.createdAt,
                l.planName, l.expireDate, l.maxDevices, l.status as licenseStatus,
                (SELECT COUNT(*) FROM devices d WHERE d.phoneNo = u.phoneNo) as deviceCount,
                (SELECT COALESCE(SUM(v.total), 0) FROM vouchers v WHERE v.phoneNo = u.phoneNo AND v.isDeleted = 0) as totalSales
         FROM users u 
         LEFT JOIN licenses l ON u.phoneNo = l.phoneNo 
         ORDER BY u.createdAt DESC`,
        [],
        (err, rows) => {
            if (err) return res.status(500).json({ success: false, message: err.message });
            res.json({ success: true, users: rows || [], customers: rows || [] });
        }
    );
});

// GET /api/admin/users/:phoneNo (Customer Details)
app.get('/api/admin/users/:phoneNo', (req, res) => {
    const phoneNo = req.params.phoneNo;
    db.get(`SELECT u.phoneNo, u.username, u.businessName, u.businessType, u.address, u.role, u.status as accountStatus, u.createdAt, l.planName, l.expireDate, l.maxDevices, l.status as licenseStatus FROM users u LEFT JOIN licenses l ON u.phoneNo = l.phoneNo WHERE u.phoneNo = ?`, [phoneNo], (err, user) => {
        if (err || !user) return res.status(404).json({ success: false, message: 'Customer not found' });

        db.all(`SELECT * FROM devices WHERE phoneNo = ?`, [phoneNo], (err, devices) => {
            db.get(`SELECT COUNT(*) as totalVouchers, COALESCE(SUM(total), 0) as totalRevenue FROM vouchers WHERE phoneNo = ? AND isDeleted = 0`, [phoneNo], (err, sales) => {
                res.json({
                    success: true,
                    user,
                    devices: devices || [],
                    salesStats: sales || { totalVouchers: 0, totalRevenue: 0 }
                });
            });
        });
    });
});

// POST /api/admin/users/block
app.post(['/api/admin/users/block', '/api/admin/license/block', '/api/license/block'], (req, res) => {
    const { phoneNo } = req.body;
    if (!phoneNo) return res.status(400).json({ success: false, message: 'phoneNo is required' });

    db.run(`UPDATE users SET status = 'off' WHERE phoneNo = ?`, [phoneNo]);
    db.run(`UPDATE licenses SET status = 'blocked' WHERE phoneNo = ?`, [phoneNo], (err) => {
        logSystemAction(phoneNo, '', 'BLOCK_ACCOUNT', 'Account and license blocked by Admin');
        res.json({ success: true, message: `Account ${phoneNo} has been blocked successfully` });
    });
});

// POST /api/admin/users/unblock
app.post(['/api/admin/users/unblock', '/api/admin/license/unblock'], (req, res) => {
    const { phoneNo } = req.body;
    if (!phoneNo) return res.status(400).json({ success: false, message: 'phoneNo is required' });

    db.run(`UPDATE users SET status = 'on' WHERE phoneNo = ?`, [phoneNo]);
    db.run(`UPDATE licenses SET status = 'active' WHERE phoneNo = ?`, [phoneNo], (err) => {
        logSystemAction(phoneNo, '', 'UNBLOCK_ACCOUNT', 'Account and license unblocked by Admin');
        res.json({ success: true, message: `Account ${phoneNo} has been unblocked/activated successfully` });
    });
});

// DELETE /api/admin/users/:phoneNo
app.delete('/api/admin/users/:phoneNo', (req, res) => {
    const phoneNo = req.params.phoneNo;
    if (!phoneNo) return res.status(400).json({ success: false, message: 'phoneNo is required' });

    db.run(`DELETE FROM users WHERE phoneNo = ?`, [phoneNo]);
    db.run(`DELETE FROM licenses WHERE phoneNo = ?`, [phoneNo]);
    db.run(`DELETE FROM devices WHERE phoneNo = ?`, [phoneNo]);
    db.run(`DELETE FROM products WHERE phoneNo = ?`, [phoneNo]);
    db.run(`DELETE FROM vouchers WHERE phoneNo = ?`, [phoneNo]);
    db.run(`DELETE FROM customers WHERE phoneNo = ?`, [phoneNo]);
    db.run(`DELETE FROM suppliers WHERE phoneNo = ?`, [phoneNo]);
    db.run(`DELETE FROM expenses WHERE phoneNo = ?`, [phoneNo]);

    logSystemAction(phoneNo, '', 'DELETE_CUSTOMER', `Customer account ${phoneNo} and all associated data deleted by Admin`);
    res.json({ success: true, message: `Customer ${phoneNo} and all data deleted successfully` });
});

// POST /api/admin/license/extend
app.post(['/api/admin/license/extend', '/api/license/extend'], (req, res) => {
    const { phoneNo, days, daysToAdd, planName, maxDevices } = req.body;
    const daysNum = parseInt(days || daysToAdd) || 30;

    db.get(`SELECT * FROM licenses WHERE phoneNo = ?`, [phoneNo], (err, license) => {
        let baseDate = new Date();
        if (license && new Date(license.expireDate) > baseDate) {
            baseDate = new Date(license.expireDate);
        }
        baseDate.setDate(baseDate.getDate() + daysNum);

        const newExpire = baseDate.toISOString();
        const plan = planName || (license ? license.planName : 'VIP License');
        const maxDev = maxDevices || (license ? license.maxDevices : 5);

        db.run(
            `INSERT OR REPLACE INTO licenses (phoneNo, planName, startDate, expireDate, maxDevices, status)
             VALUES (?, ?, CURRENT_TIMESTAMP, ?, ?, 'active')`,
            [phoneNo, plan, newExpire, maxDev],
            (err) => {
                if (err) return res.status(500).json({ success: false, message: err.message });
                logSystemAction(phoneNo, '', 'LICENSE_EXTEND', `License extended by ${daysNum} days until ${newExpire}`);
                res.json({ success: true, message: `License extended until ${newExpire}`, expireDate: newExpire });
            }
        );
    });
});

// POST /api/admin/license/change-plan
app.post('/api/admin/license/change-plan', (req, res) => {
    const { phoneNo, planName, days, maxDevices } = req.body;
    if (!phoneNo || !planName) return res.status(400).json({ success: false, message: 'phoneNo and planName required' });

    let addDays = parseInt(days) || 30;
    if (planName.toLowerCase().includes('trial')) addDays = 7;
    if (planName.toLowerCase().includes('monthly')) addDays = 30;
    if (planName.toLowerCase().includes('yearly')) addDays = 365;
    if (planName.toLowerCase().includes('lifetime')) addDays = 36500; // 100 years

    const expireDate = new Date();
    expireDate.setDate(expireDate.getDate() + addDays);

    db.run(
        `INSERT OR REPLACE INTO licenses (phoneNo, planName, startDate, expireDate, maxDevices, status)
         VALUES (?, ?, CURRENT_TIMESTAMP, ?, ?, 'active')`,
        [phoneNo, planName, expireDate.toISOString(), maxDevices || 5],
        (err) => {
            if (err) return res.status(500).json({ success: false, message: err.message });
            logSystemAction(phoneNo, '', 'CHANGE_PLAN', `License plan changed to ${planName} expiring ${expireDate.toISOString()}`);
            res.json({ success: true, message: `Plan changed to ${planName}`, expireDate: expireDate.toISOString() });
        }
    );
});

// Device Management
app.get('/api/admin/devices', (req, res) => {
    db.all(`SELECT * FROM devices ORDER BY lastSeen DESC`, [], (err, rows) => {
        res.json({ success: true, devices: rows || [] });
    });
});

app.get('/api/admin/devices/:phoneNo', (req, res) => {
    const phoneNo = req.params.phoneNo;
    db.all(`SELECT * FROM devices WHERE phoneNo = ? ORDER BY lastSeen DESC`, [phoneNo], (err, rows) => {
        res.json({ success: true, devices: rows || [] });
    });
});

app.delete('/api/admin/devices/:id', (req, res) => {
    const id = req.params.id;
    db.run(`DELETE FROM devices WHERE id = ?`, [id], (err) => {
        logSystemAction('ADMIN', '', 'REMOVE_DEVICE', `Device ID ${id} removed by admin`);
        res.json({ success: true, message: 'Device removed successfully' });
    });
});

// Admin Inspection APIs (View Customer POS Data)
app.get('/api/admin/users/:phoneNo/products', (req, res) => {
    db.all(`SELECT * FROM products WHERE phoneNo = ? AND isDeleted = 0`, [req.params.phoneNo], (err, rows) => {
        res.json({ success: true, products: rows || [] });
    });
});

app.get('/api/admin/users/:phoneNo/vouchers', (req, res) => {
    db.all(`SELECT * FROM vouchers WHERE phoneNo = ? AND isDeleted = 0 ORDER BY dateTime DESC`, [req.params.phoneNo], (err, rows) => {
        res.json({ success: true, vouchers: rows || [] });
    });
});

app.get('/api/admin/users/:phoneNo/customers', (req, res) => {
    db.all(`SELECT * FROM customers WHERE phoneNo = ? AND isDeleted = 0`, [req.params.phoneNo], (err, rows) => {
        res.json({ success: true, customers: rows || [] });
    });
});

app.get('/api/admin/users/:phoneNo/expenses', (req, res) => {
    db.all(`SELECT * FROM expenses WHERE phoneNo = ? AND isDeleted = 0 ORDER BY date DESC`, [req.params.phoneNo], (err, rows) => {
        res.json({ success: true, expenses: rows || [] });
    });
});

// System Logs API
app.get('/api/admin/logs', (req, res) => {
    const { phoneNo, action } = req.query;
    let query = `SELECT * FROM system_logs`;
    let params = [];
    
    if (phoneNo && action) {
        query += ` WHERE phoneNo = ? AND action = ?`;
        params.push(phoneNo, action);
    } else if (phoneNo) {
        query += ` WHERE phoneNo = ?`;
        params.push(phoneNo);
    } else if (action) {
        query += ` WHERE action = ?`;
        params.push(action);
    }

    query += ` ORDER BY createdAt DESC LIMIT 300`;

    db.all(query, params, (err, rows) => {
        res.json({ success: true, logs: rows || [] });
    });
});

// App Version Management
app.post('/api/admin/app/version', (req, res) => {
    const { versionName, versionCode, downloadUrl, forceUpdate, releaseNotes } = req.body;
    db.run(
        `INSERT INTO app_versions (versionName, versionCode, downloadUrl, forceUpdate, releaseNotes) VALUES (?, ?, ?, ?, ?)`,
        [versionName, versionCode || 1, downloadUrl, forceUpdate ? 1 : 0, releaseNotes || ''],
        (err) => {
            logSystemAction('ADMIN', '', 'NEW_APP_VERSION', `Published new app version ${versionName}`);
            res.json({ success: true, message: 'App version updated successfully' });
        }
    );
});

// ==========================================
// 2. MOBILE APP AUTH & USER APIS
// ==========================================

app.post(['/api/register', '/api/auth/register'], async (req, res) => {
    const { phoneNo, phone, username, businessName, businessType, address, role, password, deviceId, deviceName } = req.body;
    const userPhone = (phoneNo || phone || '').trim();
    const rawPass = password || '123456';
    
    if (!userPhone) {
        return res.status(400).json({ success: false, message: 'Phone number is required' });
    }

    db.get(`SELECT * FROM users WHERE phoneNo = ?`, [userPhone], async (err, existing) => {
        if (existing) {
            return res.status(400).json({ 
                success: false, 
                message: 'á€¤á€–á€¯á€”á€ºá€¸á€”á€¶á€•á€«á€á€ºá€–á€¼á€„á€·á€º á€¡á€€á€±á€¬á€„á€·á€ºá€•á€¼á€¯á€œá€¯á€•á€ºá€•á€¼á€®á€¸á€žá€¬á€¸á€–á€¼á€…á€ºá€•á€«á€žá€Šá€º (Phone number already registered)' 
            });
        }

        const hash = await bcrypt.hash(rawPass, 10);
        const devId = deviceId || 'DEV_' + Date.now();

        db.run(
            `INSERT INTO users (phoneNo, username, businessName, businessType, address, role, passwordHash, deviceId, status)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'on')`,
            [userPhone, username || 'User', businessName || '', businessType || '', address || '', role || 'ADMIN', hash, devId],
            function (err) {
                if (err) {
                    return res.status(500).json({ success: false, message: 'Failed to create user account: ' + err.message });
                }

                const startDate = new Date();
                const expireDate = new Date();
                expireDate.setDate(startDate.getDate() + 7);

                db.run(
                    `INSERT INTO licenses (phoneNo, planName, startDate, expireDate, maxDevices, status)
                     VALUES (?, '7-Day Free Trial', ?, ?, 5, 'active')`,
                    [userPhone, startDate.toISOString(), expireDate.toISOString()]
                );

                db.run(
                    `INSERT OR REPLACE INTO devices (phoneNo, deviceId, deviceName, status, lastSeen)
                     VALUES (?, ?, ?, 'active', CURRENT_TIMESTAMP)`,
                    [userPhone, devId, deviceName || 'Android POS Device']
                );

                logSystemAction(userPhone, devId, 'REGISTER', 'User registered with 7-day trial license');

                const token = jwt.sign({ phoneNo: userPhone, role: role || 'ADMIN' }, JWT_SECRET, { expiresIn: '365d' });

                return res.json({
                    success: true,
                    message: 'á€¡á€€á€±á€¬á€„á€·á€ºá€žá€…á€º á€¡á€±á€¬á€„á€ºá€™á€¼á€„á€ºá€…á€½á€¬ á€•á€¼á€¯á€œá€¯á€•á€ºá€•á€¼á€®á€¸á€•á€«á€•á€¼á€® (á‡ á€›á€€á€º á€¡á€á€™á€²á€· á€…á€™á€ºá€¸á€žá€•á€ºá€á€½á€„á€·á€º á€›á€›á€¾á€­á€•á€«á€žá€Šá€º)',
                    token,
                    user: {
                        phoneNo: userPhone,
                        username: username || 'User',
                        businessName: businessName || '',
                        businessType: businessType || '',
                        address: address || '',
                        role: role || 'ADMIN',
                        deviceId: devId,
                        status: 'on',
                        expireDate: expireDate.toISOString()
                    }
                });
            }
        );
    });
});

app.post(['/api/login', '/api/auth/login'], async (req, res) => {
    const { phoneNo, phone, password, deviceId, deviceName } = req.body;
    const userPhone = (phoneNo || phone || '').trim();

    if (!userPhone) {
        return res.status(400).json({ success: false, status: 'not_found', message: 'Phone number is required' });
    }

    db.get(`SELECT * FROM users WHERE phoneNo = ?`, [userPhone], async (err, user) => {
        if (err || !user) {
            return res.status(404).json({
                success: false,
                status: 'not_found',
                message: 'á€¤á€–á€¯á€”á€ºá€¸á€”á€¶á€•á€«á€á€ºá€–á€¼á€„á€·á€º á€¡á€€á€±á€¬á€„á€·á€ºá€–á€½á€„á€·á€ºá€‘á€¬á€¸á€á€¼á€„á€ºá€¸ á€™á€›á€¾á€­á€•á€« (Account not registered)'
            });
        }

        const match = await bcrypt.compare(password || '', user.passwordHash) || (password === user.passwordHash);
        if (!match) {
            return res.status(401).json({
                success: false,
                status: 'invalid_password',
                message: 'Password á€™á€¾á€¬á€¸á€šá€½á€„á€ºá€¸á€”á€±á€•á€«á€žá€Šá€º (Incorrect password)'
            });
        }

        checkAndGetLicense(userPhone, (err, licResult) => {
            if (licResult.isExpired) {
                return res.status(403).json({
                    success: false,
                    status: 'expired',
                    message: licResult.message
                });
            }

            const currentDeviceId = deviceId || user.deviceId || 'DEV_' + Date.now();

            db.all(`SELECT * FROM devices WHERE phoneNo = ? AND status = 'active'`, [userPhone], (err, activeDevices) => {
                const deviceExists = activeDevices.some(d => d.deviceId === currentDeviceId);
                const maxDevices = licResult.license ? licResult.license.maxDevices : 5;

                if (!deviceExists && activeDevices.length >= maxDevices) {
                    return res.status(403).json({
                        success: false,
                        status: 'device_limit_exceeded',
                        message: `á€á€„á€ºá€›á€±á€¬á€€á€ºá€á€½á€„á€·á€ºá€•á€¼á€¯á€‘á€¬á€¸á€žá€±á€¬ Device á€¡á€›á€±á€¡á€á€½á€€á€º (${maxDevices}) á€œá€¯á€¶á€¸ á€•á€¼á€Šá€·á€ºá€žá€½á€¬á€¸á€•á€«á€•á€¼á€®`
                    });
                }

                db.run(
                    `INSERT OR REPLACE INTO devices (phoneNo, deviceId, deviceName, status, lastSeen)
                     VALUES (?, ?, ?, 'active', CURRENT_TIMESTAMP)`,
                    [userPhone, currentDeviceId, deviceName || 'Android POS Device']
                );

                logSystemAction(userPhone, currentDeviceId, 'LOGIN', 'User logged in successfully');

                const token = jwt.sign({ phoneNo: userPhone, role: user.role }, JWT_SECRET, { expiresIn: '365d' });

                return res.json({
                    success: true,
                    status: 'on',
                    message: 'Login á€¡á€±á€¬á€„á€ºá€™á€¼á€„á€ºá€•á€«á€žá€Šá€º',
                    token,
                    user: {
                        phoneNo: user.phoneNo,
                        username: user.username,
                        businessName: user.businessName,
                        businessType: user.businessType,
                        address: user.address,
                        role: user.role,
                        deviceId: currentDeviceId,
                        status: 'on',
                        expireDate: licResult.license ? licResult.license.expireDate : ''
                    }
                });
            });
        });
    });
});

app.post(['/api/check-status', '/api/license/check'], (req, res) => {
    const { phoneNo, phone } = req.body;
    const userPhone = (phoneNo || phone || '').trim();

    if (!userPhone) {
        return res.json({ success: false, status: 'off', message: 'Phone number missing' });
    }

    db.get(`SELECT * FROM users WHERE phoneNo = ?`, [userPhone], (err, user) => {
        if (!user) {
            return res.json({ success: false, status: 'not_found', message: 'User not found' });
        }

        checkAndGetLicense(userPhone, (err, licResult) => {
            if (licResult.isExpired) {
                return res.json({
                    success: false,
                    status: 'expired',
                    message: licResult.message,
                    user: { ...user, status: 'expired' }
                });
            }

            return res.json({
                success: true,
                status: 'on',
                message: 'Account is active',
                user: {
                    phoneNo: user.phoneNo,
                    username: user.username,
                    businessName: user.businessName,
                    businessType: user.businessType,
                    address: user.address,
                    role: user.role,
                    deviceId: user.deviceId,
                    status: 'on',
                    expireDate: licResult.license ? licResult.license.expireDate : ''
                }
            });
        });
    });
});

app.post('/api/change-password', async (req, res) => {
    const { phoneNo, phone, oldPassword, newPassword } = req.body;
    const userPhone = (phoneNo || phone || '').trim();

    db.get(`SELECT * FROM users WHERE phoneNo = ?`, [userPhone], async (err, user) => {
        if (!user) return res.status(404).json({ success: false, message: 'User not found' });

        const match = await bcrypt.compare(oldPassword || '', user.passwordHash) || (oldPassword === user.passwordHash);
        if (!match) return res.status(400).json({ success: false, message: 'Old password is incorrect' });

        const newHash = await bcrypt.hash(newPassword, 10);
        db.run(`UPDATE users SET passwordHash = ? WHERE phoneNo = ?`, [newHash, userPhone], (err) => {
            logSystemAction(userPhone, user.deviceId, 'PASSWORD_CHANGE', 'Password changed');
            return res.json({ success: true, message: 'Password changed successfully' });
        });
    });
});

app.post('/api/delete-user', async (req, res) => {
    const { phoneNo, phone, password } = req.body;
    const userPhone = (phoneNo || phone || '').trim();

    db.get(`SELECT * FROM users WHERE phoneNo = ?`, [userPhone], async (err, user) => {
        if (!user) return res.status(404).json({ success: false, message: 'User not found' });

        const match = await bcrypt.compare(password || '', user.passwordHash) || (password === user.passwordHash);
        if (!match) return res.status(400).json({ success: false, message: 'Password incorrect' });

        db.run(`DELETE FROM users WHERE phoneNo = ?`, [userPhone]);
        db.run(`DELETE FROM licenses WHERE phoneNo = ?`, [userPhone]);
        db.run(`DELETE FROM devices WHERE phoneNo = ?`, [userPhone]);
        logSystemAction(userPhone, '', 'DELETE_ACCOUNT', 'User account deleted');

        return res.json({ success: true, message: 'Account deleted successfully' });
    });
});

// ==========================================
// 3. DEVICE MANAGEMENT APIS
// ==========================================

app.post('/api/device/register', (req, res) => {
    const { phoneNo, deviceId, deviceName, model, androidVersion, appVersion } = req.body;
    db.run(
        `INSERT OR REPLACE INTO devices (phoneNo, deviceId, deviceName, model, androidVersion, appVersion, status, lastSeen)
         VALUES (?, ?, ?, ?, ?, ?, 'active', CURRENT_TIMESTAMP)`,
        [phoneNo, deviceId, deviceName || 'Android POS', model || '', androidVersion || '', appVersion || '1.0'],
        (err) => {
            if (err) return res.status(500).json({ success: false, message: err.message });
            logSystemAction(phoneNo, deviceId, 'DEVICE_REGISTER', 'Device registered/updated');
            res.json({ success: true, message: 'Device registered successfully' });
        }
    );
});

app.post('/api/device/heartbeat', (req, res) => {
    const { phoneNo, deviceId } = req.body;
    db.run(
        `UPDATE devices SET lastSeen = CURRENT_TIMESTAMP WHERE phoneNo = ? AND deviceId = ?`,
        [phoneNo, deviceId],
        (err) => {
            res.json({ success: true, message: 'Heartbeat received' });
        }
    );
});

app.get('/api/devices', (req, res) => {
    const phoneNo = req.query.phoneNo;
    db.all(`SELECT * FROM devices WHERE phoneNo = ?`, [phoneNo], (err, rows) => {
        res.json({ success: true, devices: rows || [] });
    });
});

app.post('/api/device/block', (req, res) => {
    const { phoneNo, deviceId } = req.body;
    db.run(`UPDATE devices SET status = 'blocked' WHERE phoneNo = ? AND deviceId = ?`, [phoneNo, deviceId], (err) => {
        logSystemAction(phoneNo, deviceId, 'DEVICE_BLOCK', 'Device blocked by admin');
        res.json({ success: true, message: 'Device blocked' });
    });
});

app.post('/api/device/unblock', (req, res) => {
    const { phoneNo, deviceId } = req.body;
    db.run(`UPDATE devices SET status = 'active' WHERE phoneNo = ? AND deviceId = ?`, [phoneNo, deviceId], (err) => {
        logSystemAction(phoneNo, deviceId, 'DEVICE_UNBLOCK', 'Device unblocked by admin');
        res.json({ success: true, message: 'Device unblocked' });
    });
});

// ==========================================
// 4. MULTI-TENANT POS DATA SYNC & REST APIS
// ==========================================

// PRODUCTS
app.get('/api/products', (req, res) => {
    const phoneNo = req.query.phoneNo || req.query.phone;
    if (!phoneNo) return res.status(400).json({ error: 'phoneNo parameter required for multi-tenant isolation' });

    db.all(`SELECT * FROM products WHERE phoneNo = ? AND isDeleted = 0`, [phoneNo], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows || []);
    });
});

app.post('/api/products', (req, res) => {
    const item = req.body;
    const phoneNo = item.phoneNo || req.query.phoneNo;
    if (!phoneNo) return res.status(400).json({ error: 'phoneNo required' });

    db.run(
        `INSERT OR REPLACE INTO products (id, syncId, phoneNo, name, price, originalPrice, stock, category, barcode, imageUrl, isDeleted, updatedAt)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, CURRENT_TIMESTAMP)`,
        [item.id, item.syncId || item.id, phoneNo, item.name, item.price || 0, item.originalPrice || 0, item.stock || 0, item.category || '', item.barcode || '', item.imageUrl || ''],
        (err) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true, message: 'Product saved' });
        }
    );
});

app.delete('/api/products/:id', (req, res) => {
    const phoneNo = req.query.phoneNo;
    const id = req.params.id;
    db.run(`UPDATE products SET isDeleted = 1, updatedAt = CURRENT_TIMESTAMP WHERE id = ? AND phoneNo = ?`, [id, phoneNo], (err) => {
        res.json({ success: true, message: 'Product marked as deleted' });
    });
});

// VOUCHERS
app.get('/api/vouchers', (req, res) => {
    const phoneNo = req.query.phoneNo || req.query.phone;
    if (!phoneNo) return res.status(400).json({ error: 'phoneNo parameter required' });

    db.all(`SELECT * FROM vouchers WHERE phoneNo = ? AND isDeleted = 0`, [phoneNo], (err, rows) => {
        res.json(rows || []);
    });
});

app.post('/api/vouchers', (req, res) => {
    const item = req.body;
    const phoneNo = item.phoneNo || req.query.phoneNo;
    if (!phoneNo) return res.status(400).json({ error: 'phoneNo required' });

    db.run(
        `INSERT OR REPLACE INTO vouchers (receiptNo, syncId, phoneNo, customerName, itemsJson, subtotal, tax, discount, total, paid, changeAmount, paymentType, dateTime, isDeleted, updatedAt)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, CURRENT_TIMESTAMP)`,
        [item.receiptNo, item.syncId || item.receiptNo, phoneNo, item.customerName || '', item.itemsJson || '[]', item.subtotal || 0, item.tax || 0, item.discount || 0, item.total || 0, item.paid || 0, item.changeAmount || 0, item.paymentType || 'Cash', item.dateTime || new Date().toISOString()],
        (err) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true, message: 'Voucher saved' });
        }
    );
});

app.delete('/api/vouchers/:receiptNo', (req, res) => {
    const phoneNo = req.query.phoneNo;
    const receiptNo = req.params.receiptNo;
    db.run(`UPDATE vouchers SET isDeleted = 1, updatedAt = CURRENT_TIMESTAMP WHERE receiptNo = ? AND phoneNo = ?`, [receiptNo, phoneNo], (err) => {
        res.json({ success: true, message: 'Voucher deleted' });
    });
});

// CUSTOMERS
app.get('/api/customers', (req, res) => {
    const phoneNo = req.query.phoneNo;
    db.all(`SELECT * FROM customers WHERE phoneNo = ? AND isDeleted = 0`, [phoneNo], (err, rows) => {
        res.json(rows || []);
    });
});

app.post('/api/customers', (req, res) => {
    const item = req.body;
    const phoneNo = item.phoneNo || req.query.phoneNo;
    db.run(
        `INSERT OR REPLACE INTO customers (id, syncId, phoneNo, name, customerPhone, address, debt, isDeleted, updatedAt)
         VALUES (?, ?, ?, ?, ?, ?, ?, 0, CURRENT_TIMESTAMP)`,
        [item.id, item.syncId || item.id, phoneNo, item.name, item.customerPhone || '', item.address || '', item.debt || 0],
        (err) => { res.json({ success: true }); }
    );
});

app.delete('/api/customers/:id', (req, res) => {
    db.run(`UPDATE customers SET isDeleted = 1, updatedAt = CURRENT_TIMESTAMP WHERE id = ? AND phoneNo = ?`, [req.params.id, req.query.phoneNo], (err) => {
        res.json({ success: true });
    });
});

// SUPPLIERS
app.get('/api/suppliers', (req, res) => {
    const phoneNo = req.query.phoneNo;
    db.all(`SELECT * FROM suppliers WHERE phoneNo = ? AND isDeleted = 0`, [phoneNo], (err, rows) => {
        res.json(rows || []);
    });
});

app.post('/api/suppliers', (req, res) => {
    const item = req.body;
    const phoneNo = item.phoneNo || req.query.phoneNo;
    db.run(
        `INSERT OR REPLACE INTO suppliers (id, syncId, phoneNo, name, supplierPhone, company, payable, isDeleted, updatedAt)
         VALUES (?, ?, ?, ?, ?, ?, ?, 0, CURRENT_TIMESTAMP)`,
        [item.id, item.syncId || item.id, phoneNo, item.name, item.supplierPhone || '', item.company || '', item.payable || 0],
        (err) => { res.json({ success: true }); }
    );
});

app.delete('/api/suppliers/:id', (req, res) => {
    db.run(`UPDATE suppliers SET isDeleted = 1, updatedAt = CURRENT_TIMESTAMP WHERE id = ? AND phoneNo = ?`, [req.params.id, req.query.phoneNo], (err) => {
        res.json({ success: true });
    });
});

// EXPENSES
app.get('/api/expenses', (req, res) => {
    const phoneNo = req.query.phoneNo;
    db.all(`SELECT * FROM expenses WHERE phoneNo = ? AND isDeleted = 0`, [phoneNo], (err, rows) => {
        res.json(rows || []);
    });
});

app.post('/api/expenses', (req, res) => {
    const item = req.body;
    const phoneNo = item.phoneNo || req.query.phoneNo;
    db.run(
        `INSERT OR REPLACE INTO expenses (id, syncId, phoneNo, title, amount, category, date, note, isDeleted, updatedAt)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, CURRENT_TIMESTAMP)`,
        [item.id, item.syncId || item.id, phoneNo, item.title, item.amount || 0, item.category || '', item.date || '', item.note || ''],
        (err) => { res.json({ success: true }); }
    );
});

app.delete('/api/expenses/:id', (req, res) => {
    db.run(`UPDATE expenses SET isDeleted = 1, updatedAt = CURRENT_TIMESTAMP WHERE id = ? AND phoneNo = ?`, [req.params.id, req.query.phoneNo], (err) => {
        res.json({ success: true });
    });
});

// ==========================================
// 5. BULK OFFLINE SYNC APIS (UPLOAD & DOWNLOAD)
// ==========================================

app.post('/api/sync/upload', (req, res) => {
    const { phoneNo, deviceId, products, vouchers, customers, suppliers, expenses } = req.body;

    if (!phoneNo) return res.status(400).json({ success: false, message: 'phoneNo is required for sync upload' });

    db.serialize(() => {
        db.run('BEGIN TRANSACTION');

        // 1. Products Sync
        if (Array.isArray(products)) {
            const stmt = db.prepare(`
                INSERT INTO products (id, syncId, phoneNo, name, price, originalPrice, stock, category, barcode, imageUrl, isDeleted, updatedAt)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(id, phoneNo) DO UPDATE SET
                    syncId = excluded.syncId,
                    name = excluded.name,
                    price = excluded.price,
                    originalPrice = excluded.originalPrice,
                    stock = excluded.stock,
                    category = excluded.category,
                    barcode = excluded.barcode,
                    imageUrl = excluded.imageUrl,
                    isDeleted = excluded.isDeleted,
                    updatedAt = CURRENT_TIMESTAMP
            `);
            products.forEach(p => {
                stmt.run(p.id, p.syncId || p.id, phoneNo, p.name, p.price || 0, p.originalPrice || 0, p.stock || 0, p.category || '', p.barcode || '', p.imageUrl || '', p.isDeleted || 0);
            });
            stmt.finalize();
        }

        // 2. Vouchers Sync
        if (Array.isArray(vouchers)) {
            const stmt = db.prepare(`
                INSERT INTO vouchers (receiptNo, syncId, phoneNo, customerName, itemsJson, subtotal, tax, discount, total, paid, changeAmount, paymentType, dateTime, isDeleted, updatedAt)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(receiptNo, phoneNo) DO UPDATE SET
                    syncId = excluded.syncId,
                    customerName = excluded.customerName,
                    itemsJson = excluded.itemsJson,
                    subtotal = excluded.subtotal,
                    tax = excluded.tax,
                    discount = excluded.discount,
                    total = excluded.total,
                    paid = excluded.paid,
                    changeAmount = excluded.changeAmount,
                    paymentType = excluded.paymentType,
                    dateTime = excluded.dateTime,
                    isDeleted = excluded.isDeleted,
                    updatedAt = CURRENT_TIMESTAMP
            `);
            vouchers.forEach(v => {
                stmt.run(v.receiptNo, v.syncId || v.receiptNo, phoneNo, v.customerName || '', v.itemsJson || '[]', v.subtotal || 0, v.tax || 0, v.discount || 0, v.total || 0, v.paid || 0, v.changeAmount || 0, v.paymentType || 'Cash', v.dateTime || new Date().toISOString(), v.isDeleted || 0);
            });
            stmt.finalize();
        }

        // 3. Customers Sync
        if (Array.isArray(customers)) {
            const stmt = db.prepare(`
                INSERT INTO customers (id, syncId, phoneNo, name, customerPhone, address, debt, isDeleted, updatedAt)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(id, phoneNo) DO UPDATE SET
                    syncId = excluded.syncId,
                    name = excluded.name,
                    customerPhone = excluded.customerPhone,
                    address = excluded.address,
                    debt = excluded.debt,
                    isDeleted = excluded.isDeleted,
                    updatedAt = CURRENT_TIMESTAMP
            `);
            customers.forEach(c => {
                stmt.run(c.id, c.syncId || c.id, phoneNo, c.name, c.customerPhone || '', c.address || '', c.debt || 0, c.isDeleted || 0);
            });
            stmt.finalize();
        }

        // 4. Suppliers Sync
        if (Array.isArray(suppliers)) {
            const stmt = db.prepare(`
                INSERT INTO suppliers (id, syncId, phoneNo, name, supplierPhone, company, payable, isDeleted, updatedAt)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(id, phoneNo) DO UPDATE SET
                    syncId = excluded.syncId,
                    name = excluded.name,
                    supplierPhone = excluded.supplierPhone,
                    company = excluded.company,
                    payable = excluded.payable,
                    isDeleted = excluded.isDeleted,
                    updatedAt = CURRENT_TIMESTAMP
            `);
            suppliers.forEach(s => {
                stmt.run(s.id, s.syncId || s.id, phoneNo, s.name, s.supplierPhone || '', s.company || '', s.payable || 0, s.isDeleted || 0);
            });
            stmt.finalize();
        }

        // 5. Expenses Sync
        if (Array.isArray(expenses)) {
            const stmt = db.prepare(`
                INSERT INTO expenses (id, syncId, phoneNo, title, amount, category, date, note, isDeleted, updatedAt)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(id, phoneNo) DO UPDATE SET
                    syncId = excluded.syncId,
                    title = excluded.title,
                    amount = excluded.amount,
                    category = excluded.category,
                    date = excluded.date,
                    note = excluded.note,
                    isDeleted = excluded.isDeleted,
                    updatedAt = CURRENT_TIMESTAMP
            `);
            expenses.forEach(e => {
                stmt.run(e.id, e.syncId || e.id, phoneNo, e.title, e.amount || 0, e.category || '', e.date || '', e.note || '', e.isDeleted || 0);
            });
            stmt.finalize();
        }

        db.run('COMMIT', (err) => {
            if (err) return res.status(500).json({ success: false, message: 'Sync upload failed: ' + err.message });
            logSystemAction(phoneNo, deviceId, 'SYNC_UPLOAD', 'Data successfully uploaded and merged');
            res.json({ success: true, message: 'Sync upload completed', serverTime: new Date().toISOString() });
        });
    });
});

app.post('/api/sync/download', (req, res) => {
    const { phoneNo, lastSyncTime } = req.body;
    if (!phoneNo) return res.status(400).json({ success: false, message: 'phoneNo is required for sync download' });

    const timeFilter = lastSyncTime ? lastSyncTime : '1970-01-01T00:00:00.000Z';

    db.all(`SELECT * FROM products WHERE phoneNo = ? AND updatedAt > ?`, [phoneNo, timeFilter], (err, products) => {
        db.all(`SELECT * FROM vouchers WHERE phoneNo = ? AND updatedAt > ?`, [phoneNo, timeFilter], (err, vouchers) => {
            db.all(`SELECT * FROM customers WHERE phoneNo = ? AND updatedAt > ?`, [phoneNo, timeFilter], (err, customers) => {
                db.all(`SELECT * FROM suppliers WHERE phoneNo = ? AND updatedAt > ?`, [phoneNo, timeFilter], (err, suppliers) => {
                    db.all(`SELECT * FROM expenses WHERE phoneNo = ? AND updatedAt > ?`, [phoneNo, timeFilter], (err, expenses) => {
                        res.json({
                            success: true,
                            serverTime: new Date().toISOString(),
                            products: products || [],
                            vouchers: vouchers || [],
                            customers: customers || [],
                            suppliers: suppliers || [],
                            expenses: expenses || []
                        });
                    });
                });
            });
        });
    });
});

// ==========================================
// 6. APK VERSION CONTROL API
// ==========================================

app.get('/api/app/version', (req, res) => {
    db.get(`SELECT * FROM app_versions ORDER BY id DESC LIMIT 1`, [], (err, row) => {
        if (row) {
            res.json({
                success: true,
                versionName: row.versionName,
                versionCode: row.versionCode,
                downloadUrl: row.downloadUrl,
                forceUpdate: row.forceUpdate === 1,
                releaseNotes: row.releaseNotes
            });
        } else {
            res.json({
                success: true,
                versionName: '1.0.0',
                versionCode: 1,
                downloadUrl: 'http://74.81.63.87:8082/app-release.apk',
                forceUpdate: false,
                releaseNotes: 'Initial release'
            });
        }
    });
});

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ status: 'OK', serverPort: PORT, timestamp: new Date().toISOString() });
});

// Start Server
app.listen(PORT, '0.0.0.0', () => {
    console.log(`===================================================`);
    console.log(`ðŸš€ Offline POS SaaS Express Server running on Port ${PORT}`);
    console.log(`URL: http://74.81.63.87:${PORT}/api`);
    console.log(`===================================================`);
});

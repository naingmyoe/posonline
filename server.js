const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 8082;

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));

// Database File Path (JSON File Database)
const DB_FILE = path.join(__dirname, 'pos_cloud_db.json');

// Initialize local DB structure if not existing
function loadDB() {
    if (!fs.existsSync(DB_FILE)) {
        const initialData = {
            users: [],
            cloudSyncData: {} // shopBranchCode_phoneNo -> data
        };
        fs.writeFileSync(DB_FILE, JSON.stringify(initialData, null, 2));
        return initialData;
    }
    try {
        const data = fs.readFileSync(DB_FILE, 'utf8');
        return JSON.parse(data);
    } catch (e) {
        return { users: [], cloudSyncData: {} };
    }
}

function saveDB(dbData) {
    fs.writeFileSync(DB_FILE, JSON.stringify(dbData, null, 2));
}

// -------------------------------------------------------------
// 1. Health Check Endpoint (Public Status Page)
// -------------------------------------------------------------
app.get('/', (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>POS Online Cloud API Server</title>
            <style>
                body { font-family: sans-serif; background: #f4f6f9; padding: 40px; text-align: center; }
                .card { background: white; padding: 30px; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); max-width: 500px; margin: auto; }
                h2 { color: #4D5EED; }
                .status { background: #e8f5e9; color: #2e7d32; padding: 8px 16px; border-radius: 20px; font-weight: bold; display: inline-block; }
                .btn-admin { display: inline-block; margin-top: 15px; padding: 10px 20px; background: #2c3e50; color: white; text-decoration: none; border-radius: 6px; font-weight: bold; }
                .btn-admin:hover { background: #34495e; }
            </style>
        </head>
        <body>
            <div class="card">
                <h2>POS Online Cloud Backend API</h2>
                <p class="status">🟢 Server is Running (Port ${PORT})</p>
                <p>Cloud Synchronization & Authentication Ready!</p>
                <a href="/admin" class="btn-admin">Go to Admin Panel</a>
            </div>
        </body>
        </html>
    `);
});

// -------------------------------------------------------------
// 2. Check Status Endpoint
// -------------------------------------------------------------
app.post('/api/check-status', (req, res) => {
    res.json({
        status: 'online',
        message: 'POS Online Cloud Server Online',
        timestamp: Date.now()
    });
});

// -------------------------------------------------------------
// 3. Login Endpoint
// -------------------------------------------------------------
app.post('/api/login', (req, res) => {
    const { phoneNo, password } = req.body;
    const db = loadDB();
    const user = db.users.find(u => u.phoneNo === phoneNo && u.password === password);

    if (user) {
        res.json({
            status: 'success',
            message: 'Login successful',
            user: {
                phoneNo: user.phoneNo,
                businessName: user.businessName,
                shopBranchCode: user.shopBranchCode || 'MAIN-01',
                role: user.role || 'Admin'
            }
        });
    } else {
        res.status(401).json({
            status: 'error',
            message: 'ဖုန်းနံပါတ် သို့မဟုတ် စကားဝှက် မှားယွင်းနေပါသည်။'
        });
    }
});

// -------------------------------------------------------------
// 4. Register Endpoint
// -------------------------------------------------------------
app.post('/api/register', (req, res) => {
    const { phoneNo, password, businessName, shopBranchCode } = req.body;
    const db = loadDB();

    const existingUser = db.users.find(u => u.phoneNo === phoneNo);
    if (existingUser) {
        return res.status(400).json({
            status: 'error',
            message: 'ဤဖုန်းနံပါတ်ဖြင့် အကောင့်ဖွင့်ပြီးသားဖြစ်ပါသည်။'
        });
    }

    const newUser = {
        phoneNo,
        password,
        businessName: businessName || 'UN POS Shop',
        shopBranchCode: shopBranchCode || 'MAIN-01',
        createdAt: new Date().toISOString()
    };

    db.users.push(newUser);
    saveDB(db);

    res.json({
        status: 'success',
        message: 'အကောင့်သစ် အောင်မြင်စွာ ဖန်တီးပြီးပါပြီ။',
        user: newUser
    });
});

// -------------------------------------------------------------
// 5. Cloud Sync Upload Endpoint
// -------------------------------------------------------------
app.post('/api/sync-upload', (req, res) => {
    const { shopBranchCode, phoneNo, products, vouchers, customers, suppliers, expenses } = req.body;
    const db = loadDB();

    const key = `${shopBranchCode || 'MAIN-01'}_${phoneNo || 'default'}`;
    
    db.cloudSyncData[key] = {
        shopBranchCode: shopBranchCode || 'MAIN-01',
        phoneNo: phoneNo || '',
        updatedAt: new Date().toISOString(),
        products: products || [],
        vouchers: vouchers || [],
        customers: customers || [],
        suppliers: suppliers || [],
        expenses: expenses || []
    };

    saveDB(db);

    console.log(`[Cloud Sync] Uploaded data for ${key}: ${products?.length || 0} products, ${vouchers?.length || 0} vouchers`);

    res.json({
        status: 'success',
        message: 'Cloud Server သို့ ဒေတာများ အောင်မြင်စွာ Upload သိမ်းဆည်းပြီးပါပြီ!',
        timestamp: new Date().toISOString()
    });
});

// -------------------------------------------------------------
// 6. Cloud Sync Download Endpoint
// -------------------------------------------------------------
app.get('/api/sync-download', (req, res) => {
    const shopBranchCode = req.query.shopBranchCode || 'MAIN-01';
    const phoneNo = req.query.phoneNo || '';
    const key = `${shopBranchCode}_${phoneNo}`;

    const db = loadDB();
    const data = db.cloudSyncData[key];

    if (data) {
        res.json({
            status: 'success',
            shopBranchCode: data.shopBranchCode,
            updatedAt: data.updatedAt,
            products: data.products || [],
            vouchers: data.vouchers || [],
            customers: data.customers || [],
            suppliers: data.suppliers || [],
            expenses: data.expenses || []
        });
    } else {
        res.json({
            status: 'success',
            message: 'No synced data found on Cloud yet',
            products: [],
            vouchers: [],
            customers: [],
            suppliers: [],
            expenses: []
        });
    }
});

// -------------------------------------------------------------
// 7. Change Password Endpoint
// -------------------------------------------------------------
app.post('/api/change-password', (req, res) => {
    const { phoneNo, oldPassword, newPassword } = req.body;
    const db = loadDB();
    const idx = db.users.findIndex(u => u.phoneNo === phoneNo && u.password === oldPassword);

    if (idx !== -1) {
        db.users[idx].password = newPassword;
        saveDB(db);
        res.json({ status: 'success', message: 'စကားဝှက် အောင်မြင်စွာ ပြောင်းလဲပြီးပါပြီ။' });
    } else {
        res.status(400).json({ status: 'error', message: 'စကားဝှက်အဟောင်း မမှန်ကန်ပါ။' });
    }
});

// -------------------------------------------------------------
// 8. Serve Admin HTML File Route
// -------------------------------------------------------------
app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin.html'));
});

// -------------------------------------------------------------
// 9. Admin Overview Data API Endpoint
// -------------------------------------------------------------
app.get('/api/admin/overview', (req, res) => {
    const db = loadDB();
    
    // User ၏ Password များကို ဖျောက်ထားပေးခြင်း
    const safeUsers = db.users.map(u => ({
        phoneNo: u.phoneNo,
        businessName: u.businessName,
        shopBranchCode: u.shopBranchCode,
        createdAt: u.createdAt
    }));

    // Cloud Sync Data များမှ စာရင်းအကျဉ်း ထုတ်ယူခြင်း
    const syncedStores = Object.keys(db.cloudSyncData).map(key => {
        const item = db.cloudSyncData[key];
        return {
            key: key,
            shopBranchCode: item.shopBranchCode || 'MAIN-01',
            phoneNo: item.phoneNo || '',
            productsCount: item.products ? item.products.length : 0,
            vouchersCount: item.vouchers ? item.vouchers.length : 0,
            customersCount: item.customers ? item.customers.length : 0,
            updatedAt: item.updatedAt
        };
    });

    res.json({
        status: 'success',
        totalUsers: db.users.length,
        totalSyncedStores: syncedStores.length,
        users: safeUsers,
        syncedStores: syncedStores
    });
});

// Start Server
app.listen(PORT, '0.0.0.0', () => {
    console.log(`==========================================`);
    console.log(`🚀 POS Online Cloud Backend Running on Port ${PORT}`);
    console.log(`🌐 API Landing: http://localhost:${PORT}`);
    console.log(`💻 Admin Panel: http://localhost:${PORT}/admin`);
    console.log(`==========================================`);
});

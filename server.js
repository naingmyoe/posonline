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

// 1. Health Check Endpoint
app.get('/', (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>UN POS Cloud API Server</title>
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
                <h2>UN POS Cloud Backend API</h2>
                <p class="status">🟢 Server is Running</p>
                <p>Port: ${PORT}</p>
                <p>Cloud Synchronization & Authentication Ready!</p>
                <a href="/admin" class="btn-admin">Go to Admin Panel</a>
            </div>
        </body>
        </html>
    `);
});

// 2. Check Status Endpoint
app.post('/api/check-status', (req, res) => {
    const { phoneNo, deviceId } = req.body;
    const db = loadDB();
    if (!phoneNo) {
        return res.json({ status: 'on', message: 'UN POS Cloud Server Online', timestamp: Date.now() });
    }

    const user = db.users.find(u => u.phoneNo === phoneNo);
    if (!user) {
        return res.json({ status: 'not_found', message: 'အကောင့် မတွေ့ရှိပါ' });
    }

    // Check expiration
    if (user.endDate) {
        const todayStr = new Date().toISOString().split('T')[0];
        if (todayStr > user.endDate) {
            return res.json({ status: 'expired', message: `အကောင့် သက်တမ်းကုန်ဆုံးသွားပါပြီ (${user.endDate})` });
        }
    }

    if (!user.devices) user.devices = [];
    const limit = user.deviceLimit || 5;

    if (deviceId && !user.devices.includes(deviceId)) {
        if (user.devices.length >= limit) {
            return res.json({
                status: 'device_limit_exceeded',
                message: `Device Limit (${limit} စက်) ပြည့်သွားပါပြီ`
            });
        } else {
            user.devices.push(deviceId);
            saveDB(db);
        }
    }

    res.json({
        status: user.status || 'on',
        message: 'Active',
        user: {
            phoneNo: user.phoneNo,
            username: user.username,
            deviceLimit: limit,
            devicesCount: user.devices.length,
            startDate: user.startDate,
            endDate: user.endDate
        }
    });
});

// 3. Login Endpoint
app.post('/api/login', (req, res) => {
    const { phoneNo, password, deviceId } = req.body;
    const db = loadDB();
    const user = db.users.find(u => u.phoneNo === phoneNo);

    if (!user) {
        return res.status(404).json({
            status: 'not_found',
            success: false,
            message: 'ဤဖုန်းနံပါတ်ဖြင့် အကောင့်ဖွင့်ထားခြင်း မရှိပါ (Account not registered)'
        });
    }

    if (user.password !== password) {
        return res.status(401).json({
            status: 'invalid_password',
            success: false,
            message: 'Password မှားယွင်းနေပါသည် (Incorrect password)'
        });
    }

    // Check expiration date
    if (user.endDate) {
        const todayStr = new Date().toISOString().split('T')[0];
        if (todayStr > user.endDate) {
            return res.status(403).json({
                status: 'expired',
                success: false,
                message: `အကောင့် သက်တမ်းကုန်ဆုံးသွားပါပြီ (${user.endDate} ထိသာ သုံးစွဲနိုင်ပါသည်)`
            });
        }
    }

    // Check devices array & limit (default 5)
    if (!user.devices) user.devices = [];
    const limit = user.deviceLimit || 5;

    if (deviceId && !user.devices.includes(deviceId)) {
        if (user.devices.length >= limit) {
            return res.status(403).json({
                status: 'device_limit_exceeded',
                success: false,
                message: `Device Limit (${limit} စက်) ပြည့်သွားပါပြီ။ အကောင့်အသစ်မဝင်ရောက်နိုင်ပါ`
            });
        } else {
            user.devices.push(deviceId);
            saveDB(db);
        }
    }

    res.json({
        status: 'on',
        success: true,
        message: 'Login successful',
        user: {
            phoneNo: user.phoneNo,
            username: user.username,
            businessName: user.businessName,
            businessType: user.businessType,
            address: user.address,
            role: user.role,
            shopBranchCode: user.shopBranchCode || 'MAIN-01',
            deviceLimit: limit,
            devicesCount: user.devices.length,
            startDate: user.startDate,
            endDate: user.endDate,
            status: 'on'
        }
    });
});

// 4. Register Endpoint
app.post('/api/register', (req, res) => {
    const { phoneNo, password, username, businessName, businessType, address, role, deviceId, deviceLimit, startDate, endDate, shopBranchCode } = req.body;
    const db = loadDB();

    const existingUser = db.users.find(u => u.phoneNo === phoneNo);
    if (existingUser) {
        return res.status(400).json({
            status: 'error',
            message: 'ဤဖုန်းနံပါတ်ဖြင့် အကောင့်ဖွင့်ပြီးသားဖြစ်ပါသည်။'
        });
    }

    const todayStr = new Date().toISOString().split('T')[0];
    const nextYear = new Date();
    nextYear.setFullYear(nextYear.getFullYear() + 1);
    const nextYearStr = nextYear.toISOString().split('T')[0];

    const newUser = {
        phoneNo,
        password,
        username: username || 'User',
        businessName: businessName || 'UN POS Shop',
        businessType: businessType || '',
        address: address || '',
        role: role || 'ADMIN',
        shopBranchCode: shopBranchCode || 'MAIN-01',
        devices: deviceId ? [deviceId] : [],
        deviceLimit: Number(deviceLimit) || 5,
        startDate: startDate || todayStr,
        endDate: endDate || nextYearStr,
        status: 'on', // Activated immediately upon register
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

// 5. Cloud Sync Upload Endpoint
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

// 6. Cloud Sync Download Endpoint
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

// 7. Change Password
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

// =============================================================
// ADMIN PANEL ROUTES & APIs
// =============================================================

// 8. Serve Admin HTML File Route
app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin.html'));
});

// 9. Admin Overview Data API Endpoint
app.get('/api/admin/overview', (req, res) => {
    const db = loadDB();
    
    // Safety check & data formatting for Users
    const users = db.users.map(u => ({
        phoneNo: u.phoneNo,
        username: u.username || 'User',
        businessName: u.businessName || '-',
        shopBranchCode: u.shopBranchCode || 'MAIN-01',
        deviceLimit: u.deviceLimit || 5,
        devicesCount: u.devices ? u.devices.length : 0,
        startDate: u.startDate || '-',
        endDate: u.endDate || '-',
        status: u.status || 'on',
        createdAt: u.createdAt
    }));

    // Cloud Sync Data Summary
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
        users: users,
        syncedStores: syncedStores
    });
});

// 10. Admin Update User API (Extend Validity, Update Device Limit, Change Status)
app.post('/api/admin/update-user', (req, res) => {
    const { phoneNo, deviceLimit, startDate, endDate, status, password } = req.body;
    const db = loadDB();
    const user = db.users.find(u => u.phoneNo === phoneNo);

    if (!user) {
        return res.status(404).json({ status: 'error', message: 'User မတွေ့ရှိပါ' });
    }

    if (deviceLimit !== undefined) user.deviceLimit = Number(deviceLimit);
    if (startDate) user.startDate = startDate;
    if (endDate) user.endDate = endDate;
    if (status) user.status = status;
    if (password) user.password = password;

    saveDB(db);
    res.json({ status: 'success', message: 'အကောင့် အချက်အလက်များ အောင်မြင်စွာ ပြင်ဆင်ပြီးပါပြီ' });
});

// 11. Admin Reset User Registered Devices API
app.post('/api/admin/reset-devices', (req, res) => {
    const { phoneNo } = req.body;
    const db = loadDB();
    const user = db.users.find(u => u.phoneNo === phoneNo);

    if (!user) {
        return res.status(404).json({ status: 'error', message: 'User မတွေ့ရှိပါ' });
    }

    user.devices = [];
    saveDB(db);
    res.json({ status: 'success', message: 'ချိတ်ဆက်ထားသော Device များအားလုံး အောင်မြင်စွာ Reset ပြုလုပ်ပြီးပါပြီ' });
});

// 12. Admin Delete User API
app.post('/api/admin/delete-user', (req, res) => {
    const { phoneNo } = req.body;
    const db = loadDB();
    const idx = db.users.findIndex(u => u.phoneNo === phoneNo);

    if (idx !== -1) {
        db.users.splice(idx, 1);
        saveDB(db);
        res.json({ status: 'success', message: 'အကောင့် အောင်မြင်စွာ ဖျက်ဆီးပြီးပါပြီ' });
    } else {
        res.status(404).json({ status: 'error', message: 'User မတွေ့ရှိပါ' });
    }
});

// Start Server
app.listen(PORT, '0.0.0.0', () => {
    console.log(`==========================================`);
    console.log(`🚀 UN POS Cloud Backend Running on Port ${PORT}`);
    console.log(`🌐 Local Test: http://localhost:${PORT}`);
    console.log(`💻 Admin Panel: http://localhost:${PORT}/admin`);
    console.log(`==========================================`);
});

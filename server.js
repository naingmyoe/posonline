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
// 8. Admin Panel Route (Web UI Dashboard)
// -------------------------------------------------------------
app.get('/admin', (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html lang="my">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>POS Cloud Admin Dashboard</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
            <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
            <style>
                body { background-color: #f4f6f9; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
                .sidebar { min-height: 100vh; background: #2c3e50; color: #ecf0f1; }
                .sidebar .nav-link { color: #bdc3c7; padding: 12px 20px; font-weight: 500; }
                .sidebar .nav-link:hover, .sidebar .nav-link.active { background: #34495e; color: #fff; }
                .card-stat { border-radius: 10px; border: none; transition: transform 0.2s; }
                .card-stat:hover { transform: translateY(-3px); }
                .table-container { background: #fff; border-radius: 10px; padding: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.05); }
            </style>
        </head>
        <body>

        <div class="container-fluid">
            <div class="row">
                <!-- Sidebar Navigation -->
                <div class="col-md-3 col-lg-2 sidebar p-0">
                    <div class="p-3 text-center border-bottom border-secondary">
                        <h4 class="m-0 text-primary fw-bold"><i class="fa-solid fa-store"></i> POS Cloud</h4>
                        <small class="text-muted">Admin Control Center</small>
                    </div>
                    <nav class="nav flex-column mt-3">
                        <a class="nav-link active" href="#" id="link-users" onclick="switchTab('users-tab', 'link-users')"><i class="fa-solid fa-users me-2"></i> Users Management</a>
                        <a class="nav-link" href="#" id="link-sync" onclick="switchTab('sync-tab', 'link-sync')"><i class="fa-solid fa-cloud-arrow-down me-2"></i> Synced Stores Data</a>
                    </nav>
                </div>

                <!-- Main Content Area -->
                <div class="col-md-9 col-lg-10 p-4">
                    <div class="d-flex justify-content-between align-items-center mb-4">
                        <h2>Admin Dashboard</h2>
                        <button class="btn btn-outline-primary btn-sm" onclick="loadAdminData()"><i class="fa-solid fa-rotate"></i> Refresh Data</button>
                    </div>

                    <!-- Stats Overview -->
                    <div class="row mb-4">
                        <div class="col-md-4">
                            <div class="card card-stat bg-primary text-white p-3">
                                <div class="d-flex justify-content-between align-items-center">
                                    <div>
                                        <h6 class="text-uppercase mb-1">Total Users</h6>
                                        <h3 class="m-0" id="stat-total-users">0</h3>
                                    </div>
                                    <i class="fa-solid fa-user-gear fa-2x opacity-50"></i>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="card card-stat bg-success text-white p-3">
                                <div class="d-flex justify-content-between align-items-center">
                                    <div>
                                        <h6 class="text-uppercase mb-1">Active Cloud Stores</h6>
                                        <h3 class="m-0" id="stat-total-stores">0</h3>
                                    </div>
                                    <i class="fa-solid fa-shop fa-2x opacity-50"></i>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="card card-stat bg-info text-white p-3">
                                <div class="d-flex justify-content-between align-items-center">
                                    <div>
                                        <h6 class="text-uppercase mb-1">System Status</h6>
                                        <h3 class="m-0">ONLINE</h3>
                                    </div>
                                    <i class="fa-solid fa-server fa-2x opacity-50"></i>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Section 1: Registered Users -->
                    <div id="users-tab" class="tab-content">
                        <div class="table-container mb-4">
                            <h5 class="mb-3 text-secondary"><i class="fa-solid fa-address-book me-2"></i> Registered Account List</h5>
                            <div class="table-responsive">
                                <table class="table table-hover align-middle">
                                    <thead class="table-light">
                                        <tr>
                                            <th>#</th>
                                            <th>Business Name</th>
                                            <th>Phone Number</th>
                                            <th>Branch Code</th>
                                            <th>Created Date</th>
                                        </tr>
                                    </thead>
                                    <tbody id="users-table-body">
                                        <tr><td colspan="5" class="text-center">Loading users data...</td></tr>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>

                    <!-- Section 2: Synced Cloud Data Viewer -->
                    <div id="sync-tab" class="tab-content d-none">
                        <div class="table-container">
                            <h5 class="mb-3 text-secondary"><i class="fa-solid fa-database me-2"></i> Cloud Sync Stores Summary</h5>
                            <div class="table-responsive">
                                <table class="table table-striped align-middle">
                                    <thead class="table-dark">
                                        <tr>
                                            <th>Store Key</th>
                                            <th>Branch Code</th>
                                            <th>Phone No</th>
                                            <th>Products</th>
                                            <th>Vouchers</th>
                                            <th>Customers</th>
                                            <th>Last Updated</th>
                                        </tr>
                                    </thead>
                                    <tbody id="sync-table-body">
                                        <tr><td colspan="7" class="text-center">Loading store sync data...</td></tr>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>

                </div>
            </div>
        </div>

        <script>
            const API_BASE_URL = window.location.origin;

            document.addEventListener("DOMContentLoaded", () => {
                loadAdminData();
            });

            function switchTab(tabId, linkId) {
                document.querySelectorAll('.tab-content').forEach(el => el.classList.add('d-none'));
                document.getElementById(tabId).classList.remove('d-none');
                
                document.querySelectorAll('.sidebar .nav-link').forEach(el => el.classList.remove('active'));
                document.getElementById(linkId).classList.add('active');
            }

            async function loadAdminData() {
                try {
                    const response = await fetch(\`\${API_BASE_URL}/api/admin/overview\`);
                    const result = await response.json();

                    if (result.status === 'success') {
                        document.getElementById('stat-total-users').innerText = result.totalUsers;
                        document.getElementById('stat-total-stores').innerText = result.totalSyncedStores;

                        const usersBody = document.getElementById('users-table-body');
                        usersBody.innerHTML = '';
                        if(result.users.length === 0) {
                            usersBody.innerHTML = '<tr><td colspan="5" class="text-center text-muted">No registered users found.</td></tr>';
                        } else {
                            result.users.forEach((user, index) => {
                                usersBody.innerHTML += \`
                                    <tr>
                                        <td>\${index + 1}</td>
                                        <td><strong>\${user.businessName || '-'}</strong></td>
                                        <td>\${user.phoneNo}</td>
                                        <td><span class="badge bg-secondary">\${user.shopBranchCode || 'MAIN-01'}</span></td>
                                        <td>\${user.createdAt ? new Date(user.createdAt).toLocaleString() : '-'}</td>
                                    </tr>
                                \`;
                            });
                        }

                        const syncBody = document.getElementById('sync-table-body');
                        syncBody.innerHTML = '';
                        if(result.syncedStores.length === 0) {
                            syncBody.innerHTML = '<tr><td colspan="7" class="text-center text-muted">No cloud sync data available yet.</td></tr>';
                        } else {
                            result.syncedStores.forEach(store => {
                                syncBody.innerHTML += \`
                                    <tr>
                                        <td><code>\${store.key}</code></td>
                                        <td><span class="badge bg-info text-dark">\${store.shopBranchCode}</span></td>
                                        <td>\${store.phoneNo}</td>
                                        <td><span class="badge bg-primary">\${store.productsCount}</span></td>
                                        <td><span class="badge bg-success">\${store.vouchersCount}</span></td>
                                        <td><span class="badge bg-warning text-dark">\${store.customersCount}</span></td>
                                        <td><small>\${store.updatedAt ? new Date(store.updatedAt).toLocaleString() : '-'}</small></td>
                                    </tr>
                                \`;
                            });
                        }
                    }
                } catch (err) {
                    console.error('Error fetching admin data:', err);
                    alert('Admin Data ရယူရာတွင် အမှားအယွင်းရှိနေပါသည်။ Server ဖွင့်ထားခြင်း ရှိမရှိ စစ်ဆေးပါ။');
                }
            }
        </script>

        </body>
        </html>
    `);
});

// -------------------------------------------------------------
// 9. Admin Overview Data API Endpoint
// -------------------------------------------------------------
app.get('/api/admin/overview', (req, res) => {
    const db = loadDB();
    
    // User ၏ Password များကို Admin API တွင် ဖျောက်ထားပေးခြင်း
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

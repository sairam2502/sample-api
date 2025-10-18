require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

const PORT = process.env.PORT || 3000;
const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET;
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET;

// Demo clients
const clients = [
  { clientId: 'abc123', clientSecret: 'secret123' },
  { clientId: 'testClient', clientSecret: 'pass456' }
];

// Temporary refresh token store
let refreshTokens = [];

// --- 1️⃣ Get tokens ---
app.post('/auth/token', (req, res) => {
  const { clientId, clientSecret } = req.body;
  const client = clients.find(c => c.clientId === clientId && c.clientSecret === clientSecret);
  if (!client) return res.status(401).json({ error: 'Invalid credentials' });

  const accessToken = jwt.sign({ clientId }, ACCESS_TOKEN_SECRET, { expiresIn: '5m' });
  const refreshToken = jwt.sign({ clientId }, REFRESH_TOKEN_SECRET, { expiresIn: '1h' });
  refreshTokens.push(refreshToken);

  res.json({ access_token: accessToken, refresh_token: refreshToken, token_type: 'Bearer', expires_in: 300 });
});

// --- 2️⃣ Refresh token ---
app.post('/auth/refresh', (req, res) => {
  const { refresh_token } = req.body;
  if (!refresh_token) return res.status(401).json({ error: 'Missing refresh_token' });
  if (!refreshTokens.includes(refresh_token)) return res.status(403).json({ error: 'Invalid refresh_token' });

  jwt.verify(refresh_token, REFRESH_TOKEN_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired refresh_token' });
    const newAccessToken = jwt.sign({ clientId: decoded.clientId }, ACCESS_TOKEN_SECRET, { expiresIn: '5m' });
    res.json({ access_token: newAccessToken, token_type: 'Bearer', expires_in: 300 });
  });
});

// --- 3️⃣ Protected route ---
app.get('/api/data', verifyAccessToken, (req, res) => {
  res.json({
    message: '✅ Protected resource access granted',
    client: req.clientId,
    timestamp: new Date().toISOString()
  });
});

function verifyAccessToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(403).json({ error: 'No token provided' });

  jwt.verify(token, ACCESS_TOKEN_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ error: 'Token expired or invalid' });
    req.clientId = decoded.clientId;
    next();
  });
}
// --- New Endpoint: HQ Accounts Users ---
app.get('/hq/v1/accounts/:accountId/users', verifyAccessToken, (req, res) => {
  const { accountId } = req.params;

  // Static sample response
  const response = [
    {
      "id": "a75e8769-621e-40b6-a524-0cffdd2f784e",
      "account_id": accountId,
      "status": "active",
      "role": "account_admin",
      "company_id": "28e4e819-8ab2-432c-b3fb-3a94b53a91cd",
      "company_name": "Autodesk",
      "last_sign_in": "2016-04-05T07:27:20.858Z",
      "email": "john.smith@mail.com",
      "name": "John Smith",
      "nickname": "Johnny",
      "first_name": "John",
      "last_name": "Smith",
      "uid": "L9EBJKCGCXBB",
      "image_url": "http://static-dc.autodesk.net/etc/designs/v201412151200/autodesk/adsk-design/images/autodesk_header_logo_140x23.png",
      "address_line_1": "The Fifth Avenue",
      "address_line_2": "#301",
      "city": "New York",
      "postal_code": "10011",
      "state_or_province": "New York",
      "country": "United States",
      "phone": "(634)329-2353",
      "company": "Autodesk",
      "job_title": "Software Developer",
      "industry": "IT",
      "about_me": "Nothing here",
      "default_role": "BIM Manager",
      "default_role_id": "4e7e02ae-2994-4210-9153-84bfb9a23a63",
      "created_at": "2015-06-26T14:47:39.458Z",
      "updated_at": "2016-04-07T07:15:29.261Z"
    }
  ];

  res.json(response);
});

// --- 4️⃣ Logout ---
app.post('/auth/logout', (req, res) => {
  const { refresh_token } = req.body;
  refreshTokens = refreshTokens.filter(t => t !== refresh_token);
  res.json({ message: 'Logged out successfully' });
});

app.listen(PORT, () => console.log(`🚀 API running at http://localhost:${PORT}`));

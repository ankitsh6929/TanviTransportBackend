// server.js
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const sgMail = require('@sendgrid/mail');

const app = express();
app.use(cors());
app.use(express.json());

// ================= CONFIG =================
const JWT_SECRET = process.env.JWT_SECRET || 'dev_change_me';

// SendGrid
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

// ================= USERS (IN-MEMORY) =================
const users = new Map();

// Seed default admin
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@ttc.com';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'Admin@123';
const adminHash = bcrypt.hashSync(ADMIN_PASSWORD, 10);

users.set(ADMIN_EMAIL, {
  name: 'Administrator',
  email: ADMIN_EMAIL,
  role: 'admin',
  passwordHash: adminHash,
  createdAt: new Date().toISOString(),
});

// ================= HELPERS =================
function createToken(user) {
  return jwt.sign(
    { sub: user.email, role: user.role, name: user.name },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
}

function authRequired(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  if (!token) return res.status(401).json({ message: 'Missing token' });

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ message: 'Invalid token' });
  }
}

function adminOnly(req, res, next) {
  if (req.user?.role !== 'admin') {
    return res.status(403).json({ message: 'Admin only' });
  }
  next();
}

// ================= PUBLIC ROUTES =================
app.get('/api/company', (req, res) => {
  res.json({
    name: "Tanvi Transport Company",
    logo: "/logo.png",
    tagline: "Quality Is Our Priority",
    address: "No.47, Beltola College Road, Bongaon, Guwahati, Assam, 781028, India",
    email: "tanvitransportcompany@gmail.com",
    phone: ["6901244444", "9864535143"]
  });
});

app.get('/api/services', (req, res) => {
  res.json([
    "Complete Shifting Solution",
    "Warehouse Service",
    "Parcel Service",
    "Defence Relocation Service",
    "Packers And Movers",
    "Corporate Relocation Service",
    "Surface Cargo Services",
    "Office Shifting Service",
    "ODC Services All India",
    "Domestic Relocation Service",
    "Bike & Car Carriers Service"
  ]);
});

app.post('/api/inquiry', (req, res) => {
  res.json({ status: "success", message: "Inquiry received!" });
});

// ================= AUTH =================
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body || {};
    if (!name || !email || !password) {
      return res.status(400).json({ message: 'Missing fields' });
    }
    if (users.has(email)) {
      return res.status(409).json({ message: 'Email already registered' });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const user = { name, email, role: 'user', passwordHash };
    users.set(email, user);

    res.json({
      token: createToken(user),
      user: { name, email, role: 'user' }
    });
  } catch {
    res.status(500).json({ message: 'Registration failed' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const user = users.get(email);
    if (!user) return res.status(401).json({ message: 'Invalid credentials' });

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ message: 'Invalid credentials' });

    res.json({
      token: createToken(user),
      user: { name: user.name, email, role: user.role }
    });
  } catch {
    res.status(500).json({ message: 'Login failed' });
  }
});

app.get('/api/auth/me', authRequired, (req, res) => {
  res.json({ user: req.user });
});

app.get('/api/admin/stats', authRequired, adminOnly, (req, res) => {
  res.json({
    enquiriesToday: 12,
    activeRegions: 47,
    scheduledMoves: 19,
  });
});

// ================= SEND EMAIL (SENDGRID) =================
app.post('/api/sendMail', async (req, res) => {
  const { name, email, mobile, date, from, to, requirement } = req.body || {};

  if (!name || !email || !requirement) {
    return res.status(400).json({ success: false, message: "Missing fields" });
  }

  try {
    await sgMail.send({
      to: process.env.EMAIL_USER,
      from: process.env.EMAIL_USER,
      replyTo: email,
      subject: `TTC enquiry from ${name}`,
      text: `
Name: ${name}
Email: ${email}
Mobile: ${mobile || 'N/A'}
From: ${from || 'N/A'}
To: ${to || 'N/A'}
Date: ${date || 'N/A'}

Requirement:
${requirement}
      `,
    });

    res.json({ success: true, message: "Message sent successfully!" });
  } catch (err) {
    console.error("SendGrid error:", err);
    res.status(500).json({ success: false, message: "Email failed" });
  }
});

// ================= START SERVER =================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server started on port ${PORT}`);
});

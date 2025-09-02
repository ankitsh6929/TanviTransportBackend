// server.js
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
// at very top of server.js (after other requires)
require('dotenv').config();
const nodemailer = require('nodemailer');


const app = express();
app.use(cors());
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || 'dev_change_me';

// In-memory users store (replace with DB later)
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
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload; // {sub,email,role,name}
    next();
  } catch (e) {
    return res.status(401).json({ message: 'Invalid token' });
  }
}

function adminOnly(req, res, next) {
  if (req.user?.role !== 'admin') return res.status(403).json({ message: 'Admin only' });
  next();
}

// --- Public company info
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

// --- Quote/enquiry (demo)
app.post('/api/inquiry', (req, res) => {
  const { name, phone, email, typeOfMove, fromAddress, toAddress, date, description, instructions } = req.body;
  // Save/Email logic can go here
  res.json({ status: "success", message: "Inquiry received!" });
});

// --- Auth (kept for future, but the frontend no longer exposes login/register)
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body || {};
    if (!name || !email || !password) return res.status(400).json({ message: 'Missing fields' });
    if (users.has(email)) return res.status(409).json({ message: 'Email already registered' });
    if (password.length < 6) return res.status(400).json({ message: 'Password must be at least 6 characters' });

    const passwordHash = await bcrypt.hash(password, 10);
    const user = { name, email, role: 'user', passwordHash, createdAt: new Date().toISOString() };
    users.set(email, user);

    const token = createToken(user);
    res.json({ token, user: { name: user.name, email: user.email, role: user.role } });
  } catch (e) {
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

    const token = createToken(user);
    res.json({ token, user: { name: user.name, email: user.email, role: user.role } });
  } catch (e) {
    res.status(500).json({ message: 'Login failed' });
  }
});

app.get('/api/auth/me', authRequired, (req, res) => {
  res.json({ user: { email: req.user.sub, name: req.user.name, role: req.user.role } });
});

// Example admin-only endpoint
app.get('/api/admin/stats', authRequired, adminOnly, (req, res) => {
  res.json({
    enquiriesToday: 12,
    activeRegions: 47,
    scheduledMoves: 19,
  });
});


// POST /api/sendMail  (add this before app.listen)
app.post('/api/sendMail', async (req, res) => {
  const { name, email, mobile, date, from, to, requirement } = req.body || {};

  // basic validation
  if (!name || !email || !requirement) {
    return res.status(400).json({ success: false, message: "Missing required fields (name, email, requirement)" });
  }

  try {
    // create transporter using Gmail and App Password
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    // Compose message: send to your EMAIL_USER, set replyTo to visitor
    const mailOptions = {
      from: process.env.EMAIL_USER, // send from your own address (less likely to be blocked)
      replyTo: email,
      to: process.env.EMAIL_USER,   // you receive the email here
      subject: `TTC enquiry from ${name} ${from ? `(${from} -> ${to || 'N/A'})` : ''}`,
      text: [
        `You have a new enquiry from Tanvi Transport Company website.`,
        ``,
        `Name: ${name}`,
        `Email: ${email}`,
        `Mobile: ${mobile || 'N/A'}`,
        `From: ${from || 'N/A'}`,
        `To: ${to || 'N/A'}`,
        `Date: ${date || 'N/A'}`,
        ``,
        `Requirement:`,
        `${requirement}`,
      ].join('\n'),
    };

    await transporter.sendMail(mailOptions);
    return res.json({ success: true, message: "Message sent successfully!" });
  } catch (err) {
    console.error("Error sending email:", err);
    return res.status(500).json({ success: false, message: "Failed to send message." });
  }
});


const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server started on port ${PORT}`));

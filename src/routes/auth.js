const { Router } = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { PrismaClient, Role } = require("@prisma/client");
const nodemailer = require("nodemailer");

const prisma = new PrismaClient();
const r = Router();

// Mailer (configure via env)
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST, // e.g. smtp.gmail.com or your SMTP
  port: Number(process.env.EMAIL_PORT || 587),
  secure: false,
  auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
});

// helper
const toRoleEnum = (role) => {
  if (!role) return Role.CREATOR;
  const v = role.toString().toUpperCase();
  return v === "BRAND" ? Role.BRAND : v === "ADMIN" ? Role.ADMIN : Role.CREATOR;
};

// POST /api/auth/register
// body: { email, password, name, role: "brand" | "creator", brandName? }
r.post("/register", async (req, res, next) => {
  try {
    const { email, password, name, role, brandName } = req.body;

    if (!email || !password || !name)
      return res.status(400).json({ error: "Missing fields" });

    const existing = await prisma.user.findUnique({ where: { email } });
    if (existing)
      return res.status(409).json({ error: "Email already in use" });

    const hashed = await bcrypt.hash(password, 10);

    // Base user
    let data = { email, password: hashed, name, role: toRoleEnum(role) };

    // If registering as brand → create Brand and link
    if (data.role === Role.BRAND) {
      const brand = await prisma.brand.create({
        data: { name: brandName || name, website: null },
      });
      data.brandId = brand.id;
    }

    // If registering as creator → create Creator and link
    if (data.role === Role.CREATOR) {
      const creator = await prisma.creator.create({
        data: { displayName: name },
      });
      data.creatorId = creator.id;
    }

    const user = await prisma.user.create({ data });

    // Generate OTP (6 digits, 10 mins)
    const code = String(Math.floor(100000 + Math.random() * 900000));
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);
    await prisma.oTP.create({ data: { code, expiresAt, userId: user.id } });

    // Send OTP email
    await transporter.sendMail({
      from: process.env.EMAIL_FROM || process.env.EMAIL_USER,
      to: email,
      subject: "Your Hypenest verification code",
      text: `Your OTP is ${code}. It expires in 10 minutes.`,
      html: `<p>Your OTP is <b>${code}</b>. It expires in 10 minutes.</p>`,
    });

    res
      .status(201)
      .json({ message: "Registered. OTP sent to email.", email: user.email });
  } catch (e) {
    next(e);
  }
});

// POST /api/auth/verify-otp  { email, code }
r.post("/verify-otp", async (req, res, next) => {
  try {
    const { email, code } = req.body;
    if (!email || !code)
      return res.status(400).json({ error: "Missing fields" });

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.status(404).json({ error: "User not found" });

    const record = await prisma.oTP.findFirst({
      where: { userId: user.id, code },
      orderBy: { createdAt: "desc" },
    });
    if (!record) return res.status(400).json({ error: "Invalid code" });
    if (record.expiresAt < new Date())
      return res.status(400).json({ error: "OTP expired" });

    await prisma.user.update({
      where: { id: user.id },
      data: { isVerified: true },
    });
    res.json({ message: "Email verified" });
  } catch (e) {
    next(e);
  }
});

// POST /api/auth/login  { email, password }
r.post("/login", async (req, res, next) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ error: "Missing fields" });

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.status(400).json({ error: "Invalid credentials" });

    if (!user.isVerified)
      return res.status(403).json({ error: "Email not verified" });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(400).json({ error: "Invalid credentials" });

    const token = require("jsonwebtoken").sign(
      { sub: user.id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({ token, role: user.role, name: user.name });
  } catch (e) {
    next(e);
  }
});

module.exports = r;

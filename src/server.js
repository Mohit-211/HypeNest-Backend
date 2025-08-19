require("dotenv").config();
const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");

const allowed = ["https://new.hypenestmedia.com", "https://hypenestmedia.com"];
const app = express();
app.use(
  cors({
    origin: (origin, cb) => cb(null, !origin || allowed.includes(origin)),
    credentials: true,
  })
);
app.options("*", cors()); // handle preflight
app.use(express.json());
app.use(cookieParser());

// health
app.get("/health", (_req, res) => res.json({ ok: true }));

// auth routes
app.use("/api/auth", require("./routes/auth"));

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`API running on :${PORT}`));

require("dotenv").config();
const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const path = require("path");

const connectDB = require("./config/db");
const authRoutes = require("./routes/authRoutes");
const { homepage } = require("./controllers/authController");

const app = express();
connectDB();

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cors({ origin: "http://localhost:3000", credentials: true }));
app.use(cookieParser());

// Serve static files from the "views" folder.
app.use(express.static(path.join(__dirname, "views")));

// API routes for authentication.
app.use("/api/auth", authRoutes);

// Route for the homepage – shows authorized view if token valid, else shows unauthorized page.
app.get("/", homepage);

// Routes to render static login and register pages.
app.get("/login", (req, res) => {
  res.sendFile(path.join(__dirname, "views", "login.html"));
});
app.get("/register", (req, res) => {
  res.sendFile(path.join(__dirname, "views", "register.html"));
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
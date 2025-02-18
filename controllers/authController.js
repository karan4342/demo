const path = require("path");
const jwt = require("jsonwebtoken");
const User = require("../models/user");
const bcrypt = require("bcryptjs");

const generateToken = (user) => {
  return jwt.sign(
    { id: user._id, username: user.username },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRY }
  );
};

const generateRefreshToken = (user) => {
  return jwt.sign(
    { id: user._id },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: process.env.JWT_REFRESH_EXPIRY }
  );
};

// Renders homepage – if authorized, shows user info; otherwise shows unauthorized page.
exports.homepage = async (req, res) => {
  const token = req.cookies.token;
  if (!token) {
    return res.sendFile(path.join(__dirname, "../views/unauthorized.html"));
  }

  jwt.verify(token, process.env.JWT_SECRET, async (err, decoded) => {
    if (err) {
      return res.sendFile(path.join(__dirname, "../views/unauthorized.html"));
    }
    try {
      const user = await User.findById(decoded.id);
      if (!user) {
        return res.sendFile(path.join(__dirname, "../views/unauthorized.html"));
      }
  
      // Generate a new refresh token
      const refreshToken = generateRefreshToken(user);
      res.cookie("refreshToken", refreshToken, { httpOnly: true });

      // Note: Displaying the hashed password is only for demonstration.
      const dynamicPage = `
        <!DOCTYPE html>
        <html>
          <head>
            <meta charset="UTF-8">
            <title>Welcome</title>
          </head>
          <body>
            <h1>Welcome</h1>
            <p><strong>Username:</strong> ${user.username}</p>
            <p><strong>Password:</strong> ${user.password}</p>
            <p><strong>Access Token:</strong> ${token}</p>
            <p><strong>Refresh Token:</strong> ${refreshToken}</p>
          </body>
        </html>
      `;
      res.send(dynamicPage);
    } catch (error) {
      res.status(500).json({ message: "Server error" });
    }
  });
};

// REGISTER
exports.register = async (req, res) => {
  try {
    const { username, email, password } = req.body;
    let user = await User.findOne({ email });
    if (user) return res.status(400).json({ message: "User already exists" });

    user = new User({ username, email, password });
    await user.save();

    res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
};

// LOGIN
exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const token = generateToken(user);
    const refreshToken = generateRefreshToken(user);

    res.cookie("token", token, { httpOnly: true });
    res.cookie("refreshToken", refreshToken, { httpOnly: true });

    res.json({ message: "Login successful", token, refreshToken });
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
};

// REFRESH TOKEN
exports.refreshToken = (req, res) => {
  const refreshToken = req.cookies.refreshToken;
  if (!refreshToken) return res.status(401).json({ message: "Unauthorized" });

  jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ message: "Forbidden" });
    const newToken = generateToken({ _id: decoded.id });
    res.cookie("token", newToken, { httpOnly: true });
    res.json({ token: newToken });
  });
};

// LOGOUT
exports.logout = (req, res) => {
  res.clearCookie("token");
  res.clearCookie("refreshToken");
  res.json({ message: "Logged out successfully" });
};
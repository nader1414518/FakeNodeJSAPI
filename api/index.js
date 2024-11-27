const express = require("express");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

const app = express();
app.use(bodyParser.json());

// Secret key for JWT
const SECRET_KEY = "your_secret_key";

// Mock database
const users = [
  {
    id: 1,
    username: "test@gmail.com",
    password: "$2a$10$boUcTuB37d0VZTO4QhikKeH7h0Pe3NE.3Uvwi8YqTmndFJAk1TbPq",
  },
];

// Helper: Generate JWT
const generateToken = (user) => {
  return jwt.sign({ id: user.id, username: user.username }, SECRET_KEY, {
    expiresIn: "1h",
  });
};

// Routes

// Register
app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  // Check if username is already taken
  if (users.find((user) => user.username === username)) {
    return res.status(400).json({ message: "Username already exists" });
  }

  // Hash the password
  const hashedPassword = await bcrypt.hash(password, 10);

  // Add user to mock database
  const user = { id: users.length + 1, username, password: hashedPassword };
  //   console.log(user);
  users.push(user);

  res
    .status(201)
    .json({ result: true, message: "User registered successfully" });
});

// Login
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  // Find user
  const user = users.find((user) => user.username === username);
  if (!user) {
    return res.status(404).json({ result: false, message: "User not found" });
  }

  // Validate password
  const isValidPassword = await bcrypt.compare(password, user.password);
  if (!isValidPassword) {
    return res.status(401).json({ result: false, message: "Invalid password" });
  }

  // Generate token
  const token = generateToken(user);
  res.json({ result: true, message: "Login successful", token });
});

// Get user data
app.get("/user", (req, res) => {
  const token = req.headers["authorization"];

  if (!token) {
    return res.status(401).json({ result: false, message: "Token is missing" });
  }

  try {
    const decoded = jwt.verify(token.replaceAll("Bearer ", ""), SECRET_KEY);
    const user = users.find((u) => u.id === decoded.id);
    if (!user) {
      return res.status(404).json({ result: false, message: "User not found" });
    }
    res.json({ result: true, id: user.id, username: user.username });
  } catch (error) {
    res.status(401).json({ result: false, message: "Invalid token" });
  }
});

// Start the server
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});

module.exports = app;

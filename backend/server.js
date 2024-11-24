const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");

// Load environment variables from .env file
dotenv.config();

const app = express();

// Middleware for CORS and JSON parsing
app.use(cors());
app.use(express.json());

// Use the auth router
app.use("/auth", require("./routers/auth/login.js"));

// Define a simple route
app.all("/", async (req, res) => {
    return res.send(`The server is online on port ${process.env.PORT}`);
});

// Use the PORT from .env or default to 3000
const port = process.env.PORT || 3000;

// Start the server
app.listen(port, () => {
    console.log(`Server Online on port: ${port}`);
});

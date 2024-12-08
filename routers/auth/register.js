const express = require("express");
const router = express.Router();
const bcrypt = require('bcrypt');
const { SQL } = require("../../fonctions/fonctions");

router.post("/register", async (req, res) => {
    try {
        const { email, pass, fullName } = req.body;
        if (!email || !pass || !fullName)
            return res.status(400).json({ message: "Missing required fields" });
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email))
            return res.status(400).json({ message: "Invalid email format" });
        const [existingUser] = await SQL("SELECT * FROM users WHERE email = ?", [email]);
        if (existingUser)
            return res.status(400).json({ message: "Email already exists" });
        const hash = await bcrypt.hash(pass, 8);
        const result = await SQL("INSERT INTO users (FullName, Email, pass) VALUES (?, ?, ?)", [fullName, email, hash]);
        if (result.affectedRows === 0) {
            return res.status(500).json({ message: "Failed to create user" });
        }
        return res.status(201).end();
    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: "Internal server error" });
    }
});

module.exports = router;

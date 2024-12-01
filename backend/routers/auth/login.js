const express = require("express");
const router = express.Router();
const { NewToken, SQL } = require("../../fonctions/fonctions");
const bcrypt = require('bcrypt');

router.post("/login", async (req, res) => {
    try {
        const { email, pass } = req.body;
        if (!email || !pass) {
            return res.status(400).json({ message: "Email and password are required" });
        }
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ message: "Invalid email format" });
        }
        const [userinfo] = await SQL("SELECT * FROM users WHERE email = ?", [email]);
        if (!userinfo) {
            return res.status(404).json({ message: "User not found" });
        }
        const passwordMatch = await bcrypt.compare(pass, userinfo.pass);
        if (!passwordMatch) {
            return res.status(401).json({ message: "Incorrect password" });
        }
        const token = NewToken({ id: userinfo.id, email, role: userinfo.role });
        return res.status(200).json({
            token: token,
            role: userinfo.role
        });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: "Internal server error" });
    }
});

module.exports = router;

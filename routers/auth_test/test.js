const express = require("express");
const router = express.Router();
const { VerifyUser } = require("../../fonctions/fonctions");

router.get("/protected", async (req, res) => {
    let token = req.body;

    try {
        const userinfo = await VerifyUser(token).catch((error) => {
            return res.status(401).end();
        });
        if (userinfo) {
            return res.status(300).send("TEST"); // Return after sending response
        } else {
            return res.send("3yane"); // Return after sending response
        }
    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: "Internal server error" }); // Ensure execution stops here
    }
});

module.exports = router;

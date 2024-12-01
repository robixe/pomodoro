const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const db = require("./utils/db"); // Import your db.js

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

// Auth
app.use("/", require("./routers/auth/login.js"));
app.use("/", require("./routers/auth/register.js"));

app.all("/", async (req, res) => {
    res.send(`The server is online on port ${process.env.PORT}`);
});
const port = process.env.PORT || 3000;
app.listen(port, () => {
    console.log(`Server is online on port: ${port}`);
});

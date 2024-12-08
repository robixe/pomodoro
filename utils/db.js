const { createPool } = require("mysql");
const dotenv = require("dotenv");

// Load environment variables
dotenv.config();

const pool = createPool({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
});

module.exports = pool;
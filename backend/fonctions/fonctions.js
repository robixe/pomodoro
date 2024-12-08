const jwt = require("jsonwebtoken");
const pool = require("../utils/db");  // connection
const crypto = require('crypto');
const fs = require('fs');
const safe = crypto.scryptSync(process.env.SAFE, 'salt', 32);

const dotenv = require("dotenv");
dotenv.config();

const jwtSecret = process.env.JWT_SECRET;

function SQL(query, params = []) {

	return new Promise((resolve, reject) => {
		pool.query(query, params, (err, results) => {
			err ? reject(err) : resolve(results);
		});
	});
}

async function logs(user,action,ip){
	await SQL(`INSERT INTO logs (user, action, ip) VALUES (?, ?, ?)`, [user, action, ip])
}

function NewToken(payload) {
    const secretKey = process.env.JWT_SECRET || 'sd161r621ffc125216521cyy1r265chv817268fusu81512097w29692wuyt17';
    if (!secretKey) {
        throw new Error('JWT secret key is missing');
    }
    return jwt.sign(payload, secretKey, { expiresIn: '1h' });
}

module.exports = { NewToken };


const encrypt = (text) => {
	const iv = crypto.randomBytes(16);
	const cipher = crypto.createCipheriv('aes-256-cbc', safe, iv);
	let encrypted = cipher.update(text);
	encrypted = Buffer.concat([encrypted, cipher.final()]);
	return iv.toString('hex') + ':' + encrypted.toString('hex');
};

function isSecurePassword(password) {
    return (
        password.length >= 8 &&
        /[A-Z]/.test(password) &&    // Contains an uppercase letter
        /[a-z]/.test(password) &&    // Contains a lowercase letter
        /\d/.test(password) &&       // Contains a digit
        /[!@#$%^&*]/.test(password) && // Contains a special character
        !/\s/.test(password)         // No spaces
    );
}

function VerifyUser(token) {
	return new Promise((resolve, reject) => {
		jwt.verify(token, jwtSecret, async (err, decoded) => {
			if (err) {
				reject(" Invalid token ");
				return;
			}
			const { email, pass } = decoded;
			try {
				const [user_data] = await SQL("SELECT * FROM users WHERE email = ? AND pass = ?", [email, pass])
				if (user_data)
					resolve(user_data);
				else
					reject("Invalid User");
			} catch (error) {
				reject(error);
			}
		});
	});
}

async function report(status, path, description) {
	description = typeof description === 'object' ? JSON.stringify(description) : description;
	const message = encrypt(JSON.stringify({ "server": process.env.SERVER, status, path, description }));
	return await fetch(process.env.ANTER_API_URL, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			'Authorization': `Bearer ${process.env.SAFE}`
		},
		body: JSON.stringify({ safe: message })
	});
}
async function report(status, path, description) {
	description = typeof description === 'object' ? JSON.stringify(description) : description;
	const message = encrypt(JSON.stringify({ "server": process.env.SERVER, status, path, description }));
	return await fetch(process.env.ANTER_API_URL, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			'Authorization': `Bearer ${process.env.SAFE}`
		},
		body: JSON.stringify({ safe: message })
	});
}

module.exports = {
	logs,
	SQL,
	NewToken,
	VerifyUser,
    report,
	isSecurePassword
};
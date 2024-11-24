const jwt = require("jsonwebtoken");
const pool = require("./db");  // connection
let rateLimit = require("express-rate-limit");
const crypto = require('crypto');
const fs = require('fs');
const nodemailer = require('nodemailer');
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

function NewToken(pyload) {
	const token = jwt.sign(pyload, jwtSecret);
	return token
}

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

const decrypt = (text) => {
	const textParts = text.split(':');
	const iv = Buffer.from(textParts.shift(), 'hex');
	const encryptedText = Buffer.from(textParts.join(':'), 'hex');
	const decipher = crypto.createDecipheriv('aes-256-cbc', safe, iv);
	let decrypted = decipher.update(encryptedText);
	decrypted = Buffer.concat([decrypted, decipher.final()]);
	return decrypted.toString();
};

async function report(status, path, description) {
	description = typeof description === 'object' ? JSON.stringify(description) : description;
	const message = encrypt(JSON.stringify({ "server": process.env.SERVER, status, path, description }));
	return await fetch(process.env.ANTER_API_URL, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			'Authorization': `Bearer ${process.env.SAFE}`
		},
		body: JSON.stringify({ safe: message })  // Change this line
	});
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

async function SpeedLimit() {
	return limiter = rateLimit({
		windowMs: 1 * 60 * 1000, // 1 minute
		max: 100,
		message: "",
		keyGenerator: (req, res) => {
			return req.headers['x-forwarded-for'] || req.connection.remoteAddress;
		}
	});
}

function EmailEncrypt(email) {
	const hashedKey = crypto.createHash('sha256').update(process.env.KEY).digest('base64').substr(0, 32);
	const iv = crypto.randomBytes(16);
	const cipher = crypto.createCipheriv('aes-256-cbc', hashedKey, iv);
	let encrypted = cipher.update(email, 'utf8', 'hex');
	encrypted += cipher.final('hex');
	return `${iv.toString('hex')}:${encrypted}`;
}

function EmailDecrypt(encryptedData) {
	const parts = encryptedData.split(':');
	const iv = Buffer.from(parts.shift(), 'hex');
	const encryptedText = Buffer.from(parts.join(':'), 'hex');
	const hashedKey = crypto.createHash('sha256').update(process.env.KEY).digest('base64').substr(0, 32);
	const decipher = crypto.createDecipheriv('aes-256-cbc', hashedKey, iv);
	let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
	decrypted += decipher.final('utf8');
	return decrypted;
}

async function TempEmail(email) {
	let send = 0;

	const code = EmailEncrypt(email);
	const verificationLink = `https://infom4th-api-v2.robixe.online/auth/verification/${code}`;

	const transporter = nodemailer.createTransport({
		service: 'gmail',
		auth: {
			user: process.env.EMAIL_USER,
			pass: process.env.EMAIL_PASS
		}
	});

	try {
		// Use fs.readFileSync
		let htmlTemplate = fs.readFileSync('./email/verification.html', 'utf8');
		htmlTemplate = htmlTemplate.replace('{{verificationLink}}', verificationLink);

		const mailOptions = {
			from: `"${process.env.EMAIL_FROM}" <${process.env.EMAIL_USER}>`,
			to: email,
			subject: 'Email Verification - Please Confirm Your Email',
			html: htmlTemplate
		};

		await transporter.sendMail(mailOptions);
		send = 1;

	} catch (emailError) {
		console.error('Email error:', emailError);
		send = 0;
	}

	return send;
}

async function ResetPasswordEmail(email) {
	let send = 0;

	// Generate a unique code for the reset link
	const code = EmailEncrypt(email); 
	const resetPasswordLink = `https://infom4th-api-v2.robixe.online/reset/page/${code}`;

	const transporter = nodemailer.createTransport({
			service: 'gmail',
			auth: {
					user: process.env.EMAIL_USER,
					pass: process.env.EMAIL_PASS
			}
	});

	try {
			// Read the reset password email template
			let htmlTemplate = fs.readFileSync('./email/password.html', 'utf8');
			htmlTemplate = htmlTemplate.replace('{{resetLink}}', resetPasswordLink);

			const mailOptions = {
					from: `"${process.env.EMAIL_FROM}" <${process.env.EMAIL_USER}>`,
					to: email,
					subject: 'Password Reset Request - Secure Your Account',
					html: htmlTemplate
			};

			await transporter.sendMail(mailOptions);
			send = 1;

	} catch (emailError) {
			console.error('Email error:', emailError);
			send = 0;
	}

	return send;
}

module.exports = {
	logs,
	SQL,
	EmailEncrypt,
	EmailDecrypt,
	TempEmail,
	ResetPasswordEmail,
	report,
	NewToken,
	SpeedLimit,
	VerifyUser,
	isSecurePassword
};
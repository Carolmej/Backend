//Dependencies
import express from 'express';
import pool from '../config/DBManager.js';
import bcrypt from 'bcrypt';
import crypto from 'crypto';
import { platformAdminCheck } from '../middleware/userTypeChecks.js';
import errorHandler from '../middleware/errorHandler.js';
import adminAuth from '../middleware/adminAuth.js';
import { sendMail } from '../middleware/emailHandler.js';
const user = express.Router();
//Endpoints
//---------------------------------------------------------------------------------------------------------------------------
user.post('/register', async (req, res) => {
    const { name, email, phone, role } = req.body;
    if (name && email && phone && role <= 3 && role >= 1) {
        let conn;
        try {
            conn = await pool.connect();
            if ( role == 1 ) if ( await platformAdminCheck(conn, req) ) return res.status(403).json({ message: 'Forbidden' });
            let user_key = crypto.createHash('MD5').update(name + email + Date.now()).digest('hex');
            let password_hash = await bcrypt.hash(user_key, 12);
            await conn.query('INSERT INTO users (name, email, password_hash, phone, active, created_at, user_key, role) VALUES ($1, $2, $3, $4, $5, $6, $7, $8);', [name, email, password_hash, phone, false, new Date(), user_key, role]);
            await sendMail(
                email,
                'Welcome to PMaster',
                `<p>Your account has been created successfully.</p><p>Your temporary password is: <strong>${user_key}</strong></p><p>Please log in and change it as soon as possible.</p>`
            );
            return res.status(201).json({ message: 'User created successfully' });
        } catch (error) {
            errorHandler(error, res);
        } finally {
            if (conn) conn.release();
        }
    } else return res.status(400).json({ message: 'Incomplete data' });
});
user.post('/resetPass', adminAuth, async (req, res) => {
    const { user_id } = req.body;
    if (user_id) {
        let conn;
        try {
            conn = await pool.connect();
            let new_hash = crypto.createHash('MD5').update(user_id + Date.now()).digest('hex').slice(0, 16);
            let password_hash = await bcrypt.hash(new_hash, 12);
            await conn.query('UPDATE users SET password_hash = $1, active = false WHERE id = $2;', [password_hash, user_id]);
            let email = (await conn.query('SELECT email FROM users WHERE id = $1;', [user_id])).rows[0].email;
            await sendMail(
                email,
                'Password Reset Notification',
                `<p>Your password has been reset by an administrator.</p><p>Your new temporary password is: <strong>${new_hash}</strong></p><p>Please log in and change it as soon as possible.</p>`
            );
            return res.status(200).json({ message: 'Password reseted successfully' });
        } catch (error) {
            errorHandler(error, res);
        } finally {
            if (conn) conn.release();
        }
    } else return res.status(400).json({ message: 'Incomplete data' });
});
//---------------------------------------------------------------------------------------------------------------------------
export default user;
// Dependencies
import express from 'express';
import pool from '../config/DBManager.js';
import bcrypt from 'bcrypt';
import crypto from 'crypto';
import errorHandler from '../middleware/errorHandler.js';
import adminAuth from '../middleware/adminAuth.js';
import { sendMail } from '../middleware/emailHandler.js';
import jwt from 'jsonwebtoken';

// 2FA
import speakeasy from 'speakeasy';
import qrcode from 'qrcode';

// Auth middleware
import tokenAuth from '../middleware/tokenAuth.js';

const user = express.Router();

//PUBLIC ENDPOINTS — NO TOKEN REQUIRED

// LOGIN (MODIFICADO PARA SOPORTAR 2FA)
user.post('/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password)
        return res.status(400).json({ message: 'Incomplete data' });

    let conn;
    try {
        conn = await pool.connect();

        const result = await conn.query(`
            SELECT id, name, email, password_hash, role, active, twofa_enabled, twofa_secret
            FROM users 
            WHERE email = $1;
        `, [email]);

        if (result.rows.length === 0)
            return res.status(404).json({ message: 'User not found' });

        const userData = result.rows[0];

        const bcryptCompare = await bcrypt.compare(password, userData.password_hash);
        if (!bcryptCompare)
            return res.status(401).json({ message: 'Incorrect credentials' });

        if (!userData.active)
            return res.status(401).json({ message: 'Forbidden NO permissions' });

        // Si NO tiene 2FA → login normal
        if (!userData.twofa_enabled) {
            const token = jwt.sign(
                {
                    user_id: userData.id,
                    email: userData.email,
                    role: userData.role
                },
                process.env.JWT_SECRET,
                { expiresIn: '8h' }
            );

            return res.status(200).json({
                message: 'Login successful',
                token,
                user: {
                    id: userData.id,
                    name: userData.name,
                    email: userData.email,
                    role: userData.role
                }
            });
        }

        // TIENE 2FA → enviar token temporal de 5 minutos
        const tempToken = jwt.sign(
            {
                user_id: userData.id,
                email: userData.email,
                role: userData.role,
                is2FA: true
            },
            process.env.JWT_SECRET,
            { expiresIn: '5m' }
        );

        return res.status(200).json({
            user: {
                twofa: tempToken
            }
        });

    } catch (error) {
        errorHandler(error, res);
    } finally {
        if (conn) conn.release();
    }
});

// 2FA LOGIN FINAL — RECIBE TOTP Y EL TOKEN TEMPORAL
user.post('/2fa/login', async (req, res) => {
    const { totp, token } = req.body;

    if (!totp || !token)
        return res.status(400).json({ message: 'Incomplete data' });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        if (!decoded.is2FA)
            return res.status(403).json({ message: 'Invalid 2FA session' });

        let conn = await pool.connect();

        const result = await conn.query(`
            SELECT id, name, email, role, twofa_secret 
            FROM users 
            WHERE id = $1
        `, [decoded.user_id]);

        if (result.rows.length === 0)
            return res.status(404).json({ message: 'User not found' });

        const userData = result.rows[0];

        const isValid = speakeasy.totp.verify({
            secret: userData.twofa_secret,
            encoding: 'base32',
            token: totp,
            window: 1
        });

        if (!isValid)
            return res.status(401).json({ message: 'Invalid TOTP' });

        // Login completo → generar token normal
        const finalToken = jwt.sign(
            {
                user_id: userData.id,
                email: userData.email,
                role: userData.role
            },
            process.env.JWT_SECRET,
            { expiresIn: '8h' }
        );

        return res.status(200).json({
            message: 'Login successful',
            token: finalToken,
            user: {
                id: userData.id,
                name: userData.name,
                email: userData.email,
                role: userData.role
            }
        });

    } catch (error) {
        return errorHandler(error, res);
    }
});


// GENERAR SECRETO 2FA + QR — SE USA EL EMAIL, NO EL ID (CORREGIDO)
user.post('/2fa/generate', async (req, res) => {
    const { email } = req.body;

    if (!email)
        return res.status(400).json({ message: 'Incomplete data' });

    let conn;
    try {
        conn = await pool.connect();

        const result = await conn.query(
            'SELECT id FROM users WHERE email = $1;',
            [email]
        );

        if (result.rows.length === 0)
            return res.status(404).json({ message: 'User not found' });

        const secret = speakeasy.generateSecret({ length: 20 }).base32;

        const otpauthURL = `otpauth://totp/${encodeURIComponent(email)}?secret=${encodeURIComponent(secret)}&issuer=PMaster`;

        const qrImage = await qrcode.toDataURL(otpauthURL);

        await conn.query(`
            UPDATE users SET twofa_secret = $1 WHERE email = $2
        `, [secret, email]);

        return res.status(200).json({ secret, qrImage });

    } catch (error) {
        errorHandler(error, res);
    } finally {
        if (conn) conn.release();
    }
});

//PRIVATE ENDPOINTS — REQUIEREN TOKEN NORMAL DESPUÉS DE LOGIN

user.use(tokenAuth);

// REGISTER
user.post('/register', adminAuth, async (req, res) => {
    const { name, email, phone, role } = req.body;

    if (name && email && phone && role <= 3 && role >= 1) {
        let conn;
        try {
            conn = await pool.connect();

            let user_key = crypto.createHash('MD5').update(name + email + Date.now()).digest('hex');
            let password_hash = await bcrypt.hash(String(user_key), 12);

            await conn.query(`
                INSERT INTO users (name, email, password_hash, phone, active, created_at, user_key, role, twofa_enabled, twofa_secret)
                VALUES ($1,$2,$3,$4,$5,$6,$7,$8,false,NULL)
            `, [name, email, password_hash, phone, false, new Date(), user_key, role]);

            return res.status(201).json({ message: 'User created successfully' });

        } catch (error) {
            errorHandler(error, res);
        } finally {
            if (conn) conn.release();
        }
    } else return res.status(400).json({ message: 'Incomplete data' });
});

// RESET PASSWORD
user.post('/resetPass', adminAuth, async (req, res) => {
    const { user_id } = req.body;

    if (!user_id)
        return res.status(400).json({ message: 'Incomplete data' });

    let conn;
    try {
        conn = await pool.connect();

        let new_hash = crypto
            .createHash('MD5')
            .update(user_id + Date.now())
            .digest('hex')
            .slice(0, 16);

        let password_hash = await bcrypt.hash(String(new_hash), 12);

        await conn.query(`
            UPDATE users SET password_hash = $1, active = false WHERE id = $2;
        `, [password_hash, user_id]);

        return res.status(200).json({ message: 'Password reset successfully' });

    } catch (error) {
        errorHandler(error, res);
    } finally {
        if (conn) conn.release();
    }
});

// PROFILE GET
user.get('/profile', async (req, res) => {
    const user_id = req.tokenData.user_id;

    let conn;
    try {
        conn = await pool.connect();

        const userResult = await conn.query(`
            SELECT id, name, email, role, phone, active, twofa_enabled 
            FROM users 
            WHERE id = $1;
        `, [user_id]);

        const projectsResult = await conn.query(`
            SELECT p.id, p.name, p.status, p.end
            FROM projects p
            JOIN project_members pm ON p.id = pm.project_id
            WHERE pm.user_id = $1;
        `, [user_id]);

        return res.status(200).json({
            ...userResult.rows[0],
            projects: projectsResult.rows
        });

    } catch (error) {
        errorHandler(error, res);
    } finally {
        if (conn) conn.release();
    }
});

// PROFILE UPDATE
user.put('/profile', async (req, res) => {
    const user_id = req.tokenData.user_id;
    const { name, phone } = req.body;

    let conn;
    try {
        conn = await pool.connect();

        const result = await conn.query(`
            UPDATE users 
            SET name = $1, phone = $2, updated_at = CURRENT_TIMESTAMP
            WHERE id = $3 
            RETURNING id;
        `, [name, phone, user_id]);

        if (result.rows.length === 0)
            return res.status(404).json({ message: 'User not found or nothing updated' });

        return res.status(200).json({ message: 'User profile updated successfully' });

    } catch (error) {
        return errorHandler(error, res);
    } finally {
        if (conn) conn.release();
    }
});

export default user;

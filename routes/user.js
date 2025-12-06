//Dependencies
import express from 'express';
import pool from '../config/DBManager.js';
import bcrypt from 'bcrypt';
import crypto from 'crypto';
//import { platformAdminCheck } from '../middleware/userTypeChecks.js';
import errorHandler from '../middleware/errorHandler.js';
import adminAuth from '../middleware/adminAuth.js';
import { sendMail } from '../middleware/emailHandler.js';
const user = express.Router();
const user_details = express.Router();
//JWT -  para endpoints privados
import  jwt from 'jsonwebtoken';


//Endpoints
//---------------------------------------------------------------------------------------------------------------------------
user.post('/register',adminAuth, async (req, res) => {
    const { name, email, phone, role } = req.body;
    if (name && email && phone && role <= 3 && role >= 1) {
        let conn;
        try {
            conn = await pool.connect();
            if ( role == 1 ) if ( await platformAdminCheck(conn, req) ) return res.status(403).json({ message: 'Forbidden' });
            
            let user_key = crypto.createHash('MD5').update(name + email + Date.now()).digest('hex');
            
            // CORRECCIÓN: Convertir user_key explícitamente a String antes de hashear
            let password_hash = await bcrypt.hash(String(user_key), 12); 
            
            await conn.query('INSERT INTO users (name, email, password_hash, phone, active, created_at, user_key, role) VALUES ($1, $2, $3, $4, $5, $6, $7, $8);', [name, email, password_hash, phone, false, new Date(), user_key, role]);
            await sendMail(
                email,
                console.log("Correo DESACTIVADO: usuario creado con password temporal:", user_key)
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
            
            // CORRECCIÓN: Convertir new_hash explícitamente a String antes de hashear
            let password_hash = await bcrypt.hash(String(new_hash), 12); 
            
            await conn.query('UPDATE users SET password_hash = $1, active = false WHERE id = $2;', [password_hash, user_id]);
            let email = (await conn.query('SELECT email FROM users WHERE id = $1;', [user_id])).rows[0].email;
            await sendMail(
                email,
                console.log("Correo DESACTIVADO: password temporal generado:", new_hash)
            );
            return res.status(200).json({ message: 'Password reseted successfully' });
        } catch (error) {
            errorHandler(error, res);
        } finally {
            if (conn) conn.release();
        }
    } else return res.status(400).json({ message: 'Incomplete data' });
});


user.post('/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password)
        return res.status(400).json({ message: 'Incomplete data' });

    let conn;
    try {
        conn = await pool.connect();

        const result = await conn.query(
            'SELECT id, name, email, password_hash, role, active FROM users WHERE email = $1;',
            [email]
        );

        if (result.rows.length === 0)
            return res.status(404).json({ message: 'User not found' });

        const user = result.rows[0];

        //Validar contraseña
        const bcryptCompare = await bcrypt.compare(password, user.password_hash);
        if (!bcryptCompare)
            return res.status(401).json({ message: 'Incorrect credencials' });

        //Validar si la cuenta está activa
        if (!user.active)
            return res.status(401).json({ message: 'Forbidden NO permises' });

        //Crear token JWT
        const token = jwt.sign(
            {
                user_id: user.id,
                email: user.email,
                role: user.role
            },
            process.env.JWT_SECRET,
            { expiresIn: '8h' } // puedes cambiarlo
        );

        return res.status(200).json({
            message: 'Login successful',
            token,
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                role: user.role
            }
        });

    } catch (error) {
        errorHandler(error, res);
    } finally {
        if (conn) conn.release();
    }
});


//---------------------------------------------------------------------------------------------------------------------------

/**
 * GET /user_details/profile
 * Obtiene toda la información del perfil del usuario logueado.
 */
user.get('/profile', async (req, res) => {
    // AHORA CONSISTENTE: Se usa req.tokenData.user_id
    const user_id = req.tokenData.user_id; 

    let conn;
    try {
        conn = await pool.connect();
        
        // 1. Obtener información base del usuario y su rol
        const userQuery = `
            SELECT id, name, email, role, phone, active 
            FROM users 
            WHERE id = $1;
        `;
        const userResult = await conn.query(userQuery, [user_id]);
        
        if (userResult.rows.length === 0) {
            return res.status(404).json({ message: 'User not found' });
        }
        const userInfo = userResult.rows[0];

        // 2. Obtener proyectos donde el usuario es miembro
        const projectsQuery = `
            SELECT 
                p.id, p.name, p.status, p.end 
            FROM projects p
            JOIN project_members pm ON p.id = pm.project_id
            WHERE pm.user_id = $1;
        `;
        const projectsResult = await conn.query(projectsQuery, [user_id]);

        // 3. Consolidar y retornar
        return res.status(200).json({
            ...userInfo,
            projects: projectsResult.rows
        });

    } catch (error) {
        return errorHandler(error, res);
    } finally {
        if (conn) conn.release();
    }
});

/**
 * PUT /user_details/profile
 * Permite al usuario actualizar campos básicos de su perfil.
 */
user.put('/profile', async (req, res) => {
    // AHORA CONSISTENTE: Se usa req.tokenData.user_id
    const user_id = req.tokenData.user_id;
    const { name, phone } = req.body; 

    let conn;
    try {
        conn = await pool.connect();
        
        const updateQuery = `
            UPDATE users 
            SET name = $1, phone = $2, updated_at = CURRENT_TIMESTAMP
            WHERE id = $3 
            RETURNING id;
        `;
        const result = await conn.query(updateQuery, [name, phone, user_id]);
        
        if (result.rows.length === 0) {
            return res.status(404).json({ message: 'User not found or nothing updated' });
        }

        return res.status(200).json({ message: 'User profile updated successfully' });

    } catch (error) {
        return errorHandler(error, res);
    } finally {
        if (conn) conn.release();
    }
});


export default user;
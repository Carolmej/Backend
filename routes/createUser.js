import express from 'express'
import pool from '../config/DBManager.js';
import hashStrings from '../utilities/hashStrings.js';
import crypto from 'crypto'

const createUser = express.Router();



// endpoints for user management
//------------------------------------
// Create a new user
createUser.post('/', async (req, res, next) =>{

    if(!req.body) return res.status(400).json({ message: 'Missing request body' });

    const { name, email, phone, role } = req.body;

    const { tokenData } = req;

    if(!name || !email || !phone || !role) return res.status(400).json({ message: 'Missing required fields' });
    if(tokenData.role != 0) return res.status(403).json({ message: 'Forbidden' }); // only platform admin can create 'admin's
    if(!['0', '1', '2'].find(e=>e==role)) return res.status(400).json({ message: 'Invalid role' });

    let conn;

    const temporalPasswordLength = 32;
    const rawPassword = crypto.randomBytes( temporalPasswordLength / 2 ).toString('hex')
    const passwordHash = await hashStrings(rawPassword);
    const createdAt = new Date().toISOString().replace('T', ' ').replace('Z', '');
    const userKey = crypto.randomBytes(16).toString('hex');

    try{

        conn = await pool.connect();
        conn.query(`INSERT INTO users(name, email, password_hash, phone, active, created_at, user_key, role) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, [name, email, passwordHash, phone, true, createdAt, userKey, role]);

        res.status(201).json({ message: 'User create succesfully', tempPassword: rawPassword })

    }catch(e){
        console.log('error al crear usuario: createUser.js ==> ',e)
    }finally{
        if(conn) conn.release();
    }

    return res.status(500).json({message: 'error al crear usuario'})



})



export default createUser;

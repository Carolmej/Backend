import express from 'express'
import pool from '../config/DBManager.js';
import bcrypt from 'bcrypt'


const login = express.Router();

// Endpoint for user login
login.post('/', async (req, res, next) => {

    if (!req.body) return res.status(400).json({ message: 'Missing request body' });
    const { email, password: rawPassword } = req?.body;

    if (!email || !rawPassword) return res.status(400).json({ message: 'Missing required fields' });


    let conn;
    let isDbConnectionClosed = false;

    try {

        conn = await pool.connect();
        const queryResult = await conn.query('SELECT * FROM users WHERE email = $1', [email]);
        const userResult = queryResult.rows[0]

        if(queryResult.rowCount <= 0 ) {
            if (conn) conn.release()
            isDbConnectionClosed =true;
            return res.status(401).json({message: 'Invalid Credentials'})
        }

        const { id: userID, user_key: userKey, role, active: tempPassword, password_hash: hashedPasswordDb } = userResult
        const areTheSamePassword = await bcrypt.compare(rawPassword, hashedPasswordDb);

        if(!areTheSamePassword){
            if (conn) conn.release()
            isDbConnectionClosed =true;
            return res.status(401).json({message: 'Invalid Credentials'})
            
        }
        
        res.status(200).json({userID, userKey, role, tempPassword,});

    } catch (e) {
        console.log('error al loguear usuario: login.js ==> ', e)
        res.sendStatus(500).json({ message: 'backend error' });

    } finally {
        if (conn && !isDbConnectionClosed) conn.release(()=>{})

    }
    

});

export default login;





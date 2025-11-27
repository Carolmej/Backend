import express from 'express'
import pool from '../config/DBManager.js';
import generateToken from '../utilities/generateJWT.js';

const getToken = express.Router();

// Endpoint to get a new token using user_key
getToken.get('/getToken', async (req, res, next)=>{

    const { user_key: userKey } = req.headers;
    
    if(!userKey) return res.status(401).json({ error: 'Invalid credentials' });

    let conn;
    let isDbConnectionClosed = false;

    try{

        conn = await pool.connect();
        const queryResult = await conn.query(`SELECT * FROM users WHERE user_key = $1`, [userKey])
        const userResult = queryResult.rows[0]

        if(queryResult.rowCount <= 0 ) {
            if (conn) conn.release()
            isDbConnectionClosed =true;
            return res.status(401).json({message: 'Invalid Credentials'})
        }

        const { id: userId, role, user_key: userKeyDB} = userResult

        if(userKeyDB != userKey){
            if (conn) conn.release()
            isDbConnectionClosed =true;
            return res.status(401).json({message: 'Invalid Credentials'})
        }

        const token = generateToken(userId, role, userKeyDB);


        res.status(200).json({token})

    }catch(error){

    }finally{
        if (conn && !isDbConnectionClosed) conn.release(()=>{})
    }
})





export default getToken;
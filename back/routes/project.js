//Dependencies
import express from 'express';
import pool from '../config/DBManager.js';
import fs from 'fs';
import crypto from 'crypto';
import { openDB, createTables } from '../config/SQLiteManager.js';
import errorHandler from '../middleware/errorHandler.js';
import adminAuth from '../middleware/adminAuth.js';
const project  = express.Router();

//Endpoints
//---------------------------------------------------------------------------------------------------------------------------
project.post('/', adminAuth, async (req, res) => {
    const { name, description, client_id, team_leader_id, start, end } = req.body;
    if ( name && description && client_id && team_leader_id && start && end ) {
        let conn, liteConn, project_id;
        try {
            project_id = crypto.randomBytes(4).toString('hex');
            conn = await pool.connect();
            conn.query('BEGIN;');
            await conn.query('INSERT INTO projects VALUES ($1, $2, $3, $4, $5, $6, $7, $8);', [project_id, name, description, client_id, team_leader_id, start, end, `${project_id}.db`]);
            await conn.query('INSERT INTO project_members (project_id, user_id) VALUES ($1, $2);', [project_id, team_leader_id]);
            liteConn = openDB('./projects/' + project_id);
            createTables(liteConn);
            conn.query('COMMIT;');
            return res.status(201).json({ project_id: project_id });
        } catch (error) {
            conn.query('ROLLBACK;');
            if (liteConn) liteConn.close();
            if (fs.existsSync(`./projects/${project_id}.db`)) fs.unlinkSync(`./projects/${project_id}.db`);
            errorHandler(error, res);
        } finally {
            if (liteConn) liteConn.close();
            if (conn) conn.release();
        }
    } else return res.status(400).json({ message: 'Incomplete data' });
});
//---------------------------------------------------------------------------------------------------------------------------
export default project;
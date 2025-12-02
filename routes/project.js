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
// Get all projects
project.get('/', async (req, res) => {
    let conn;
    try {
        conn = await pool.connect();
        const result = await conn.query(`
            SELECT p.*, u.name AS leader_name
            FROM projects p
            JOIN users u ON p.team_leader_id = u.id
            ORDER BY p.start DESC;
        `);
        return res.status(200).json(result.rows);
    } catch (error) {
        return errorHandler(error, res);
    } finally {
        if (conn) conn.release();
    }
});

// Get project by ID
project.get('/:id', async (req, res) => {
    const { id } = req.params;
    let conn;
    try {
        conn = await pool.connect();
        const result = await conn.query(`
            SELECT p.id, p.name, p.description, p.client_id, p.team_leader_id, 
                   p.start, p.end, u.name AS leader_name
            FROM projects p
            JOIN users u ON p.team_leader_id = u.id
            WHERE p.id = $1;
        `, [id]);
        if (result.rows.length === 0)
            return res.status(404).json({ message: 'Project not found' });

        return res.status(200).json(result.rows[0]);
    } catch (error) {
        return errorHandler(error, res);
    } finally {
        if (conn) conn.release();
    }
});

// Update project
project.put('/:id', adminAuth, async (req, res) => {
    const { id } = req.params;
    const { name, description, client_id, team_leader_id, start, end } = req.body;

    if (name && description && client_id && team_leader_id && start && end) {
        let conn;
        try {
            conn = await pool.connect();
            const result = await conn.query(`
                UPDATE projects
                SET name = $1, description = $2, client_id = $3,
                    team_leader_id = $4, start = $5, end = $6
                WHERE id = $7;
            `, [name, description, client_id, team_leader_id, start, end, id]);

            if (result.rowCount === 0)
                return res.status(404).json({ message: 'Project not found' });

            return res.status(200).json({ message: 'Project updated successfully' });
        } catch (error) {
            return errorHandler(error, res);
        } finally {
            if (conn) conn.release();
        }

    } else return res.status(400).json({ message: 'Incomplete data' });
});

// Delete project
project.delete('/:id', adminAuth, async (req, res) => {
    const { id } = req.params;
    let conn;
    try {
        conn = await pool.connect();
        conn.query('BEGIN;');

        const result = await conn.query(`
            SELECT sqlite_file FROM projects WHERE id = $1;
        `, [id]);

        if (result.rows.length === 0)
            return res.status(404).json({ message: 'Project not found' });

        const sqliteFile = `./projects/${result.rows[0].sqlite_file}`;

        await conn.query(`DELETE FROM projects WHERE id = $1;`, [id]);
        conn.query('COMMIT;');

        if (fs.existsSync(sqliteFile))
            fs.unlinkSync(sqliteFile);

        return res.status(200).json({ message: 'Project deleted successfully' });

    } catch (error) {
        conn.query('ROLLBACK;');
        return errorHandler(error, res);
    } finally {
        if (conn) conn.release();
    }
});
//-----------------------------------------------------------------------------------------------------------
export default project;

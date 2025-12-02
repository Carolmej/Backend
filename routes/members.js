import express from 'express';
import pool from '../config/DBManager.js';
import errorHandler from '../middleware/errorHandler.js';

const members = express.Router();

// Add member to project
members.post('/:project_id', async (req, res) => {
    const { project_id } = req.params;
    const { user_id } = req.body;

    if (project_id && user_id) {
        let conn;
        try {
            conn = await pool.connect();
            await conn.query(`
                INSERT INTO project_members (project_id, user_id)
                VALUES ($1, $2);
            `, [project_id, user_id]);

            return res.status(201).json({ message: 'Member added successfully' });

        } catch (error) {
            return errorHandler(error, res);

        } finally {
            if (conn) conn.release();
        }

    } else return res.status(400).json({ message: 'Incomplete data' });
});

// Get all members of a project
members.get('/:project_id', async (req, res) => {
    const { project_id } = req.params;

    let conn;
    try {
        conn = await pool.connect();
        const result = await conn.query(`
            SELECT u.id, u.name, u.email, u.role
            FROM project_members pm
            JOIN users u ON u.id = pm.user_id
            WHERE pm.project_id = $1;
        `, [project_id]);

        return res.status(200).json(result.rows);

    } catch (error) {
        return errorHandler(error, res);

    } finally {
        if (conn) conn.release();
    }
});

// Get specific member of a project
members.get('/:project_id/:user_id', async (req, res) => {
    const { project_id, user_id } = req.params;

    let conn;
    try {
        conn = await pool.connect();
        const result = await conn.query(`
            SELECT u.id, u.name, u.email, u.role
            FROM project_members pm
            JOIN users u ON u.id = pm.user_id
            WHERE pm.project_id = $1 AND pm.user_id = $2;
        `, [project_id, user_id]);

        if (result.rows.length === 0)
            return res.status(404).json({ message: 'Member not found' });

        return res.status(200).json(result.rows[0]);

    } catch (error) {
        return errorHandler(error, res);

    } finally {
        if (conn) conn.release();
    }
});

// Delete member from project
members.delete('/:project_id/:user_id', async (req, res) => {
    const { project_id, user_id } = req.params;

    let conn;
    try {
        conn = await pool.connect();
        await conn.query(`
            DELETE FROM project_members
            WHERE project_id = $1 AND user_id = $2;
        `, [project_id, user_id]);

        return res.status(200).json({ message: 'Member removed successfully' });

    } catch (error) {
        return errorHandler(error, res);

    } finally {
        if (conn) conn.release();
    }
});

export default members;

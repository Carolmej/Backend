import express from 'express';
import pool from '../config/DBManager.js';
import errorHandler from '../middleware/errorHandler.js';

const members = express.Router();

// Helper: verificar si el proyecto existe
async function projectExists(projectId) {
    const conn = await pool.connect();
    const result = await conn.query(
        "SELECT id FROM projects WHERE id = $1",
        [projectId]
    );
    conn.release();
    return result.rows.length > 0;
}

// Helper: verificar si el usuario existe
async function userExists(userId) {
    const conn = await pool.connect();
    const result = await conn.query(
        "SELECT id FROM users WHERE id = $1",
        [userId]
    );
    conn.release();
    return result.rows.length > 0;
}

// Añadir miembro al proyecto
members.post('/:projectId', async (req, res) => {
    const { projectId } = req.params;
    const { user_id } = req.body;

    // Validar campos
    if (!user_id)
        return res.status(400).json({ message: "User id required" });

    try {
        if (!(await projectExists(projectId)))
            return res.status(404).json({ message: "Project not found" });

        if (!(await userExists(user_id)))
            return res.status(404).json({ message: "User not found" });

        const conn = await pool.connect();

        // Insertar miembro
        await conn.query(
            `INSERT INTO project_members (project_id, user_id)
             VALUES ($1, $2)`,
            [projectId, user_id]
        );

        conn.release();
        return res.status(201).json({ message: "Member added" });

    } catch (error) {
        return errorHandler(error, res);
    }
});

// Listar miembros del proyecto
members.get('/:projectId', async (req, res) => {
    const { projectId } = req.params;

    try {
        const conn = await pool.connect();

        // Obtener miembros
        const members = await conn.query(
            `SELECT users.id, users.name, users.email, users.role 
             FROM project_members
             INNER JOIN users ON users.id = project_members.user_id
             WHERE project_members.project_id = $1`,
            [projectId]
        );

        conn.release();

        return res.status(200).json(members.rows);

    } catch (error) {
        return errorHandler(error, res);
    }
});

// Quitar miembro del proyecto
members.delete('/:projectId/:userId', async (req, res) => {
    const { projectId, userId } = req.params;

    try {
        const conn = await pool.connect();

        // Borrar el miembro
        await conn.query(
            `DELETE FROM project_members 
             WHERE project_id = $1 AND user_id = $2`,
            [projectId, userId]
        );

        conn.release();

        return res.status(200).json({ message: "Member removed" });

    } catch (error) {
        return errorHandler(error, res);
    }
});

// Obtener un miembro específico
members.get('/:projectId/:userId', async (req, res) => {
    const { projectId, userId } = req.params;

    try {
        const conn = await pool.connect();

        const member = await conn.query(
            `SELECT users.id, users.name, users.email, users.role 
             FROM project_members
             INNER JOIN users ON users.id = project_members.user_id
             WHERE project_members.project_id = $1 
             AND project_members.user_id = $2`,
            [projectId, userId]
        );

        conn.release();

        if (member.rows.length === 0)
            return res.status(404).json({ message: "Member not found" });

        return res.status(200).json(member.rows[0]);

    } catch (error) {
        return errorHandler(error, res);
    }
});

export default members;
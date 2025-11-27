import express from 'express';
import pool from '../config/DBManager.js';
import { openDB } from '../config/SQLiteManager.js';
import errorHandler from '../middleware/errorHandler.js';

const teams = express.Router();

// Helper: obtener la bd sqlite del proyecto
function getDB(projectId) {
    return openDB(./projects/${projectId});
}

// Helper: verify if project exists
async function projectExists(projectId) {
    const conn = await pool.connect();
    const result = await conn.query("SELECT id FROM projects WHERE id = $1", [projectId]);
    conn.release();
    return result.rows.length > 0;
}

// Create a new team
teams.post('/:projectId', async (req, res) => {
    const { projectId } = req.params;
    const { name, description } = req.body;

    if (!name)
        return res.status(400).json({ message: "Name required" });

    try {
        if (!(await projectExists(projectId)))
            return res.status(404).json({ message: "Project not found" });

        const db = getDB(projectId);

        db.prepare(`
            INSERT INTO teams (name, description)
            VALUES (?, ?)
        `).run(name, description || "");

        return res.status(201).json({ message: "Team created" });

    } catch (error) {
        errorHandler(error, res);
    }
});

// Listar equipos
teams.get('/:projectId', async (req, res) => {
    const { projectId } = req.params;

    try {
        const db = getDB(projectId);

        const rows = db.prepare(SELECT * FROM teams).all();

        return res.status(200).json(rows);

    } catch (error) {
        errorHandler(error, res);
    }
});

// Obtener un equipo
teams.get('/:projectId/:teamId', async (req, res) => {
    const { projectId, teamId } = req.params;

    try {
        const db = getDB(projectId);

        const team = db.prepare(SELECT * FROM teams WHERE id = ?).get(teamId);

        if (!team)
            return res.status(404).json({ message: "Team not found" });

        return res.status(200).json(team);

    } catch (error) {
        errorHandler(error, res);
    }
});

// Edit team
teams.put('/:projectId/:teamId', async (req, res) => {
    const { projectId, teamId } = req.params;
    const { name, description } = req.body;

    try {
        const db = getDB(projectId);

        const exists = db.prepare(SELECT id FROM teams WHERE id = ?).get(teamId);
        if (!exists)
            return res.status(404).json({ message: "Team not found" });

        db.prepare(`
            UPDATE teams
            SET name = ?, description = ?
            WHERE id = ?
        `).run(name, description, teamId);

        return res.status(200).json({ message: "Team updated" });

    } catch (error) {
        errorHandler(error, res);
    }
});

// Delete team
teams.delete('/:projectId/:teamId', async (req, res) => {
    const { projectId, teamId } = req.params;

    try {
        const db = getDB(projectId);

        db.prepare(DELETE FROM teams WHERE id = ?).run(teamId);
        db.prepare(DELETE FROM teammembers WHERE team_id = ?).run(teamId);

        return res.status(200).json({ message: "Team deleted" });

    } catch (error) {
        errorHandler(error, res);
    }
});

// Add member to team
teams.post('/:projectId/:teamId/member', async (req, res) => {
    const { projectId, teamId } = req.params;
    const { user_id } = req.body;

    if (!user_id)
        return res.status(400).json({ message: "User id required" });

    try {
        const db = getDB(projectId);

        db.prepare(`
            INSERT INTO teammembers (team_id, user_id)
            VALUES (?, ?)
        `).run(teamId, user_id);

        return res.status(201).json({ message: "Member added" });

    } catch (error) {
        errorHandler(error, res);
    }
});

// Delete member from team
teams.delete('/:projectId/:teamId/member/:userId', async (req, res) => {
    const { projectId, teamId, userId } = req.params;

    try {
        const db = getDB(projectId);

        db.prepare(`
            DELETE FROM teammembers
            WHERE team_id = ? AND user_id = ?
        `).run(teamId, userId);

        return res.status(200).json({ message: "Member removed" });

    } catch (error) {
        errorHandler(error, res);
    }
});

// view team members
teams.get('/:projectId/:teamId/members', async (req, res) => {
    const { projectId, teamId } = req.params;

    try {
        const db = getDB(projectId);

        const rows = db.prepare(`
            SELECT user_id FROM teammembers WHERE team_id = ?
        `).all(teamId);

        return res.status(200).json(rows);

    } catch (error) {
        errorHandler(error, res);
    }
});

export default teams;
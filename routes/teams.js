import express from 'express';
import { openDB } from '../config/SQLiteManager.js';
import errorHandler from '../middleware/errorHandler.js';

const teams = express.Router();

// Create team
teams.post('/:project_id', async (req, res) => {
    const { project_id } = req.params;
    const { name, description } = req.body;

    if (project_id && name) {
        let db;
        try {
            db = openDB('./projects/' + project_id);

            db.prepare(`
                INSERT INTO teams (name, description)
                VALUES (?, ?);
            `).run(name, description || "");

            return res.status(201).json({ message: 'Team created successfully' });

        } catch (error) {
            return errorHandler(error, res);

        } finally {
            if (db) db.close();
        }

    } else return res.status(400).json({ message: 'Incomplete data' });
});

// Get all teams
teams.get('/:project_id', async (req, res) => {
    const { project_id } = req.params;

    let db;
    try {
        db = openDB('./projects/' + project_id);

        const rows = db.prepare(`
            SELECT * FROM teams;
        `).all();

        return res.status(200).json(rows);

    } catch (error) {
        return errorHandler(error, res);

    } finally {
        if (db) db.close();
    }
});

// Get team by id
teams.get('/:project_id/:team_id', async (req, res) => {
    const { project_id, team_id } = req.params;

    let db;
    try {
        db = openDB('./projects/' + project_id);

        const row = db.prepare(`
            SELECT * FROM teams WHERE id = ?;
        `).get(team_id);

        if (!row)
            return res.status(404).json({ message: 'Team not found' });

        return res.status(200).json(row);

    } catch (error) {
        return errorHandler(error, res);

    } finally {
        if (db) db.close();
    }
});

// Update team
teams.put('/:project_id/:team_id', async (req, res) => {
    const { project_id, team_id } = req.params;
    const { name, description } = req.body;

    if (name) {
        let db;
        try {
            db = openDB('./projects/' + project_id);

            const exists = db.prepare(`
                SELECT id FROM teams WHERE id = ?;
            `).get(team_id);

            if (!exists)
                return res.status(404).json({ message: 'Team not found' });

            db.prepare(`
                UPDATE teams
                SET name = ?, description = ?
                WHERE id = ?;
            `).run(name, description, team_id);

            return res.status(200).json({ message: 'Team updated successfully' });

        } catch (error) {
            return errorHandler(error, res);

        } finally {
            if (db) db.close();
        }

    } else return res.status(400).json({ message: 'Incomplete data' });
});

// Delete team
teams.delete('/:project_id/:team_id', async (req, res) => {
    const { project_id, team_id } = req.params;

    let db;
    try {
        db = openDB('./projects/' + project_id);

        db.prepare(`
            DELETE FROM teams WHERE id = ?;
        `).run(team_id);

        db.prepare(`
            DELETE FROM teammembers WHERE team_id = ?;
        `).run(team_id);

        return res.status(200).json({ message: 'Team deleted successfully' });

    } catch (error) {
        return errorHandler(error, res);

    } finally {
        if (db) db.close();
    }
});

// Add user to team
teams.post('/:project_id/:team_id/member', async (req, res) => {
    const { project_id, team_id } = req.params;
    const { user_id } = req.body;

    if (user_id) {
        let db;
        try {
            db = openDB('./projects/' + project_id);

            db.prepare(`
                INSERT INTO teammembers (team_id, user_id)
                VALUES (?, ?);
            `).run(team_id, user_id);

            return res.status(201).json({ message: 'Member added successfully' });

        } catch (error) {
            return errorHandler(error, res);

        } finally {
            if (db) db.close();
        }

    } else return res.status(400).json({ message: 'Incomplete data' });
});

// Remove user from team
teams.delete('/:project_id/:team_id/member/:user_id', async (req, res) => {
    const { project_id, team_id, user_id } = req.params;

    let db;
    try {
        db = openDB('./projects/' + project_id);

        db.prepare(`
            DELETE FROM teammembers
            WHERE team_id = ? AND user_id = ?;
        `).run(team_id, user_id);

        return res.status(200).json({ message: 'Member removed successfully' });

    } catch (error) {
        return errorHandler(error, res);

    } finally {
        if (db) db.close();
    }
});
//-----------------------------------------------------------------------------------------------------------
export default teams;

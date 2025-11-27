import express from 'express';
import pool from '../config/DBManager.js';
import { openDB } from '../config/SQLiteManager.js';
import errorHandler from '../middleware/errorHandler.js';

const tasks = express.Router();

// Helper: Get SQLite DB for project
function getDB(projectId) {
    return openDB(`./projects/${projectId}`);
}

// Helper: verify if project exists
async function projectExists(projectId) {
    const conn = await pool.connect();
    const result = await conn.query(
        "SELECT id FROM projects WHERE id = $1",
        [projectId]
    );
    conn.release();
    return result.rows.length > 0;
}

// Create a new task
tasks.post('/:projectId', async (req, res) => {
    const { projectId } = req.params;
    const { module_id, title, description, priority, status, user_ids } = req.body;

    if (!title)
        return res.status(400).json({ message: "Title required" });

    try {
        if (!(await projectExists(projectId)))
            return res.status(404).json({ message: "Project not found" });

        const db = getDB(projectId);

        db.prepare(`
            INSERT INTO tasks (module_id, title, description, priority, status, user_ids)
            VALUES (?, ?, ?, ?, ?, ?)
        `).run(module_id || null, title, description || "", priority || "", status || "pending", user_ids || null);

        return res.status(201).json({ message: "Task created" });

    } catch (error) {
        return errorHandler(error, res);
    }
});

// View all  tasks
tasks.get('/:projectId', async (req, res) => {
    const { projectId } = req.params;

    try {
        if (!(await projectExists(projectId)))
            return res.status(404).json({ message: "Project not found" });

        const db = getDB(projectId);

        const rows = db.prepare(`SELECT * FROM tasks ORDER BY created_at DESC`).all();

        return res.status(200).json(rows);

    } catch (error) {
        return errorHandler(error, res);
    }
});

// List of tasks by module
tasks.get('/:projectId/module/:moduleId', async (req, res) => {
    const { projectId, moduleId } = req.params;

    try {
        if (!(await projectExists(projectId)))
            return res.status(404).json({ message: "Project not found" });

        const db = getDB(projectId);

        const rows = db.prepare(`SELECT * FROM tasks WHERE module_id = ?`).all(moduleId);

        return res.status(200).json(rows);

    } catch (error) {
        return errorHandler(error, res);
    }
});

// Obtener una tarea
tasks.get('/:projectId/task/:taskId', async (req, res) => {
    const { projectId, taskId } = req.params;

    try {
        const db = getDB(projectId);

        const task = db.prepare(`SELECT * FROM tasks WHERE id = ?`).get(taskId);

        if (!task)
            return res.status(404).json({ message: "Task not found" });

        return res.status(200).json(task);

    } catch (error) {
        return errorHandler(error, res);
    }
});

// Update task 
tasks.put('/:projectId/task/:taskId', async (req, res) => {
    const { projectId, taskId } = req.params;
    const { title, description, priority, status, user_ids, module_id } = req.body;

    try {
        const db = getDB(projectId);

        const exists = db.prepare(`SELECT id FROM tasks WHERE id = ?`).get(taskId);
        if (!exists)
            return res.status(404).json({ message: "Task not found" });

        db.prepare(`
            UPDATE tasks
            SET title = ?, description = ?, priority = ?, status = ?, user_ids = ?, module_id = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        `).run(title, description, priority, status, user_ids, module_id, taskId);

        return res.status(200).json({ message: "Task updated" });

    } catch (error) {
        return errorHandler(error, res);
    }
});

// Change task status
tasks.patch('/:projectId/task/:taskId/status', async (req, res) => {
    const { projectId, taskId } = req.params;
    const { status } = req.body;

    if (!status)
        return res.status(400).json({ message: "Status required" });

    try {
        const db = getDB(projectId);

        db.prepare(`
            UPDATE tasks SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?
        `).run(status, taskId);

        return res.status(200).json({ message: "Status updated" });

    } catch (error) {
        return errorHandler(error, res);
    }
});

// Eliminate tasks
tasks.delete('/:projectId/task/:taskId', async (req, res) => {
    const { projectId, taskId } = req.params;

    try {
        const db = getDB(projectId);
        db.prepare(`DELETE FROM tasks WHERE id = ?`).run(taskId);

        return res.status(200).json({ message: "Task deleted" });

    } catch (error) {
        return errorHandler(error, res);
    }
});

export default tasks;

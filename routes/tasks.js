import express from 'express';
import pool from '../config/DBManager.js';
import { openDB } from '../config/SQLiteManager.js';
import errorHandler from '../middleware/errorHandler.js';

const tasks = express.Router();

// Create task
tasks.post('/:project_id', async (req, res) => {
    const { project_id } = req.params;
<<<<<<< HEAD
    const { module_id, title, description, priority, status, user_ids } = req.body;
=======
    // NOTA: Se asume que la tabla tasks en SQLite ahora tiene el campo due_date.
    const { module_id, title, description, priority, status, user_ids, due_date } = req.body; 
>>>>>>> elMakeo

    if (project_id && title) {
        let db;
        try {
            db = openDB('./projects/' + project_id);
            db.prepare(`
<<<<<<< HEAD
                INSERT INTO tasks (module_id, title, description, priority, status, user_ids)
                VALUES (?, ?, ?, ?, ?, ?);
            `).run(module_id || null, title, description || "", priority || "", status || "pending", user_ids || null);
=======
                INSERT INTO tasks (module_id, title, description, priority, status, user_ids, due_date)
                VALUES (?, ?, ?, ?, ?, ?, ?);
            `).run(module_id || null, title, description || "", priority || "", status || "pending", user_ids || null, due_date || null); // due_date añadido
>>>>>>> elMakeo

            return res.status(201).json({ message: 'Task created successfully' });

        } catch (error) {
            return errorHandler(error, res);
        } finally {
            if (db) db.close();
        }

    } else return res.status(400).json({ message: 'Incomplete data' });
});

// Get all tasks
tasks.get('/:project_id', async (req, res) => {
    const { project_id } = req.params;
    let db;
    try {
        db = openDB('./projects/' + project_id);
        const rows = db.prepare(`SELECT * FROM tasks ORDER BY created_at DESC;`).all();
        return res.status(200).json(rows);

    } catch (error) {
        return errorHandler(error, res);
    } finally {
        if (db) db.close();
    }
});

// Get task by ID
tasks.get('/:project_id/:task_id', async (req, res) => {
    const { project_id, task_id } = req.params;
    let db;
    try {
        db = openDB('./projects/' + project_id);
        const row = db.prepare(`SELECT * FROM tasks WHERE id = ?;`).get(task_id);

        if (!row)
            return res.status(404).json({ message: 'Task not found' });

        return res.status(200).json(row);

    } catch (error) {
        return errorHandler(error, res);
    } finally {
        if (db) db.close();
    }
});

// Update task
tasks.put('/:project_id/:task_id', async (req, res) => {
    const { project_id, task_id } = req.params;
<<<<<<< HEAD
    const { module_id, title, description, priority, status, user_ids } = req.body;
=======
    // NOTA: Se asume que la tabla tasks en SQLite ahora tiene el campo due_date.
    const { module_id, title, description, priority, status, user_ids, due_date } = req.body; 
>>>>>>> elMakeo

    if (title && status) {
        let db;
        try {
            db = openDB('./projects/' + project_id);

            const exists = db.prepare(`SELECT id FROM tasks WHERE id = ?;`).get(task_id);
            if (!exists)
                return res.status(404).json({ message: 'Task not found' });

            db.prepare(`
                UPDATE tasks 
<<<<<<< HEAD
                SET module_id = ?, title = ?, description = ?, priority = ?, status = ?, user_ids = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?;
            `).run(module_id, title, description, priority, status, user_ids, task_id);
=======
                SET module_id = ?, title = ?, description = ?, priority = ?, status = ?, user_ids = ?, due_date = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?;
            `).run(module_id, title, description, priority, status, user_ids, due_date, task_id); // due_date añadido
>>>>>>> elMakeo

            return res.status(200).json({ message: 'Task updated successfully' });

        } catch (error) {
            return errorHandler(error, res);
        } finally {
            if (db) db.close();
        }

    } else return res.status(400).json({ message: "Incomplete data" });
});

<<<<<<< HEAD
// Update task status
=======
// Update task status (Requerimiento funcional: Actualizar Progreso de Tarea)
>>>>>>> elMakeo
tasks.patch('/:project_id/:task_id/status', async (req, res) => {
    const { project_id, task_id } = req.params;
    const { status } = req.body;

    if (status) {
        let db;
        try {
            db = openDB('./projects/' + project_id);

            db.prepare(`
                UPDATE tasks 
                SET status = ?, updated_at = CURRENT_TIMESTAMP 
                WHERE id = ?;
            `).run(status, task_id);

            return res.status(200).json({ message: 'Status updated successfully' });

        } catch (error) {
            return errorHandler(error, res);
        } finally {
            if (db) db.close();
        }

    } else return res.status(400).json({ message: "Incomplete data" });
});

// Delete task
tasks.delete('/:project_id/:task_id', async (req, res) => {
    const { project_id, task_id } = req.params;
    let db;
    try {
        db = openDB('./projects/' + project_id);

        db.prepare(`DELETE FROM tasks WHERE id = ?;`).run(task_id);

        return res.status(200).json({ message: 'Task deleted successfully' });

    } catch (error) {
        return errorHandler(error, res);
    } finally {
        if (db) db.close();
    }
});

export default tasks;

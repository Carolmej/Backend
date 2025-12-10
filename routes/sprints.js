// Backend/routes/modules.js
import express from 'express';
import { openDB } from '../config/SQLiteManager.js';
import errorHandler from '../middleware/errorHandler.js';

const modules = express.Router();

// Crear Módulo/Sprint
modules.post('/:project_id', async (req, res) => {
    const { project_id } = req.params;
    const { title, description, priority, status } = req.body;

    if (project_id && title) {
        let db;
        try {
            db = openDB('./projects/' + project_id);
            // Inserta un nuevo módulo/sprint
            db.prepare(`
                INSERT INTO modules (title, description, priority, status)
                VALUES (?, ?, ?, ?);
            `).run(title, description || "", priority || "medium", status || "active");

            return res.status(201).json({ message: 'Module/Sprint created successfully' });

        } catch (error) {
            return errorHandler(error, res);
        } finally {
            if (db) db.close();
        }

    } else return res.status(400).json({ message: 'Incomplete data' });
});

// Obtener todos los Módulos/Sprints
modules.get('/:project_id', async (req, res) => {
    const { project_id } = req.params;
    let db;
    try {
        db = openDB('./projects/' + project_id);
        const rows = db.prepare(`SELECT * FROM modules ORDER BY created_at DESC;`).all();
        return res.status(200).json(rows);

    } catch (error) {
        return errorHandler(error, res);
    } finally {
        if (db) db.close();
    }
});

// Obtener Módulo/Sprint por ID
modules.get('/:project_id/:module_id', async (req, res) => {
    const { project_id, module_id } = req.params;
    let db;
    try {
        db = openDB('./projects/' + project_id);
        const row = db.prepare(`SELECT * FROM modules WHERE id = ?;`).get(module_id);

        if (!row)
            return res.status(404).json({ message: 'Module/Sprint not found' });

        return res.status(200).json(row);

    } catch (error) {
        return errorHandler(error, res);
    } finally {
        if (db) db.close();
    }
});

// Actualizar Módulo/Sprint
modules.put('/:project_id/:module_id', async (req, res) => {
    const { project_id, module_id } = req.params;
    const { title, description, priority, status } = req.body;

    if (title) {
        let db;
        try {
            db = openDB('./projects/' + project_id);

            const exists = db.prepare(`SELECT id FROM modules WHERE id = ?;`).get(module_id);
            if (!exists)
                return res.status(404).json({ message: 'Module/Sprint not found' });

            db.prepare(`
                UPDATE modules 
                SET title = ?, description = ?, priority = ?, status = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?;
            `).run(title, description, priority, status, module_id);

            return res.status(200).json({ message: 'Module/Sprint updated successfully' });

        } catch (error) {
            return errorHandler(error, res);
        } finally {
            if (db) db.close();
        }

    } else return res.status(400).json({ message: "Incomplete data" });
});

// Eliminar Módulo/Sprint
modules.delete('/:project_id/:module_id', async (req, res) => {
    const { project_id, module_id } = req.params;
    let db;
    try {
        db = openDB('./projects/' + project_id);

        // Elimina el módulo
        db.prepare(`DELETE FROM modules WHERE id = ?;`).run(module_id);

        return res.status(200).json({ message: 'Module/Sprint deleted successfully' });

    } catch (error) {
        return errorHandler(error, res);
    } finally {
        if (db) db.close();
    }
});

export default modules;
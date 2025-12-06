// Backend/routes/notifications.js
import express from 'express';
import pool from '../config/DBManager.js';
import errorHandler from '../middleware/errorHandler.js';

const notifications = express.Router();

/**
 * GET /notifications
 * Obtiene la lista de notificaciones para el usuario logueado.
 */
notifications.get('/', async (req, res) => {
    const user_id = req.user.id;
    // Paginación para eficiencia móvil
    const { limit = 20, offset = 0 } = req.query; 

    let conn;
    try {
        conn = await pool.connect();
        
        const query = `
            SELECT id, title, content, is_read, created_at 
            FROM notifications 
            WHERE user_id = $1
            ORDER BY created_at DESC
            LIMIT $2 OFFSET $3;
        `;
        const result = await conn.query(query, [user_id, limit, offset]);

        return res.status(200).json(result.rows);

    } catch (error) {
        return errorHandler(error, res);
    } finally {
        if (conn) conn.release();
    }
});

/**
 * PATCH /notifications/:notification_id/read
 * Marca una notificación específica como leída.
 */
notifications.patch('/:notification_id/read', async (req, res) => {
    const user_id = req.user.id;
    const { notification_id } = req.params;

    let conn;
    try {
        conn = await pool.connect();
        
        const query = `
            UPDATE notifications 
            SET is_read = TRUE, updated_at = CURRENT_TIMESTAMP
            WHERE id = $1 AND user_id = $2
            RETURNING id;
        `;
        const result = await conn.query(query, [notification_id, user_id]);

        if (result.rows.length === 0) {
            return res.status(404).json({ message: 'Notification not found or access denied' });
        }

        return res.status(200).json({ message: 'Notification marked as read' });

    } catch (error) {
        return errorHandler(error);
    } finally {
        if (conn) conn.release();
    }
});

export default notifications;
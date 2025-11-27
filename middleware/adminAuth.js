import pool from "../config/DBManager.js";
import errorHandler from "../middleware/errorHandler.js";

export default async (req, res, next) => {
    let conn;
    try {
        conn = await pool.connect();
        const result = await conn.query('SELECT role FROM users WHERE user_key = $1;', [req.tokenData.user_key]);
        if (result.rows.length === 0) {
            return res.status(401).json({ message: 'Invalid admin credentials' });
        } else if (result.rows[0].role > 1) {
            return res.status(403).json({ message: 'Forbidden' });
        } else {
            next();
        }
    } catch (error) {
        errorHandler(error, res);
    } finally {
        if (conn) conn.release();
    }
}
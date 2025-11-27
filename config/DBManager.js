import pg from 'pg';

const pool = new pg.Pool({
    host: 'localhost',
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DB,
    max: process.env.DB_CONNECTION_LIMIT
});

export default pool;
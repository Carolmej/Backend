import express from 'express';
import pool from '../config/DBManager.js';
import fs from 'fs';
import crypto from 'crypto';
import { openDB, createTables } from '../config/SQLiteManager.js';
import errorHandler from '../middleware/errorHandler.js';
import adminAuth from '../middleware/adminAuth.js';
const reports = express.Router();


// just like we have been doing in project.js, here we will create endpoints to generate reports.
// instead use 'projects.get('/getProject', ...) ... etc' you will use 'reports.get(...', etc








export default reports;




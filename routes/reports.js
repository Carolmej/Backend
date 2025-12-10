// Backend/routes/reports.js
import express from 'express';
import pool from '../config/DBManager.js';
import errorHandler from '../middleware/errorHandler.js';
import { openDB } from '../config/SQLiteManager.js';

// Dependencias necesarias para la generación de PDF y manejo de archivos
import fs from 'fs';
import path from 'path';
import { PDFDocument, rgb } from 'pdf-lib'; 

const reports = express.Router();

// --- CONFIGURACIÓN Y FUNCIONES AUXILIARES DE PDF ---
// Carpeta donde se guardarán los reportes
const REPORTS_PATH = path.join(process.cwd(), 'reports'); 

// Placeholder para funciones de PDF (ajustar según tu librería real)
const pixelToPoints = (px) => px * 0.75; 
const splitText = (text, maxWidth, font, fontSize) => [[text, 1]]; 
// --- FIN FUNCIONES AUXILIARES DE PDF ---

/**
 * Middleware de Autenticación de Reportes: 
 * Permite al propio usuario o a un administrador (rol 1) acceder.
 */
const checkReportAuth = (req, res, next) => {
    // El user_id en el parámetro de la URL es un string, lo convertimos a entero
    const reportUser = parseInt(req.params.user_id, 10); 
    
    // req.tokenData.user_id y req.tokenData.role son adjuntados por tokenAuth.js
    if (req.tokenData.user_id === reportUser || req.tokenData.role <= 1) { 
        next();
    } else {
        return res.status(403).json({ message: 'Forbidden: You do not have permission to view this report.' });
    }
};

/**
 * Función auxiliar para obtener las fechas límite de comparación (hoy y +7 días).
 */
const getDueDates = () => {
    const today = new Date();
    today.setHours(0, 0, 0, 0); 

    const sevenDaysFromNow = new Date(today);
    sevenDaysFromNow.setDate(today.getDate() + 7);

    // Formato YYYY-MM-DD para la comparación de cadenas
    return {
        todayISO: today.toISOString().split('T')[0], 
        sevenDaysISO: sevenDaysFromNow.toISOString().split('T')[0]
    };
};

/**
 * Función central para obtener y agregar datos de progreso por módulo (Reporte 4 y 5).
 * @param {string} projectId - ID del proyecto.
 * @returns {object} - Datos agregados.
 */
const getModuleProgressReportData = (projectId) => {
    let db;
    const reportData = {
        modules: {},
        modulesCount: 0,
        totalTasks: { total: 0, completed: 0 }
    };
    
    try {
        db = openDB(`./projects/${projectId}`); 
        
        // 1. Obtener módulos y tareas
        const modules = db.prepare(`SELECT id, title FROM modules;`).all();
        const tasks = db.prepare(`SELECT module_id, status FROM tasks;`).all();
        
        reportData.modulesCount = modules.length;
        
        // 2. Inicializar estructura por nombre de módulo
        modules.forEach(mod => {
            reportData.modules[mod.title] = { total: 0, completed: 0, percentage: '0%' };
        });
        
        // 3. Agregar tareas
        tasks.forEach(task => {
            const module = modules.find(m => m.id === task.module_id);
            const moduleName = module ? module.title : 'Unassigned Module'; 
            
            if (reportData.modules[moduleName] === undefined) {
                 reportData.modules[moduleName] = { total: 0, completed: 0, percentage: '0%' };
            }
            
            reportData.modules[moduleName].total++;
            reportData.totalTasks.total++;
            
            if (task.status === 'completed') {
                reportData.modules[moduleName].completed++;
                reportData.totalTasks.completed++;
            }
        });
        
        // 4. Calcular porcentajes
        Object.keys(reportData.modules).forEach(moduleName => {
            const mod = reportData.modules[moduleName];
            mod.percentage = mod.total > 0 
                ? ((mod.completed / mod.total) * 100).toFixed(0) + '%' 
                : '0%';
        });
        
        return reportData;
        
    } catch (error) {
        console.error("Error al agregar datos del proyecto:", error);
        throw new Error("Failed to aggregate project data.");
    } finally {
        if (db) db.close();
    }
};

/**
 * Genera el archivo PDF con la información del reporte (Reporte 5).
 */
const generateModuleReportPdf = async (reportData, projectName, projectId) => {
    const pdfDoc = await PDFDocument.create();
    const page = pdfDoc.addPage();
    const { width, height } = page.getSize();
    const fontSize = 12;
    const helvFont = await pdfDoc.embedFont('Helvetica');
    const helvBoldFont = await pdfDoc.embedFont('Helvetica-Bold');
    
    let y = height - 50; 

    // Título principal
    const title = `REPORTE DE PROGRESO DE MÓDULOS\nProyecto: ${projectName}`;
    page.drawText(title, { x: 50, y: y, size: 18, font: helvBoldFont, color: rgb(0, 0, 0.5) });
    y -= 50;

    // Resumen General
    const totalCompletion = reportData.totalTasks.total > 0 
        ? ((reportData.totalTasks.completed / reportData.totalTasks.total) * 100).toFixed(2) 
        : '0.00';
    
    page.drawText(`RESUMEN DEL PROYECTO (${totalCompletion}%)`, {
        x: 50, y: y, size: 14, font: helvBoldFont, color: rgb(0.2, 0.2, 0.2)
    });
    y -= 20;
    page.drawText(`Total Tareas: ${reportData.totalTasks.total} tareas, ${reportData.totalTasks.completed} completadas`, {
        x: 50, y: y, size: fontSize, font: helvFont,
    });
    y -= 40;

    // Detalle por Módulo
    page.drawText(`DETALLE POR MÓDULO (${reportData.modulesCount} Módulos)`, {
        x: 50, y: y, size: 14, font: helvBoldFont, color: rgb(0.1, 0.4, 0.1),
    });
    y -= 25;

    Object.keys(reportData.modules).forEach(moduleName => {
        const mod = reportData.modules[moduleName];
        
        // Módulo y Porcentaje
        page.drawText(`${moduleName}: ${mod.percentage}`, {
            x: 70, y: y, size: fontSize, font: helvBoldFont, color: rgb(0, 0, 0),
        });
        y -= 15;

        // Tareas del Módulo
        page.drawText(`  - Tareas: ${mod.total}, Completadas: ${mod.completed}`, {
            x: 90, y: y, size: fontSize - 2, font: helvFont, color: rgb(0.3, 0.3, 0.3),
        });
        y -= 25; 
    });
    
    // Gráfica Placeholder
    if (y < 100) { 
        page = pdfDoc.addPage();
        y = height - 50;
    }
    
    // Guardar el PDF
    if (!fs.existsSync(REPORTS_PATH)) fs.mkdirSync(REPORTS_PATH, { recursive: true });
    
    const outputPath = path.join(REPORTS_PATH, `${projectId}_module_report_${Date.now()}.pdf`);
    const pdfBytes = await pdfDoc.save();
    fs.writeFileSync(outputPath, pdfBytes);
    
    return outputPath;
};

// --- ENDPOINTS DE REPORTES ---

/**
 * 1. GET /reports/project-progress/:project_id
 * Genera Reporte de Progreso de un Proyecto (JSON).
 */
reports.get('/project-progress/:project_id', async (req, res) => {
    const { project_id } = req.params;
    let conn;
    let db;
    try {
        conn = await pool.connect();
        const projectResult = await conn.query(`
            SELECT name, start, "end" FROM projects WHERE id = $1;
        `, [project_id]);

        if (projectResult.rows.length === 0)
            return res.status(404).json({ message: 'Project not found' });

        const project = projectResult.rows[0];
        
        db = openDB('./projects/' + project_id);
        const tasks = db.prepare(`
            SELECT status, estimated_hours, created_at FROM tasks;
        `).all();
        
        const totalTasks = tasks.length;
        const completedTasks = tasks.filter(t => t.status === 'completed').length;
        const pendingTasks = totalTasks - completedTasks;
        
        const progressPercentage = totalTasks > 0 ? (completedTasks / totalTasks) * 100 : 0;
        
        return res.status(200).json({
            project_name: project.name,
            start_date: project.start,
            end_date: project.end,
            metrics: {
                total_tasks: totalTasks,
                completed_tasks: completedTasks,
                pending_tasks: pendingTasks,
                progress_percentage: progressPercentage.toFixed(2) + '%'
            },
            message: "Report generated successfully"
        });

    } catch (error) {
        return errorHandler(error, res);
    } finally {
        if (conn) conn.release();
        if (db) db.close();
    }
});

/**
 * 2. GET /reports/dashboard/summary
 * Obtiene un resumen de métricas clave para el Dashboard principal del usuario (JSON).
 */
reports.get('/dashboard/summary', async (req, res) => {
    const user_id = req.tokenData.user_id;
    
    let conn;
    let tasksDueSoonCount = 0;
    let tasksOverdueCount = 0;
    
    const { todayISO, sevenDaysISO } = getDueDates();

    try {
        conn = await pool.connect();
        
        // 1. Obtener proyectos activos del usuario (PostgreSQL)
        const projectsQuery = `
            SELECT p.id, p.sqlite_file
            FROM projects p
            JOIN project_members pm ON p.id = pm.project_id
            WHERE pm.user_id = $1;
        `;
        const projectsResult = await conn.query(projectsQuery, [user_id]);
        const userProjects = projectsResult.rows;

        // 2. ITERAR y agregar métricas de tareas (SQLite)
        for (const project of userProjects) {
            let db;
            try {
                db = openDB(`./projects/${project.id}`); 
                
                const tasks = db.prepare(`
                    SELECT due_date
                    FROM tasks 
                    WHERE user_ids = ? AND status != 'completed';
                `).all(user_id);

                for (const task of tasks) {
                    const dueDate = task.due_date;
                    if (!dueDate) continue; 

                    const normalizedDueDate = dueDate.split('T')[0]; 

                    if (normalizedDueDate < todayISO) {
                        tasksOverdueCount++;
                    } else if (normalizedDueDate <= sevenDaysISO) {
                        tasksDueSoonCount++;
                    }
                }
            } catch (dbError) {
                console.error(`Error procesando proyecto ${project.id}: ${dbError.message}`);
            } finally {
                if (db) db.close();
            }
        }
        
        // 3. CÁLCULOS RESTANTES (Proyectos totales y cercanos a fecha límite)
        const projectCountQuery = `
            SELECT COUNT(DISTINCT pm.project_id) AS total_projects
            FROM project_members pm
            WHERE pm.user_id = $1;
        `;
        const projectCountResult = await conn.query(projectCountQuery, [user_id]);
        const totalProjects = parseInt(projectCountResult.rows[0].total_projects, 10);

        const nearDeadlineProjectsQuery = `
            SELECT id, name, "end"
            FROM projects
            JOIN project_members pm ON id = pm.project_id
            WHERE pm.user_id = $1 AND status != 'completed' AND "end" < NOW() + interval '7 day'
            ORDER BY "end" ASC
            LIMIT 3; 
        `;
        const nearDeadlineResult = await conn.query(nearDeadlineProjectsQuery, [user_id]);

        return res.status(200).json({
            summary: {
                total_projects_assigned: totalProjects,
                tasks_due_soon: tasksDueSoonCount,
                tasks_overdue: tasksOverdueCount,
                projects_near_deadline_count: nearDeadlineResult.rows.length,
            },
            projects_near_deadline: nearDeadlineResult.rows
        });

    } catch (error) {
        return errorHandler(error, res);
    } finally {
        if (conn) conn.release();
    }
});

/**
 * 3. GET /reports/team-productivity/:user_id
 * Genera Reporte de Productividad consolidado para un usuario (JSON).
 */
reports.get('/team-productivity/:user_id', checkReportAuth, async (req, res) => {
    const reportUser = parseInt(req.params.user_id, 10);
    
    let conn;
    let totalTasks = 0;
    let completedTasks = 0;
    let totalEstimatedHours = 0;

    try {
        conn = await pool.connect();
        
        // 1. Obtener la lista de proyectos del usuario (PostgreSQL)
        const projectsQuery = `
            SELECT project_id
            FROM project_members 
            WHERE user_id = $1;
        `;
        const projectsResult = await conn.query(projectsQuery, [reportUser]);
        const projectIds = projectsResult.rows.map(row => row.project_id);

        if (projectIds.length === 0) {
            return res.status(200).json({ 
                user_id: reportUser,
                message: 'User is not assigned to any project.',
                metrics: {
                    total_tasks: 0, completed_tasks: 0, completion_rate: '0.00%', total_estimated_hours: 0,
                }
            });
        }
        
        // 2. Iterar sobre cada proyecto para agregar las métricas de tareas (SQLite)
        for (const projectId of projectIds) {
            let db;
            try {
                db = openDB(`./projects/${projectId}`);
                
                const tasks = db.prepare(`
                    SELECT status, estimated_hours
                    FROM tasks 
                    WHERE user_ids = ?;
                `).all(reportUser);

                totalTasks += tasks.length;
                
                tasks.forEach(task => {
                    const estimatedHours = parseFloat(task.estimated_hours) || 0;
                    totalEstimatedHours += estimatedHours;
                    
                    if (task.status === 'completed') {
                        completedTasks += 1;
                    }
                });

            } catch (dbError) {
                console.error(`Error processing project ${projectId}: ${dbError.message}`);
            } finally {
                if (db) db.close();
            }
        }

        // 3. Consolidar métricas
        const completionRate = totalTasks > 0 ? (completedTasks / totalTasks) * 100 : 0;
        
        return res.status(200).json({
            user_id: reportUser,
            metrics: {
                total_tasks: totalTasks,
                completed_tasks: completedTasks,
                pending_tasks: totalTasks - completedTasks,
                completion_rate: completionRate.toFixed(2) + '%',
                total_estimated_hours: totalEstimatedHours.toFixed(2),
            },
            message: 'Team productivity report generated successfully'
        });

    } catch (error) {
        return errorHandler(error, res);
    } finally {
        if (conn) conn.release();
    }
});

/**
 * 4. GET /reports/module-progress/:project_id
 * Retorna el reporte de progreso por módulo en formato JSON.
 */
reports.get('/module-progress/:project_id', async (req, res) => {
    const { project_id } = req.params;
    try {
        const reportData = getModuleProgressReportData(project_id);
        
        // Formato de salida solicitado
        const modulesSummary = Object.keys(reportData.modules).map(name => 
            `${name}: ${reportData.modules[name].percentage}`
        ).join(', ');
        
        const tasksByModule = reportData.modules;
        
        return res.status(200).json({
            modules: `${reportData.modulesCount} {${modulesSummary}}`,
            tasks_by_module: tasksByModule,
            total_tareas: {
                total: reportData.totalTasks.total,
                completed: reportData.totalTasks.completed
            }
        });
    } catch (error) {
        return errorHandler(error, res); 
    }
});

/**
 * 5. GET /reports/module-progress-pdf/:project_id
 * Genera el reporte de progreso por módulo en formato PDF y lo retorna.
 */
reports.get('/module-progress-pdf/:project_id', async (req, res) => {
    const { project_id } = req.params;
    let conn;

    try {
        // 1. Obtener Nombre del Proyecto (PostgreSQL)
        conn = await pool.connect();
        const projectResult = await conn.query('SELECT name FROM projects WHERE id = $1;', [project_id]);
        
        if (projectResult.rows.length === 0) {
            return res.status(404).json({ message: 'Project not found' });
        }
        const projectName = projectResult.rows[0].name;
        
        // 2. Agregar Datos y Generar PDF
        const reportData = getModuleProgressReportData(project_id);
        const pdfPath = await generateModuleReportPdf(reportData, projectName, project_id);
        
        // 3. Enviar el archivo
        return res.sendFile(pdfPath, err => {
             if (err) {
                 console.error("Error al enviar PDF:", err);
                 res.status(500).send({ message: "Fallo al enviar el reporte generado." });
             }
             // Limpiar el archivo temporal
             try {
                 fs.unlinkSync(pdfPath);
             } catch(e) {
                 console.warn("Fallo al eliminar el archivo de reporte temporal:", e.message);
             }
        });

    } catch (error) {
        if (conn) conn.release();
        return errorHandler(error, res); 
    } finally {
        if (conn) conn.release();
    }
});

export default reports;
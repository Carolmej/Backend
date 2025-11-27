//Dependencies
import express from 'express';
import pool from '../config/DBManager.js';
import fs from 'fs';
import crypto from 'crypto';
import { openDB, createTables } from '../config/SQLiteManager.js';
import errorHandler from '../middleware/errorHandler.js';
import adminAuth from '../middleware/adminAuth.js';
const project = express.Router();


//Endpoints
//---------------------------------------------------------------------------------------------------------------------------
//Enpoint to create a new project
project.post('/', adminAuth, async (req, res) => {
    const { name, description, client_id, team_leader_id, start, end } = req.body;
    if (name && description && client_id && team_leader_id && start && end) {
        let conn, liteConn, project_id; //conn bd postgress y connlite bd sqlite
        try {
            project_id = crypto.randomBytes(4).toString('hex'); // create random id of 8 characters
            conn = await pool.connect();
            conn.query('BEGIN;');
            await conn.query('INSERT INTO projects VALUES ($1, $2, $3, $4, $5, $6, $7, $8);', [project_id, name, description, client_id, team_leader_id, start, end, `${project_id}.db`]);

            /**
             * @note this line is commented because there is not table 'project_members'
             */

            // await conn.query('INSERT INTO project_members (project_id, user_id) VALUES ($1, $2);', [project_id, team_leader_id]);
            liteConn = openDB('./projects/' + project_id);
            createTables(liteConn); // creates the tables with no data because the project is just initilized
            conn.query('COMMIT;');
            return res.status(201).json({ project_id: project_id });
        } catch (error) {
            conn.query('ROLLBACK;');
            if (liteConn) liteConn.close();
            if (fs.existsSync(`./projects/${project_id}.db`)) fs.unlinkSync(`./projects/${project_id}.db`);
            errorHandler(error, res);
        } finally {
            if (liteConn) liteConn.close();
            if (conn) conn.release();
        }
    } else return res.status(400).json({ message: 'Incomplete data' });
});



// auth Middleware is not needed because it was added in the index file
project.get('/', async (req, res, next) => {

    const { role } = req.tokenData;

    if (!['1', '0'].includes(role)) {
        return res.status(403).json({ message: 'forbidden' })
    }

    const query = `SELECT id, name, description, start, "end" FROM projects;`;
    const projects = await executeQueryOrFetchMultipleDataPostgreSQL(query);

    return res.status(200).json(projects);


})

// endpoint to get all members of a project
project.get('/getMembers', async (req, res, next) => {

    let liteConn;

    const { project_id: projectId } = req.headers;


    if (!projectId) return res.status(400).json({ message: 'the project id is needed in headers' })

    try {
        liteConn = openDB('./projects/' + projectId);


        const membersIdFromAnyTeamOfTheCurrentProject = liteConn.prepare('SELECT * FROM teammembers').all().map(member => {
            return { userId: member.user_id }
        });


        let members = []

        for (const e of membersIdFromAnyTeamOfTheCurrentProject) {
            const query = "SELECT id, name FROM users WHERE id = $1";
            const member = (await executeQueryOrFetchMultipleDataPostgreSQL(query, [e.userId]))[0];
            members.push(member);
        }


        members = members.filter((item, index, self) =>  // this code removes duplicates from the array of members
            index === self.findIndex((t) => (
                t.id === item.id
            ))
        )

        res.status(200).json({ members })
    } catch (e) {
        console.log('error en project.js funcion /getMembers')
        res.status(500).json({ message: 'error in backend' })
    } finally {
        if (liteConn) liteConn.close();
    }

})

// endpoint to get all teams of a project
project.get('/getTeams', async (req, res, next) => {

    let liteConn;

    const { project_id: projectId } = req.headers;

    if (!projectId) return res.status(400).json({ message: 'the project id is needed in headers' })

    try {
        liteConn = openDB('./projects/' + projectId);
        const teams = liteConn.prepare('SELECT * FROM teams').all();
        res.status(200).json({ teams });
    } catch (e) {
        console.log('error en project.js funcion /getTeams')
        res.status(500).json({ message: 'error in backend' })
    } finally {
        if (liteConn) liteConn.close();
    }
})


// endpoint to create a new team in a project
project.post('/createTeam', async (req, res, next) => {


    if (!req.body) return res.status(400).json({ message: 'you must provide all the fields requested' });
    const { project_id: projectId, name, description } = req.body;

    if (!projectId || !name || !description) {
        return res.status(400).json({ message: 'you must provide all the fields requested' });
    }

    const rowArray = await executeQueryOrFetchMultipleDataPostgreSQL('SELECT * FROM projects WHERE id = $1', [projectId]);
    const projectData = rowArray[0];

    if (!projectData) return res.status(400).json({ message: 'the project id provided does not exist' }); // if doesn't exist exit


    // if exists continue with all the above code

    const sqliteDatabasePathWithDoubleDbExtension = './projects/' + projectData.database_path;
    const sqliteDatabasePath = sqliteDatabasePathWithDoubleDbExtension.replace('.db', ''); // removing the extra .db added before

    let liteConn; //  variable with no value yet

    try {


        liteConn = openDB(sqliteDatabasePath); // the object returned represents the connection to the sqlite database of the project



        let idTeam = liteConn.prepare('INSERT INTO teams (name, description) VALUES (?, ?)').run([name, description]).lastInsertRowid;


        // after created the team, we need to add the team leader as member of the team too
        const team_leader_id = projectData.team_leader_id;

        liteConn.prepare('INSERT INTO teammembers (team_id, user_id) VALUES (?, ?)').run([idTeam, team_leader_id]);






        return res.status(201).json({ message: 'team created succesfully' });
    } catch (e) {
        console.log('error en project.js funcion /createTeam', e)
        return res.status(500).json({ message: 'error in backend' })
    } finally { // the finally block always runs no matter if there was an error or not
        if (liteConn) liteConn.close();
    }

})



// endpoint to add a member to a team in a project
project.post('/addMember', async (req, res, next) => {


    // validate rol

    const { role } = req.tokenData;

    if (!['1', '0'].includes(role)) { // only 1 and 0 roles are allowed to add members
        return res.status(403).json({ message: 'forbidden' })
    }

    if (!req.body) return res.status(400).json({ message: 'you must provide all the fields requested' });

    const { project_id, user_id, team_id } = req.body; // teamId is not in Alan's doc but it's needed to know to which team add the member

    if (!project_id || !user_id || !team_id) {
        return res.status(400).json({ message: 'you must provide all the fields requested' });
    }


    // validate that project exists

    const rowArray = await executeQueryOrFetchMultipleDataPostgreSQL('SELECT * FROM projects WHERE id = $1', [project_id]);
    const projectData = rowArray[0];
    if (!projectData) return res.status(400).json({ message: 'the project id provided does not exist' }); // if doesn't exist exit

    // validate that user exists

    const userRowArray = await executeQueryOrFetchMultipleDataPostgreSQL('SELECT * FROM users WHERE id = $1', [user_id]);
    const userData = userRowArray[0];
    if (!userData) return res.status(400).json({ message: 'the user id provided does not exist' }); // if doesn't exist exit


    // valite if team exists in the project
    let liteConn; //  variable with no value yet

    try {
        const sqliteDatabasePathWithDoubleDbExtension = './projects/' + projectData.database_path;
        const sqliteDatabasePath = sqliteDatabasePathWithDoubleDbExtension.replace('.db', ''); // removing the extra .db added before
        liteConn = openDB(sqliteDatabasePath); // the object returned represents the connection to the sqlite database of the project

        const teamRow = liteConn.prepare('SELECT * FROM teams WHERE id = ?').get([team_id]);
        if (!teamRow) return res.status(400).json({ message: 'the team id provided does not exist in the project' }); // if doesn't exist exit


        // if all validations are passed, continue to add the member to the team

        liteConn.prepare('INSERT INTO teammembers (team_id, user_id) VALUES (?, ?)').run([team_id, user_id]);
        return res.status(201).json({ message: 'member added succesfully to the team' });
    } catch (e) {
        console.log('error en project.js funcion /addMember', e)
        return res.status(500).json({ message: 'error in backend' })
    } finally { // the finally block always runs no matter if there was an error or not
        if (liteConn) liteConn.close();
    }


})



// endpoint to remove a member from a team in a project
project.post('/removeMember', async (req, res, next) => { // this should be a delete method but Alan's doc says post 🫡

    const { role } = req.tokenData;
    if (!['1', '0'].includes(role)) { // only 1 and 0 roles are allowed to remove members
        return res.status(403).json({ message: 'forbidden' })
    }


    if (!req.body) return res.status(400).json({ message: 'you must provide all the fields requested' });
    const { project_id, user_id, team_id } = req.body; // teamId is not in Alan's doc but it's needed to know from which team remove the member

    if (!project_id || !user_id || !team_id) {
        return res.status(400).json({ message: 'you must provide all the fields requested' });
    }


    // validate that project exists
    const rowArray = await executeQueryOrFetchMultipleDataPostgreSQL('SELECT * FROM projects WHERE id = $1', [project_id]);
    const projectData = rowArray[0];
    if (!projectData) return res.status(400).json({ message: 'the project id provided does not exist' }); // if doesn't exist exit

    // validate that user exists
    const userRowArray = await executeQueryOrFetchMultipleDataPostgreSQL('SELECT * FROM users WHERE id = $1', [user_id]);
    const userData = userRowArray[0];
    if (!userData) return res.status(400).json({ message: 'the user id provided does not exist' }); // if doesn't exist exit


    // valite if team exists in the project
    let liteConn; //  variable with no value yet

    try {
        const sqliteDatabasePathWithDoubleDbExtension = './projects/' + projectData.database_path;
        const sqliteDatabasePath = sqliteDatabasePathWithDoubleDbExtension.replace('.db', ''); // removing the extra .db added before
        liteConn = openDB(sqliteDatabasePath); // the object returned represents the connection to the sqlite database of the project
        const teamRow = liteConn.prepare('SELECT * FROM teams WHERE id = ?').get([team_id]);
        if (!teamRow) return res.status(400).json({ message: 'the team id provided does not exist in the project' }); // if doesn't exist exit
        // if all validations are passed, continue to remove the member from the team
        liteConn.prepare('DELETE FROM teammembers WHERE team_id = ? AND user_id = ?').run([team_id, user_id]);
        return res.status(200).json({ message: 'member removed succesfully from the team' });
    } catch (e) {
        console.log('error en project.js funcion /removeMember', e)
        return res.status(500).json({ message: 'error in backend' })
    } finally { // the finally block always runs no matter if there was an error or not
        if (liteConn) liteConn.close();
    }



});



// endpoint to remove a team from a project
project.post('/removeTeam', async (req, res, next) => { // this should be a delete method but Alan's doc says post 🫡
    const { role } = req.tokenData;
    if (!['1', '0'].includes(role)) { // only 1 and 0 roles are allowed to remove teams
        return res.status(403).json({ message: 'forbidden' })
    }

    if (!req.body) return res.status(400).json({ message: 'you must provide all the fields requested' });
    const { project_id, team_id } = req.body;


    if (!project_id || !team_id) {
        return res.status(400).json({ message: 'you must provide all the fields requested' });
    }

    // validate that project exists
    const rowArray = await executeQueryOrFetchMultipleDataPostgreSQL('SELECT * FROM projects WHERE id = $1', [project_id]);
    const projectData = rowArray[0];
    if (!projectData) return res.status(400).json({ message: 'the project id provided does not exist' }); // if doesn't exist exit


    // valite if team exists in the project
    let liteConn; //  variable with no value yet
    try {
        const sqliteDatabasePathWithDoubleDbExtension = './projects/' + projectData.database_path;
        const sqliteDatabasePath = sqliteDatabasePathWithDoubleDbExtension.replace('.db', ''); // removing the extra .db added before
        liteConn = openDB(sqliteDatabasePath);

        const teamRow = liteConn.prepare('SELECT * FROM teams WHERE id = ?').get([team_id]);
        if (!teamRow) return res.status(400).json({ message: 'the team id provided does not exist in the project' }); // if doesn't exist exit
        // if all validations are passed, continue to remove the team
        liteConn.prepare('DELETE FROM teams WHERE id = ?').run([team_id]);
        liteConn.prepare('DELETE FROM teammembers WHERE team_id = ?').run([team_id]);
        return res.status(200).json({ message: 'team removed succesfully from the project' });

    } catch (e) {
        console.log('error en project.js funcion /removeTeam', e)
        return res.status(500).json({ message: 'error in backend' })
    } finally { // the finally block always runs no matter if there was an error or not
        if (liteConn) liteConn.close();
    }


});



// endpoint to update a team in a project
project.post('/updateTeam', async (req, res, next) => {

    const { role } = req.tokenData;

    if (!['1', '0'].includes(role)) { // only 1 and 0 roles are allowed to update teams
        return res.status(403).json({ message: 'forbidden' })
    }

    if (!req.body) return res.status(400).json({ message: 'you must provide all the fields requested.' });
    const { project_id, team_id, name, description } = req.body;


    if (!project_id || !team_id || !name || !description) {
        return res.status(400).json({ message: 'you must provide all the fields requested..' });
    }

    // validate that project exists
    const rowArray = await executeQueryOrFetchMultipleDataPostgreSQL('SELECT * FROM projects WHERE id = $1', [project_id]);
    const projectData = rowArray[0];
    if (!projectData) return res.status(400).json({ message: 'the project id provided does not exist' }); // if doesn't exist exit

    // valite if team exists in the project
    let liteConn; //  variable with no value yet

    try {
        const sqliteDatabasePathWithDoubleDbExtension = './projects/' + projectData.database_path;
        const sqliteDatabasePath = sqliteDatabasePathWithDoubleDbExtension.replace('.db', ''); // removing the extra .db added before
        liteConn = openDB(sqliteDatabasePath); // the object returned represents the connection to the sqlite database of the project

        const teamRow = liteConn.prepare('SELECT * FROM teams WHERE id = ?').get([team_id]);
        if (!teamRow) return res.status(400).json({ message: 'the team id provided does not exist in the project' }); // if doesn't exist exit

        // if all validations are passed, continue to update the team
        liteConn.prepare('UPDATE teams SET name = ?, description = ? WHERE id = ?').run([name, description, team_id]);
        return res.status(200).json({ message: 'team updated succesfully in the project' });

    } catch (e) {
        console.log('error en project.js funcion /updateTeam', e)
        return res.status(500).json({ message: 'error in backend' })
    } finally {
        if (liteConn) liteConn.close();
    }

});




// TASKS and MODULES endpoints
project.get('/getModules', async (req, res, next) => {

    const { project_id: projectId } = req.headers;

    if (!projectId) return res.status(400).json({ message: 'the project id is needed in headers' })


    // validate that project exists
    const rowArray = await executeQueryOrFetchMultipleDataPostgreSQL('SELECT * FROM projects WHERE id = $1', [projectId]);
    const projectData = rowArray[0];
    if (!projectData) return res.status(400).json({ message: 'the project id provided does not exist' }); // if doesn't exist exit

    let liteConn;
    try {
        liteConn = openDB('./projects/' + projectData.database_path.replace('.db', '')); // in the DB the field has .db but the openDB function adds it again
        const modules = liteConn.prepare('SELECT * FROM modules').all();
        res.status(200).json({ modules });
    } catch (e) {
        console.log('error en project.js funcion /getModules', e)
        res.status(500).json({ message: 'error in backend' })
    } finally {
        if (liteConn) liteConn.close();
    }

});



// endpoint to create a new module in a project
project.post('/createModule', async (req, res, next) => {

    const { role } = req.tokenData;


    if (!['1', '0'].includes(role)) { // only 1 and 0 roles are allowed to create modules
        return res.status(403).json({ message: 'forbidden' })
    }

    if (!req.body) return res.status(400).json({ message: 'you must provide all the fields requested' });


    /**
     * modules table fields of sqlite database:
     * 
     * "id" integer primary key autoincrement not null,
     * "title" text not null,
     * "description" text,
     * "priority" text,
     * "status" text,
     * "created_at" timestamp default current_date,
     * "updated_at" timestamp default current_date,
     * "team_ids" integer
     * 
     */
    const { project_id, title, description, priority, status, team_ids } = req.body;


    if (!project_id || !title || !description || !priority || !status || !team_ids) {
        return res.status(400).json({ message: 'you must provide all the fields requested' });
    }

    // validate that project exists
    const rowArray = await executeQueryOrFetchMultipleDataPostgreSQL('SELECT * FROM projects WHERE id = $1', [project_id]);
    const projectData = rowArray[0];
    if (!projectData) return res.status(400).json({ message: 'the project id provided does not exist' }); // if doesn't exist exit

    let liteConn; //  variable with no value yet
    try {
        
        const sqliteDatabasePathWithDoubleDbExtension = './projects/' + projectData.database_path;
        const sqliteDatabasePath = sqliteDatabasePathWithDoubleDbExtension.replace('.db', ''); // removing the extra .db added before
        liteConn = openDB(sqliteDatabasePath); // the object returned represents the connection to the sqlite database of the project

        liteConn.prepare('INSERT INTO modules (title, description, priority, status, created_at, updated_at, team_ids) VALUES (?, ?, ?, ?, ?, ?, ?)').run([title, description, priority, status, new Date().toISOString(), new Date().toISOString(), team_ids]);

        return res.status(201).json({ message: 'module created succesfully in the project' });
    } catch (e) {

        console.log('error en project.js funcion /createModule', e)
        return res.status(500).json({ message: 'error in backend' })

    } finally {
        if (liteConn) liteConn.close();
    }


});



// endpoint to update a module in a project
project.post('/updateModule', async (req, res, next) => {
    

    const { role } = req.tokenData;
    if (!['1', '0'].includes(role)) { // only 1 and 0 roles are allowed to update modules
        return res.status(403).json({ message: 'forbidden' })
    }


    if (!req.body) return res.status(400).json({ message: 'you must provide all the fields requested' });

    const { project_id, module_id, title, description, priority, status, team_ids } = req.body;
    if (!project_id || !module_id || !title || !description || !priority || !status || !team_ids) {
        return res.status(400).json({ message: 'you must provide all the fields requested' });
    }

    // validate that project exists
    const rowArray = await executeQueryOrFetchMultipleDataPostgreSQL('SELECT * FROM projects WHERE id = $1', [project_id]);
    const projectData = rowArray[0];
    if (!projectData) return res.status(400).json({ message: 'the project id provided does not exist' }); // if doesn't exist exit


    let liteConn; //  variable with no value yet

    try {
        const sqliteDatabasePathWithDoubleDbExtension = './projects/' + projectData.database_path;
        const sqliteDatabasePath = sqliteDatabasePathWithDoubleDbExtension.replace('.db', ''); // removing the extra .db added before
        liteConn = openDB(sqliteDatabasePath); // the object returned represents the connection to the sqlite database of the project
        const moduleRow = liteConn.prepare('SELECT * FROM modules WHERE id = ?').get([module_id]);
        if (!moduleRow) return res.status(400).json({ message: 'the module id provided does not exist in the project' }); // if doesn't exist exit

        // if all validations are passed, continue to update the module
        liteConn.prepare('UPDATE modules SET title = ?, description = ?, priority = ?, status = ?, updated_at = ?, team_ids = ? WHERE id = ?').run([title, description, priority, status, new Date().toISOString(), team_ids, module_id]);
        return res.status(200).json({ message: 'module updated succesfully in the project' });
    } catch (e) {
        console.log('error en project.js funcion /updateModule', e)
        return res.status(500).json({ message: 'error in backend' })
    } finally {
        if (liteConn) liteConn.close();
    }


});



// endpoint to delete a module from a project
project.post('/deleteModule', async (req, res, next) => {

    const { role } = req.tokenData;

    if (!['1', '0'].includes(role)) { // only 1 and 0 roles are allowed to delete modules
        return res.status(403).json({ message: 'forbidden' })
    }

    if (!req.body) return res.status(400).json({ message: 'you must provide all the fields requested' });

    const { project_id, module_id } = req.body;
    if (!project_id || !module_id) {
        return res.status(400).json({ message: 'you must provide all the fields requested' });
    }

    // validate that project exists
    const rowArray = await executeQueryOrFetchMultipleDataPostgreSQL('SELECT * FROM projects WHERE id = $1', [project_id]);
    const projectData = rowArray[0];
    if (!projectData) return res.status(400).json({ message: 'the project id provided does not exist' }); // if doesn't exist exit


    let liteConn; //  variable with no value yet

    try {
        const sqliteDatabasePathWithDoubleDbExtension = './projects/' + projectData.database_path;
        const sqliteDatabasePath = sqliteDatabasePathWithDoubleDbExtension.replace('.db', '');

        liteConn = openDB(sqliteDatabasePath); // the object returned represents the connection to the sqlite database of the project
        const moduleRow = liteConn.prepare('SELECT * FROM modules WHERE id = ?').get([module_id]);
        if (!moduleRow) return res.status(400).json({ message: 'the module id provided does not exist in the project' }); // if doesn't exist exit

        // if all validations are passed, continue to delete the module
        liteConn.prepare('DELETE FROM modules WHERE id = ?').run([module_id]);



        // if a module is deleted, all its tasks must be deleted too
        liteConn.prepare('DELETE FROM tasks WHERE module_id = ?').run([module_id]);

        return res.status(200).json({ message: 'module deleted succesfully from the project' });

    }catch (e) {
        console.log('error en project.js funcion /deleteModule', e)
        return res.status(500).json({ message: 'error in backend' })
    } finally {
        if (liteConn) liteConn.close();
    }

});


/**
 * TASKS table fields of sqlite database:
 * 
 *  "id" integer primary key autoincrement not null,
 *  "module_id" integer,
 *  "title" text not null,
 *  "description" text,
 *  "priority" text,
 *  "status" text,
 *  "created_at" timestamp default current_date,
 *  "updated_at" timestamp default current_date,
 *  "user_ids" integer
 */

// endpoint to get all tasks of a project
project.get('/getTasks', async (req, res, next) => {
    const { project_id: projectId } = req.headers;

    if (!projectId) return res.status(400).json({ message: 'the project id is needed in headers' })

    // validate that project exists
    const rowArray = await executeQueryOrFetchMultipleDataPostgreSQL('SELECT * FROM projects WHERE id = $1', [projectId]);
    const projectData = rowArray[0];
    if (!projectData) return res.status(400).json({ message: 'the project id provided does not exist' }); // if doesn't exist exit

    let liteConn;
    try {
        liteConn = openDB('./projects/' + projectData.database_path.replace('.db', '')); // in the DB the field has .db but the openDB function adds it again
        const tasks = liteConn.prepare('SELECT * FROM tasks').all();
        res.status(200).json({ tasks });
    } catch (e) {
        console.log('error en project.js funcion /getTasks', e)
        res.status(500).json({ message: 'error in backend' })
    }
});



// endpoint to create a new task in a project
project.post('/createTask', async (req, res, next) => {

    const  { project_id, module_id, title, description, priority, status, user_ids } = req.body;

    if (!project_id || !module_id || !title || !description || !priority || !status || !user_ids) {
        return res.status(400).json({ message: 'you must provide all the fields requested' });
    }


    // validate that project exists
    const rowArray = await executeQueryOrFetchMultipleDataPostgreSQL('SELECT * FROM projects WHERE id = $1', [project_id]);
    const projectData = rowArray[0];
    if (!projectData) return res.status(400).json({ message: 'the project id provided does not exist' }); // if doesn't exist exit

    let liteConn; //  variable with no value yet
    try {
        const sqliteDatabasePathWithDoubleDbExtension = './projects/' + projectData.database_path;
        const sqliteDatabasePath = sqliteDatabasePathWithDoubleDbExtension.replace('.db', ''); // removing the extra .db added before
        liteConn = openDB(sqliteDatabasePath); // the object returned represents the connection to the sqlite database of the project

        liteConn.prepare('INSERT INTO tasks (module_id, title, description, priority, status, created_at, updated_at, user_ids) VALUES (?, ?, ?, ?, ?, ?, ?, ?)').run([module_id, title, description, priority, status, new Date().toISOString(), new Date().toISOString(), user_ids]);
        return res.status(201).json({ message: 'task created succesfully in the project' });
    } catch (e) {

        console.log('error en project.js funcion /createTask', e)
        return res.status(500).json({ message: 'error in backend' })
    } finally {
        if (liteConn) liteConn.close();
    } 
});



// endpoint to update a task in a project
project.post('/updateTask', async (req, res, next) => {

    const { project_id, task_id, module_id, title, description, priority, status, user_ids } = req.body;

    if (!project_id || !task_id || !module_id || !title || !description || !priority || !status || !user_ids) {
        return res.status(400).json({ message: 'you must provide all the fields requested' });
    }
    // validate that project exists
    const rowArray = await executeQueryOrFetchMultipleDataPostgreSQL('SELECT * FROM projects WHERE id = $1', [project_id]);
    const projectData = rowArray[0];
    if (!projectData) return res.status(400).json({ message: 'the project id provided does not exist' }); // if doesn't exist exit
    let liteConn; //  variable with no value yet

    try {
        const sqliteDatabasePathWithDoubleDbExtension = './projects/' + projectData.database_path;
        const sqliteDatabasePath = sqliteDatabasePathWithDoubleDbExtension.replace('.db', ''); // removing the extra .db added before
        liteConn = openDB(sqliteDatabasePath); // the object returned represents the connection to the sqlite database of the project
        const taskRow = liteConn.prepare('SELECT * FROM tasks WHERE id = ?').get([task_id]);
        if (!taskRow) return res.status(400).json({ message: 'the task id provided does not exist in the project' }); // if doesn't exist exit
        // if all validations are passed, continue to update the task
        liteConn.prepare('UPDATE tasks SET module_id = ?, title = ?, description = ?, priority = ?, status = ?, updated_at = ?, user_ids = ? WHERE id = ?').run([module_id, title, description, priority, status, new Date().toISOString(), user_ids, task_id]);
        return res.status(200).json({ message: 'task updated' });
    } catch (e) {
        console.log('error en project.js funcion /updateTask', e)
        return res.status(500).json({ message: 'error in backend' })
    }
});



// endpoint to delete a task from a project
project.post('/removeTask', async (req, res, next) => {

    const { project_id, task_id, module_id } = req.body;

    if (!project_id || !task_id || !module_id) {
        return res.status(400).json({ message: 'you must provide all the fields requested' });
    }

    // validate that project exists
    const rowArray = await executeQueryOrFetchMultipleDataPostgreSQL('SELECT * FROM projects WHERE id = $1', [project_id]);
    const projectData = rowArray[0];
    if (!projectData) return res.status(400).json({ message: 'the project id provided does not exist' }); // if doesn't exist exit

    // valite if task exists in the project and module
    let liteConn; //  variable with no value yet
    try {
        const sqliteDatabasePathWithDoubleDbExtension = './projects/' + projectData.database_path;
        const sqliteDatabasePath = sqliteDatabasePathWithDoubleDbExtension.replace('.db', '');
        liteConn = openDB(sqliteDatabasePath); // the object returned represents the connection to the sqlite database of the project

        const taskRow = liteConn.prepare('SELECT * FROM tasks WHERE id = ? AND module_id = ?').get([task_id, module_id]);
        if (!taskRow) return res.status(400).json({ message: 'the task id provided does not exist in the project and module' }); // if doesn't exist exit
        
        // validate if the module exists in the project
        const moduleRow = liteConn.prepare('SELECT * FROM modules WHERE id = ?').get([module_id]);
        if (!moduleRow) return res.status(400).json({ message: 'the module id provided does not exist in the project' }); // if doesn't exist exit
        // if all validations are passed, continue to delete the task
        liteConn.prepare('DELETE FROM tasks WHERE id = ? AND module_id = ?').run([task_id, module_id]);
        return res.status(200).json({ message: 'task deleted succesfully from the project' });
    } catch (e) {
        console.log('error en project.js funcion /removeTask', e)
        return res.status(500).json({ message: 'error in backend' })
    } finally {
        if (liteConn) liteConn.close();
    }



});



//////////// FUNCTIONS TO AVOID REPEATING CODE  //////////////////////

/**
 * 
 * @param {string} query 
 * @param {Array} values
 * @returns {Promise<[]>}
 */
const executeQueryOrFetchMultipleDataPostgreSQL = async (query, values) => {
    let conn;

    try {

        conn = await pool.connect();
        const result = await conn.query(query, values);

        const rows = result.rows;
        return rows;

    } catch (e) {
        console.log(e)
    } finally {
        if (conn) conn.release();
    }
}












//---------------------------------------------------------------------------------------------------------------------------
export default project;
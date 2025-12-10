// Dependencies
import express from 'express';
import morgan from 'morgan';
import cors from 'cors';

// Routes
import project from './routes/project.js';
import user from './routes/user.js';
import tasks from './routes/tasks.js';
import members from './routes/members.js';
import teams from './routes/teams.js';
import reports from './routes/reports.js';
import modules from './routes/Sprints.js';
import notifications from './routes/notifications.js';


// Middleware
import auth from './middleware/tokenAuth.js';

// App setup
const app = express();
app.use(cors());
app.use(morgan('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));


//ENDPOINTS PÚBLICOS (sin autenticación)
app.post('/user', user);  //dejamos solo la ruta directa de login

//ENDPOINTS PRIVADOS (con autenticación)
/*app.use('/user', auth, user.stack.filter(layer => layer.route.path !== '/login').reduce((router, layer) => {
    router.use(layer.route.path, layer.route.stack[0].handle);
    return router;
}, express.Router()));*/ //el resto de rutas de user con auth
app.use('/user',user)
app.use('/project', auth, project);
app.use('/tasks', auth, tasks);
app.use('/members', auth, members);
app.use('/teams', auth, teams);
app.use('/reports', auth, reports);
app.use('/modules', auth, modules);
app.use('/notifications', auth, notifications); 
//app.use('/user-details', auth, user); // detalles y perfil del usuario



// Utilities
app.get('/', (req, res) => {
    res.send('Hi there! Im alive!');
});

app.use((req, res, next) => {
    res.status(404).send({ message: 'Not found' });
});

// Start server
app.listen(process.env.PORT || 3200, () => {
    console.log('Server is running on port ' + (process.env.PORT || 3200));
});

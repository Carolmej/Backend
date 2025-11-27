// Dependencies
import express from 'express';
import morgan from 'morgan';
import cors from 'cors';

// Routes
import project from './routes/project.js';
import user from './routes/user.js';
import tasks from './routes/tasks.js';
import members from './routes/members.js';

// Middleware
import auth from './middleware/tokenAuth.js';

// App setup
const app = express();
app.use(cors());
app.use(morgan('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));


//ENDPOINTS PÚBLICOS (sin autenticación)
app.use('/user', user);   // register, login quedan libres

//ENDPOINTS PRIVADOS (con autenticación)
app.use('/project', auth, project);

app.use('/tasks', auth, tasks);

app.use('/members', auth, members);

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

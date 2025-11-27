//Dependencies
import express from 'express';
import morgan from 'morgan';
import cors from 'cors';
//Routes
import project from './routes/project.js';
import user from './routes/user.js';
import createUser from './routes/createUser.js';
import login from './routes/login.js';
import getToken from './routes/getToken.js';
import reports from './routes/reports.js';
//Middleware
import auth from './middleware/tokenAuth.js';

import { openDB, createTables } from './config/SQLiteManager.js';


//App setup
const app = express();
app.use(cors());
app.use(morgan('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));


//// for testing only



app.use('/test/create/user/', (req, res, next)=>{
    req.tokenData = {
        role: 0
    }
    next();
} , createUser);

app.get('/test/someEndpointSecure', auth, (req, res, next)=>{
    console.log(req.tokenData)  // this prints =>  { userId: 4, role: '1', iat: 1764180955, exp: 1764224155 }
    res.json({message: 'simon',})
})

////


//Endpoints
app.use('/login', login, getToken);
app.use('/create/user', auth, createUser)
app.use('/project', auth, project);
app.use('/user', auth, user);

app.use('/reports', auth, reports);

    // aqui pones los demas endpoints, justo como el de reports arriba, maike.


//Utilities
app.get('/', (req, res) => {
    res.send('Hi there! Im alive!');
});
app.use((req, res, next) => {
    res.status(404).send({ message: 'Not found' });
});


//Start server
app.listen(process.env.PORT || 3200, () => {
    console.log('Server is running on port ' + (process.env.PORT || 3200));
})



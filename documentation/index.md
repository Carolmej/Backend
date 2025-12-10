# API documentation

This API runs on [`https://pmaster.elcilantro.site/api/`](https://pmaster.elcilantro.site/api/).

All endpoints will return a code 400 with the message Invalid Data when the input data values are not met exactly
And return a code 500 with message {"message": "Internal server error at time: DD/MM/YYYY, hh:mm:ss am/pm"} when there was a backend error.

---
### Open endpoints

Open endpoints that require no Authentication.

### Platform access `user/`
* [login](https://pmaster.elcilantro.site/api/documentation/login.md) : `POST user/login`
* [Generate 2FA secret]() : `POST user/2fa/generate`
* [Enable 2FA]() : `POST user/2fa/enable`
* [2FA Login]() : `POST user/2fa/login`

---
### Endpoints that require Authentication

Closed endpoints require a valid Token to be included in the header authorization of the request with the format:
```json
"authorization" : "bearer XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
```
A normal session token is returned by user/login or user/2fa/login.
Its expiration time is 8 hours.
2FA temporary tokens expire after 5 minutes.

## Error Responses
**Condition** : The token provided was invalid.
**Code** : `401 Unauthorized`
```json
{
    "message": "Invalid token"
}
```
<br>

**Condition** : No token was provided.
**Code** : `401 Unauthorized`
```json
{
    "message": "No token provided"
}
```

<br>

**Condition**: The information requested doesn't match the token owner.
**Code** : `401 Unauthorized`

```json
{
    "message": "Invalid credentials"
}
```
<br>

### User related `user/`
Create user : POST user/register
Reset user password : POST user/resetPass
Get user profile : GET user/profile
Update user profile : PUT user/profile

### Project CRUD `project/`
Get project info : GET project/
Create project : POST project/
Get single project : GET project/:id
Update project : PUT project/:id
Remove project : DELETE project/:id

### Project members `members/`
Get project members : GET members/:project_id
Add project member : POST members/:project_id
Remove project member : DELETE members/:project_id/:user_id

### Project teams `teams/`
Get project teams : GET teams/:project_id
Create project team : POST teams/:project_id
Update project team : PUT teams/:project_id/:team_id
Remove project team : DELETE teams/:project_id/:team_id

### Project sprints `sprints/`
Get project modules : GET modules/:project_id
Create module : POST modules/:project_id
Update module : PUT modules/:project_id/:module_id
Remove module : DELETE modules/:project_id/:module_id
Get module by ID : GET modules/:project_id/:module_id

### Tasks `tasks/`
Get module tasks : GET tasks/:project_id/:module_id
Create module task : POST tasks/:project_id/:module_id
Update task : PUT tasks/:project_id/:module_id/:task_id
Remove task : DELETE tasks/:project_id/:module_id/:task_id
Get task by ID : GET tasks/:project_id/:module_id/:task_id

### Notifications `notifications/`
Get notifications : GET notifications/
Mark notification as read : PATCH notifications/:notification_id/read

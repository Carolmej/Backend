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

**Condition** : No token was provided. **Code** : `401 Unauthorized`
```json
{
    "message": "No token provided"
}
```

<br>

**Condition**: The information requested doesn't match the token owner.(e.g, in a security context). 
**Code** : `401 Unauthorized`

```json
{
    "message": "Invalid credentials"
}
```
<br>

### User related `user/` (full details in: user.md)
* [Create user](https://pmaster.elcilantro.site/api/documentation/user.md) (Admin only): `POST user/register`
* [Reset user password](https://pmaster.elcilantro.site/api/documentation/user.md) (Admin only): `POST user/resetPass`
* [Get user profile](https://pmaster.elcilantro.site/api/documentation/user.md) : `GET user/profile`
* [Update user profile](https://pmaster.elcilantro.site/api/documentation/user.md) : `PUT user/profile`

### Project CRUD `project/` (full details in project.md)
* [Get project info](https://pmaster.elcilantro.site/api/documentation/project.md) : `GET project/`
* [Create project](https://pmaster.elcilantro.site/api/documentation/project.md) (Admin only): `POST project/`
* [Get single project](https://pmaster.elcilantro.site/api/documentation/project.md) : `GET project/:id`
* [Update project](https://pmaster.elcilantro.site/api/documentation/project.md) (Admin only): `PUT project/:id`
* [Remove project](https://pmaster.elcilantro.site/api/documentation/project.md) (Admin only): `DELETE project/:id`

### Project members `members/` (full details in member.id)
* [Get project members](https://pmaster.elcilantro.site/api/documentation/member.id) : `GET members/:project_id`
* [Add project member ](https://pmaster.elcilantro.site/api/documentation/member.id): `POST members/:project_id`
* [Get specific member](https://pmaster.elcilantro.site/api/documentation/member.id) : `GET memebers/:project_id/:user_id`
* [Remove project member](https://pmaster.elcilantro.site/api/documentation/member.id) : `DELETE members/:project_id/:user_id`

### Project teams `teams/` (full details in teams.id)
* [Get project teams](https://pmaster.elcilantro.site/api/documentation/teams.id) : `GET teams/:project_id`
* [Create project team](https://pmaster.elcilantro.site/api/documentation/teams.id) : `POST teams/:project_id`
* [Get team by id](https://pmaster.elcilantro.site/api/documentation/teams.id): `GET teams/:project_id/:team_id`
* [Update project team](https://pmaster.elcilantro.site/api/documentation/teams.id) : `PUT teams/:project_id/:team_id`
* [Remove project team](https://pmaster.elcilantro.site/api/documentation/teams.id) : `DELETE teams/:project_id/:team_id`
* [Add user to team](https://pmaster.elcilantro.site/api/documentation/teams.id): `POST teams/:project_id/:team_id/member`
* [Remove user from team](https://pmaster.elcilantro.site/api/documentation/teams.id): `DELETE teams/:project_id/:team_id/member/:user_id`

### Project sprints `sprints/` (Full details in sprints.md)
* [Get project modules](https://pmaster.elcilantro.site/api/documentation/sprints.md) : `GET modules/:project_id`
* [Create module](https://pmaster.elcilantro.site/api/documentation/sprints.md) : `POST modules/:project_id`
* [Get module by ID](https://pmaster.elcilantro.site/api/documentation/sprints.md) : `GET modules/:project_id/:module_id`
* [Update module](https://pmaster.elcilantro.site/api/documentation/sprints.md) : `PUT modules/:project_id/:module_id`
* [Remove module](https://pmaster.elcilantro.site/api/documentation/sprints.md) : `DELETE modules/:project_id/:module_id`


### Tasks `tasks/` (full details in tasks.md)
* [Get module tasks](https://pmaster.elcilantro.site/api/documentation/tasks.md) : `GET tasks/:project_id/:module_id`
* [Create module task](https://pmaster.elcilantro.site/api/documentation/tasks.md) : `POST tasks/:project_id/:module_id`
* [Get task by ID:](https://pmaster.elcilantro.site/api/documentation/tasks.md) `GET tasks/:project_id/:task_id`
* [Update task]() (Full): `PUT tasks/:project_id/:module_id/:task_id`
* [Update task status](https://pmaster.elcilantro.site/api/documentation/tasks.md) (Progress): `PATCH tasks/:project_id/:task_id/status`
* [Remove task](https://pmaster.elcilantro.site/api/documentation/tasks.md) : `DELETE tasks/:project_id/:module_id/:task_id`
* [Get task by ID](https://pmaster.elcilantro.site/api/documentation/tasks.md) : `GET tasks/:project_id/:module_id/:task_id`

### Notifications `notifications/` (full details in notifications.md)
* [Get notifications](https://pmaster.elcilantro.site/api/documentation/notifications.md) : `GET notifications/`
* [Mark notification as read](https://pmaster.elcilantro.site/api/documentation/notifications.md) : `PATCH notifications/:notification_id/read`


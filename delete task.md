# DELETE TASK
Deletes a task from the project database.

_URL_ : `/tasks/:project_id/:task_id`
_Method_ : `DELETE`
_Auth required_ : Yes
_URL Parameters_ : `project_id`, `task_id`
_Data input_ : None

_Success Response Code_ : `200 OK`

```json
{
    "message": "Task deleted successfully"
}
ERROR RESPONSES
Condition : Task not found.
Code : 404 Not Found

json
{
    "message": "Task not found"
}

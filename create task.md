TASKS:

# Tasks Management
Endpoints for managing tasks within a specific project. All task data is stored in a SQLite database local to the project.
## Create Task
Creates a new task within a project and optionally associates it with a module/sprint.

_URL_ : /tasks/:project_id

_Method_ : POST

_Auth required_ : Yes

_URL Parameters_ : project_idData input : body : { module_id, title, description, priority, status, user_ids, due_date }

| Field |Type | Description |Required | Default | 
| :---- | :-- | :---------- | :------ | :------ |
|module_id| integer | ID of the module/sprint the task belongs to. | No | null| 
| title | string | Task title |  | Yes |
| description | string | Detailed task description. | No | "" | 
priority | string | Task priority.| No | "" |
| status | string | Task status. | No | "pending" | user_ids | integer| ID of the user assigned to the task. |No | null | 
| due_date| string |Task due date (ISO format preferred). | No |null | 

_Success Response Code_ : 201 Created
JSON
{
    "message": "Task created successfully"
}











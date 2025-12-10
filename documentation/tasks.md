# Tasks Management
Endpoints for managing tasks within a specific project. All task data is stored in a SQLite database local to the project.
## Create Task
Creates a new task within a project and optionally associates it with a module/sprint.

__URL__ : `/tasks/:project_id`

__Method__ : `POST`

__Auth required__ : Yes

__URL Parameters__ : `project_idData input : body : { module_id, title, description, priority, status, user_ids, due_date }`

| Field |Type | Description |Required | Default | 
| :---- | :-- | :---------- | :------ | :------ |
|`module_id`| `integer` | ID of the module/sprint the task belongs to. | No | null| 
| `title` | `string` | Task title |  | Yes |
| `description` | `string` | Detailed task description. | No | "" | 
`priority` | `string` | Task priority.| No | "" |
| `status` | `string` | Task status. | No | "pending" | user_ids | integer| ID of the user assigned to the task. |No | null | 
| `due_date`| `string` |Task due date (ISO format preferred). | No |null | 

__Success Response Code__ : `201 Created`
```JSON
{
    "message": "Task created successfully"
}
```

# Get all tasks 

Retrieves all tasks for a given project, ordered by creation date descending.

__URL__ : `/tasks/:project_id`

__Method__ : `GET`

__Auth required__ : Yes

__URL Parameters__ : `project_id`

__Data input__ : None

__Success Response
Code__ : `200 OK`

```json
[
    {
        "id": 1,
        "module_id": 10,
        "title": "Fix database connection",
        "description": "...",
        "priority": "high",
        "status": "pending",
        "created_at": "2024-01-01 10:00:00",
        "updated_at": "2024-01-01 10:00:00",
        "user_ids": 25,
        "due_date": "2024-02-15"
    }
]
```
# Get task by ID
Retrieves a specific task using its ID.

__URL__ : `/tasks/:project_id/:task_id`

__Method__ :` GET`

__Auth required__ : Yes

__URL Parameters__ : `project_id, task_id`

__Data input__ : None

__Success Response
Code__ : `200 OK`

```json
{
    "id": 1,
    "module_id": 10,
    "title": "Fix database connection",
    "description": "...",
    "priority": "high",
    "status": "pending",
    "created_at": "2024-01-01 10:00:00",
    "updated_at": "2024-01-01 10:00:00",
    "user_ids": 25,
    "due_date": "2024-02-15"
}
```

# Update task

Updates all non-timestamp fields of an existing task.

__URL__ : `/tasks/:project_id/:task_id`

__Method__ : `PUT`

__Auth required__ : Yes

__URL Parameters__ : `project_id, task_id`

__Data input__ : body : { module_id, title, description, priority, status, user_ids, due_date }

| Field | Type | Description | Required |
| :---- | :--- | :---------  | :------  |
| module_id | integer | Module/sprint ID. | Yes |
| title | string | Task title. | Yes |
| description | string | Detailed task description. | No | 
| priority | string | Task priority. | No |
| status | string | Task status. | Yes |
| user_ids | integer | User ID assigned. | No
| due_date | string | Task due date (ISO format preferred). | No

__Success Response Code:__ `200 ok`
```json
{
    "message": "Task updated successfully"
}
```

# Update Task Status (Progress Update)
Updates only the status of an existing task.
__URL__ : `/tasks/:project_id/:task_id/status`
__Method__ : `PATCH`
__Auth required__ : Yes
__URL Parameters__ : `project_id, task_id`
__Data input__ : `body : { status }`

| Field| Type| Description| Required| 
|:--- | :--- | :--- | :---- |
| status| string| New task status.| Yes | 

__Success Response Code__ : `200 OK`
```JSON
{
    "message": "Status updated successfully"
}
```

# Delete Task
Deletes a task from the project database.

__URL__ : `/tasks/:project_id/:task_id`

__Method__ : `DELETE`

__Auth required__ : Yes

__URL Parameters__ : `project_id, task_id`

__Data input__ : None

__Success Response
Code__ : `200 OK`

```JSON

{
    "message": "Task deleted successfully"
}
```

# ERROR RESPONSES

__Condition__ : Task not found.

__Code__ : `404 Not Found`

```JSON

{
    "message": "Task not found"
}
```
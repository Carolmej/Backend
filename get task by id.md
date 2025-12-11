# Get task by ID
Retrieves a specific task using its ID.

_URL_ : `/tasks/:project_id/:task_id`
_Method_ : `GET`
_Auth required_ : Yes
_URL Parameters_ : `project_id`, `task_id`
_Data input_ : None

_SSuccess Response Code_ : `200 OK`

```json
{
    "id": 1,
    "module_id": 10,
    "title": "Fix database connection",
    "description": "...",
    "priority": "high",
    "status": "pending",
    "created_at": "2024-01-01T10:00:00.000Z",
    "updated_at": "2024-01-01T10:00:00.000Z",
    "user_ids": 25,
    "due_date": "2024-02-15"
}


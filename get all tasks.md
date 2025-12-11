# GET ALL TASKS
Retrieves all tasks for a given project, ordered by creation date descending.

_URL_ : `/tasks/:project_id`
_Method_ : `GET`
_Auth required_ : Yes
_URL Parameters_ : `project_id`
_Data input_ : None

_Success Response Code_ : `200 OK`

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
# UPDATE TASK
Updates all non-timestamp fields of an existing task.

_URL_ : `/tasks/:project_id/:task_id`
_Method_ : `PUT`
_Auth required_ : Yes
_URL Parameters_ : `project_id`, `task_id`
_Data input_ : `body : { module_id, title, description, priority, status, user_ids, due_date }`

| Field | Type | Description | Required |
| :---- | :--- | :---------  | :------  |
| `module_id` | integer | Module/sprint ID. | **Yes** |
| `title` | string | Task title. | **Yes** |
| `description` | string | Detailed task description. | No | 
| `priority` | string | Task priority. | No |
| `status` | string | Task status. | **Yes** |
| `user_ids` | integer | User ID assigned. | No |
| `due_date` | string | Task due date (ISO format preferred). | No |

_Success Response Code_ : `200 OK`

```json
{
    "message": "Task updated successfully"
}

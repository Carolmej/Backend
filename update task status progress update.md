# UPDATE TASK STATUS (PROGRESS UPDATE)
Updates only the status of an existing task.

_URL_ : `/tasks/:project_id/:task_id/status`
_Method_ : `PATCH`
_Auth required_ : Yes
_URL Parameters_ : `project_id`, `task_id`
_Data input_ : `body : { status }`

| Field | Type | Description | Required |
| :--- | :--- | :--- | :---- |
| `status` | string | New task status. | **Yes** |

_Success Response Code_ : `200 OK`

```json
{
    "message": "Status updated successfully"
}


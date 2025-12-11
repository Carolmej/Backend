# UPDATE PROJECT
_URL_ : `/project/:id`
_Method_ : `PUT`
_Auth required_ : Yes
_Permissions required_ : Admin only
_URL parameters_ : `id` (required)
_Data input_ : `body : { name, description, client_id, team_leader_id, start, end }`

| Field | Type | Description | Required |
| :---- | :--- | :---------- | :------ |
| `name` | string | Project name | **Yes** |
| `description` | string | Project description | **Yes** |
| `client_id` | integer | Client organization ID | **Yes** |
| `team_leader_id` | integer | User ID of project leader | **Yes** |
| `start` | string | Project start date (YYYY-MM-DD) | **Yes** |
| `end` | string | Project end date (YYYY-MM-DD) | **Yes** |

_Success Response Code_ : `200 OK`

```json
{
    "message": "Project updated successfully"
}
Notes:

Updates all project fields

Requires all fields (partial updates not supported)

Does not modify SQLite database filename

ERROR RESPONSES
Condition : Missing required fields.
Code : 400 Bad Request

json
{
    "message": "Incomplete data"
}
Condition : Project not found.
Code : 404 Not Found

json
{
    "message": "Project not found"
}
Condition : User is not admin.
Code : 401 Unauthorized

json
{
    "message": "Admin privileges required"
}
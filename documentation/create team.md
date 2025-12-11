# CREATE TEAM
_URL_ : `/teams/:project_id`
_Method_ : `POST`
_Auth required_ : Yes
_Permissions required_ : Project member
_URL parameters_ : `project_id` (required)
_Data input_ : `body : { name, description }`

| Field | Type | Description | Required | Default |
| :---- | :--- | :---------- | :------ | :------ |
| `name` | string | Team name | **Yes** | - |
| `description` | string | Team description | No | `""` |

_Success Response Code_ : `201 Created`

```json
{
    "message": "Team created successfully"
}
Notes:

Creates new team in project's SQLite database

Required: name

Optional: description (default: "")

Stored in teams table

Team belongs to the specific project

ERROR RESPONSES
Condition : Missing project_id or name.
Code : 400 Bad Request

json
{
    "message": "Incomplete data"
}
Condition : Project database not found.
Code : 404 Not Found

Condition : Invalid authentication.
Code : 401 Unauthorized

json
{
    "message": "Invalid token"
}







# CREATE SPRINT/MODULE
_URL_ : `/sprints/:project_id`
_Method_ : `POST`
_Auth required_ : Yes
_Permissions required_ : Project member
_URL parameters_ : `project_id` (required)
_Data input_ : `body : { title, description, priority, status }`

| Field | Type | Description | Required | Default |
| :---- | :--- | :---------- | :------ | :------ |
| `title` | string | Sprint/module name | **Yes** | - |
| `description` | string | Detailed description | No | `""` |
| `priority` | string | Priority level | No | `"medium"` |
| `status` | string | Current status | No | `"active"` |

_Success Response Code_ : `201 Created`

```json
{
    "message": "Module/Sprint created successfully"
}
Notes:

Creates new sprint/module in project's SQLite database

Optional fields: description (default: ""), priority (default: "medium"), status (default: "active")

Automatically sets created_at timestamp

Stores in modules table

ERROR RESPONSES
Condition : Missing project_id or title.
Code : 400 Bad Request

```json
{
    "message": "Incomplete data"
}
Condition : Project database not found.
Code : 404 Not Found

Condition : Invalid authentication.
Code : 401 Unauthorized

```json
{
    "message": "Invalid token"
}




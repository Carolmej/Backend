# UPDATE SPRINT/MODULE
_URL_ : `/sprints/:project_id/:module_id`
_Method_ : `PUT`
_Auth required_ : Yes
_Permissions required_ : Project member
_URL parameters_ : `project_id` (required), `module_id` (required)
_Data input_ : `body : { title, description, priority, status }`

| Field | Type | Description | Required |
| :---- | :--- | :---------- | :------ |
| `title` | string | Sprint/module name | **Yes** |
| `description` | string | Detailed description | No |
| `priority` | string | Priority level | No |
| `status` | string | Current status | No |

_Success Response Code_ : `200 OK`

```json
{
    "message": "Module/Sprint updated successfully"
}
Notes:

Updates all provided fields

Sets updated_at to current timestamp

title is required for update

Other fields optional but will update if provided

ERROR RESPONSES
Condition : Missing title field.
Code : 400 Bad Request

json
{
    "message": "Incomplete data"
}
Condition : Module not found.
Code : 404 Not Found

json
{
    "message": "Module/Sprint not found"
}
Condition : Invalid authentication.
Code : 401 Unauthorized

json
{
    "message": "Invalid token"
}
# DELETE SPRINT/MODULE
_URL_ : `/sprints/:project_id/:module_id`
_Method_ : `DELETE`
_Auth required_ : Yes
_Permissions required_ : Project member
_URL parameters_ : `project_id` (required), `module_id` (required)

_Success Response Code_ : `200 OK`

```json
{
    "message": "Module/Sprint deleted successfully"
}
Notes:

Permanently deletes module from SQLite database

Does not delete associated tasks (orphaned tasks remain)

No confirmation prompt - immediate deletion

Returns success message only

ERROR RESPONSES
Condition : Project database not found.
Code : 404 Not Found

Condition : Invalid authentication.
Code : 401 Unauthorized

json
{
    "message": "Invalid token"
}
# DELETE PROJECT
_URL_ : `/project/:id`
_Method_ : `DELETE`
_Auth required_ : Yes
_Permissions required_ : Admin only
_URL parameters_ : `id` (required)

_Success Response Code_ : `200 OK`

```json
{
    "message": "Project deleted successfully"
}
Notes:

Deletes project from PostgreSQL database

Deletes associated SQLite database file (./projects/{project_id}.db)

Uses database transaction with rollback

Physically removes SQLite file from filesystem

ERROR RESPONSES
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
Condition : SQLite file deletion fails.
Code : 500 Internal Server Error

json
{
    "message": "Internal server error at time: 20/03/2024, 03:45:30 pm"
}
# PROJECT MANAGEMENT

## CREATE NEW PROJECT

_URL_ : `/project/`
_Method_ : `POST`
_Auth required_ : Yes
_Permissions required_ : Admin only (adminAuth middleware)
_Data input_ : `body : { name, description, client_id, team_leader_id, start, end }`

_Success Response_
_Condition_ : All required fields provided and user is admin.
_Code_ : `201 Created`

```json
{
    "project_id": "a1b2c3d4"
}
Notes:

Generates unique project ID using crypto.randomBytes

Creates project in PostgreSQL database

Creates SQLite database file for project data ({project_id}.db)

Automatically adds team leader as first project member

Uses database transaction with rollback on error

Error Response
Condition : Missing required fields.
Code : 400 Bad Request

json
{
    "message": "Incomplete data"
}
Condition : User is not admin.
Code : 401 Unauthorized

json
{
    "message": "Admin privileges required"
}
Condition : Duplicate project or database error.
Code : 400 Bad Request (via errorHandler)





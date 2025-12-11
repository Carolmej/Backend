# GET ALL PROJECTS
_URL_ : `/project/`
_Method_ : `GET`
_Auth required_ : Yes
_Permissions required_ : Authenticated user

_Success Response Code_ : `200 OK`

```json
[
    {
        "id": "a1b2c3d4",
        "name": "PM System Development",
        "description": "Project management platform",
        "client_id": 5,
        "team_leader_id": 123,
        "start": "2024-03-01",
        "end": "2024-12-31",
        "sqlite_file": "a1b2c3d4.db",
        "leader_name": "John Doe"
    }
]
Notes:

Returns array of all projects

Joined with users table to include leader name

Ordered by start date DESC (newest first)

Includes SQLite filename for each project

ERROR RESPONSES
Condition : Invalid authentication.
Code : 401 Unauthorized

json
{
    "message": "Invalid token"
}

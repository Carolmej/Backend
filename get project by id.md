# GET PROJECT BY ID
_URL_ : `/project/:id`
_Method_ : `GET`
_Auth required_ : Yes
_Permissions required_ : Authenticated user
_URL parameters_ : `id` (required)

_Success Response Code_ : `200 OK`

```json
{
    "id": "a1b2c3d4",
    "name": "PM System Development",
    "description": "Project management platform",
    "client_id": 5,
    "team_leader_id": 123,
    "start": "2024-03-01",
    "end": "2024-12-31",
    "leader_name": "John Doe"
}
Notes:

Returns single project object

Excludes SQLite filename from response

Includes leader name via JOIN

ERROR RESPONSES
Condition : Project not found.
Code : 404 Not Found

json
{
    "message": "Project not found"
}
Condition : Invalid authentication.
Code : 401 Unauthorized

json
{
    "message": "Invalid token"
}
# GET ALL TEAMS
_URL_ : `/teams/:project_id`
_Method_ : `GET`
_Auth required_ : Yes
_Permissions required_ : Project member
_URL parameters_ : `project_id` (required)

_Success Response Code_ : `200 OK`

```json
[
    {
        "id": 1,
        "name": "Frontend Team",
        "description": "User interface development team"
    },
    {
        "id": 2,
        "name": "Backend Team",
        "description": "API and database team"
    }
]
Notes:

Returns all teams in project

Includes ID, name, description

Empty array if none exist

No member info here

ERROR RESPONSES
Condition : Project database not found.
Code : 404 Not Found

Condition : Invalid authentication.
Code : 401 Unauthorized

json
{
    "message": "Invalid token"
}
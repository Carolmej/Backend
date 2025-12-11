# GET SPECIFIC TEAM
_URL_ : `/teams/:project_id/:team_id`
_Method_ : `GET`
_Auth required_ : Yes
_Permissions required_ : Project member
_URL parameters_ : `project_id` (required), `team_id` (required)

_Success Response Code_ : `200 OK`

```json
{
    "id": 1,
    "name": "Frontend Team",
    "description": "User interface development team"
}
Notes:

Returns one team

Confirms team belongs to the project

ERROR RESPONSES
Condition : Team not found.
Code : 404 Not Found

json
{
    "message": "Team not found"
}
Condition : Invalid authentication.
Code : 401 Unauthorized

json
{
    "message": "Invalid token"
}
# DELETE TEAM
_URL_ : `/teams/:project_id/:team_id`
_Method_ : `DELETE`
_Auth required_ : Yes
_Permissions required_ : Project admin or team creator
_URL parameters_ : `project_id` (required), `team_id` (required)

_Success Response Code_ : `200 OK`

```json
{
    "message": "Team deleted successfully"
}
Notes:

Deletes team from DB

Also deletes members from teammembers

Immediate deletion

ERROR RESPONSES
Condition : Project database not found.
Code : 404 Not Found

Condition : Invalid authentication.
Code : 401 Unauthorized

json
{
    "message": "Invalid token"
}
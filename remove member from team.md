# REMOVE MEMBER FROM TEAM
_URL_ : `/teams/:project_id/:team_id/member/:user_id`
_Method_ : `DELETE`
_Auth required_ : Yes
_Permissions required_ : Project member
_URL parameters_ : `project_id` (required), `team_id` (required), `user_id` (required)

_Success Response Code_ : `200 OK`

```json
{
    "message": "Member removed successfully"
}
Notes:

Removes user from team members

Deletes record from teammembers

Does not delete user from system

ERROR RESPONSES
Condition : Project database not found.
Code : 404 Not Found

Condition : Invalid authentication.
Code : 401 Unauthorized

json
{
    "message": "Invalid token"
}
# REMOVE MEMBER FROM PROJECT
_URL_ : `/members/:project_id/:user_id`
_Method_ : `DELETE`
_Auth required_ : Yes
_Permissions required_ : Project admin or owner (cannot remove self)
_URL parameters_ : `project_id` (required), `user_id` (required)

_Success Response Code_ : `200 OK`

```json
{
    "message": "Member removed successfully"
}
Notes:

Deletes record from project_members table

Returns success message only

Does not delete user from users table

ERROR RESPONSES
Condition : Invalid authentication.
Code : 401 Unauthorized

json
{
    "message": "Invalid token"
}
Condition : Insufficient permissions.
Code : 403 Forbidden

json
{
    "message": "Insufficient permissions"
}

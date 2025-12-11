# GET SPECIFIC PROJECT MEMBER
_URL_ : `/members/:project_id/:user_id`
_Method_ : `GET`
_Auth required_ : Yes
_Permissions required_ : Project member
_URL parameters_ : `project_id` (required), `user_id` (required)

_Success Response Code_ : `200 OK`

```json
{
    "id": 123,
    "name": "John Doe",
    "email": "john@example.com",
    "role": "developer"
}
Notes:

Returns single user object

Verifies user belongs to specified project

ERROR RESPONSES
Condition : Member not found in project.
Code : 404 Not Found

json
{
    "message": "Member not found"
}
Condition : Invalid authentication.
Code : 401 Unauthorized

json
{
    "message": "Invalid token"
}
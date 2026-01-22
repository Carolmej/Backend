# GET ALL PROJECT MEMBERS
_URL_ : `/members/:project_id`
_Method_ : `GET`
_Auth required_ : Yes
_Permissions required_ : Project member
_URL parameters_ : `project_id` (required)

_Success Response Code_ : `200 OK`

```json
[
    {
        "id": 123,
        "name": "John Doe",
        "email": "john@example.com",
        "role": "developer"
    },
    {
        "id": 124,
        "name": "Jane Smith",
        "email": "jane@example.com",
        "role": "manager"
    }
]
Notes:

Returns array of user objects

Joins project_members with users table

Includes id, name, email, and role

ERROR RESPONSES
Condition : Invalid authentication.
Code : 401 Unauthorized

json
{
    "message": "Invalid token"
}
Condition : User not a project member.
Code : 401 Unauthorized

json
{
    "message": "Invalid credentials"
}

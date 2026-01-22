# ADD MEMBER TO TEAM
_URL_ : `/teams/:project_id/:team_id/member`
_Method_ : `POST`
_Auth required_ : Yes
_Permissions required_ : Project member
_URL parameters_ : `project_id` (required), `team_id` (required)
_Data input_ : `body : { user_id }`

| Field | Type | Description | Required |
| :---- | :--- | :---------- | :------ |
| `user_id` | integer | User ID from PostgreSQL users table | **Yes** |

_Success Response Code_ : `201 Created`

```json
{
    "message": "Member added successfully"
}
Notes:

Adds user to team

Prevents duplicates

User must exist in main PostgreSQL users table

ERROR RESPONSES
Condition : Missing user_id.
Code : 400 Bad Request

Condition : Team not found / user invalid.
Code : 404 Not Found

Condition : Invalid authentication.
Code : 401 Unauthorized

json
{
    "message": "Invalid token"
}
# UPDATE TEAM
_URL_ : `/teams/:project_id/:team_id`
_Method_ : `PUT`
_Auth required_ : Yes
_Permissions required_ : Project member
_URL parameters_ : `project_id` (required), `team_id` (required)
_Data input_ : `body : { name, description }`

| Field | Type | Description | Required |
| :---- | :--- | :---------- | :------ |
| `name` | string | Team name | **Yes** |
| `description` | string | Team description | No |

_Success Response Code_ : `200 OK`

```json
{
    "message": "Team updated successfully"
}
Notes:

Updates name/description

name required

Does NOT modify team members

ERROR RESPONSES
Condition : Missing name.
Code : 400 Bad Request

```json
{
    "message": "Incomplete data"
}
Condition : Team not found.
Code : 404 Not Found

```json
{
    "message": "Team not found"
}
Condition : Invalid authentication.
Code : 401 Unauthorized

```json
{
    "message": "Invalid token"
}
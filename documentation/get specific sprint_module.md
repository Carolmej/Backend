# GET SPECIFIC SPRINT/MODULE
_URL_ : `/sprints/:project_id/:module_id`
_Method_ : `GET`
_Auth required_ : Yes
_Permissions required_ : Project member
_URL parameters_ : `project_id` (required), `module_id` (required)

_Success Response Code_ : `200 OK`

```json
{
    "id": 1,
    "title": "Sprint 1 - Backend API",
    "description": "Develop REST API endpoints",
    "priority": "high",
    "status": "active",
    "created_at": "2024-03-15T10:30:00Z",
    "updated_at": "2024-03-20T14:15:00Z"
}
Notes:

Returns single module object

Includes all database fields

Verifies module belongs to specified project

ERROR RESPONSES
Condition : Module not found.
Code : 404 Not Found

json
{
    "message": "Module/Sprint not found"
}
Condition : Project database not found.
Code : 404 Not Found

Condition : Invalid authentication.
Code : 401 Unauthorized

json
{
    "message": "Invalid token"
}
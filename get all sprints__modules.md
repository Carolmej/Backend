# GET ALL SPRINTS/MODULES
_URL_ : `/sprints/:project_id`
_Method_ : `GET`
_Auth required_ : Yes
_Permissions required_ : Project member
_URL parameters_ : `project_id` (required)

_Success Response Code_ : `200 OK`

```json
[
    {
        "id": 1,
        "title": "Sprint 1 - Backend API",
        "description": "Develop REST API endpoints",
        "priority": "high",
        "status": "active",
        "created_at": "2024-03-15T10:30:00Z",
        "updated_at": "2024-03-20T14:15:00Z"
    },
    {
        "id": 2,
        "title": "Sprint 2 - Frontend UI",
        "description": "User interface development",
        "priority": "medium",
        "status": "planning",
        "created_at": "2024-03-18T09:00:00Z",
        "updated_at": null
    }
]
Notes:

Returns array of all sprints/modules

Ordered by created_at DESC (newest first)

Returns all fields from modules table

Empty array if no modules exist

ERROR RESPONSES
Condition : Project database not found.
Code : 404 Not Found

Condition : Invalid authentication.
Code : 401 Unauthorized

json
{
    "message": "Invalid token"
}
# GET MODULE PROGRESS REPORT (JSON)
_URL_ : `/reports/module-progress/:project_id`
_Method_ : `GET`
_Auth required_ : Yes
_Permissions required_ : Project member
_URL parameters_ : `project_id` (required)

_Success Response Code_ : `200 OK`

```json
{
    "modules": "3 {Backend: 85%, Frontend: 60%, Database: 90%}",
    "tasks_by_module": {
        "Backend": {
            "total": 20,
            "completed": 17,
            "percentage": "85%"
        },
        "Frontend": {
            "total": 15,
            "completed": 9,
            "percentage": "60%"
        }
    },
    "total_tareas": {
        "total": 55,
        "completed": 45
    }
}
Notes:

Aggregates module completion percentages

Returns both summary string and detailed object

Scans project's SQLite database

Handles unassigned tasks

ERROR RESPONSES
Condition : Project database not found.
Code : 404 Not Found

json
{
    "message": "Project not found"
}
# GET DASHBOARD SUMMARY
_URL_ : `/reports/dashboard/summary`
_Method_ : `GET`
_Auth required_ : Yes
_Permissions required_ : Authenticated user

_Success Response Code_ : `200 OK`

```json
{
    "summary": {
        "total_projects_assigned": 5,
        "tasks_due_soon": 8,
        "tasks_overdue": 3,
        "projects_near_deadline_count": 2
    },
    "projects_near_deadline": [
        {
            "id": "a1b2c3d4",
            "name": "Mobile App",
            "end": "2024-03-25"
        }
    ]
}
Notes:

Consolidates metrics across all user projects

Tasks due soon: within 7 days

Tasks overdue: past due date

Projects near deadline: ending within 7 days

Scans all SQLite project databases

ERROR RESPONSES
Condition : Invalid authentication.
Code : 401 Unauthorized

json
{
    "message": "Invalid token"
}
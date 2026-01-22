# GET TEAM PRODUCTIVITY REPORT
_URL_ : `/reports/team-productivity/:user_id`
_Method_ : `GET`
_Auth required_ : Yes
_Permissions required_ : Own user ID or admin (role ≤ 1)
_URL parameters_ : `user_id` (required)

_Success Response Code_ : `200 OK`

```json
{
    "user_id": 123,
    "metrics": {
        "total_tasks": 45,
        "completed_tasks": 38,
        "pending_tasks": 7,
        "completion_rate": "84.44%",
        "total_estimated_hours": 245.5
    },
    "message": "Team productivity report generated successfully"
}
Notes:

Aggregates tasks across all user's projects

Calculates completion rate and estimated hours

Requires admin role or own user ID

Scans all project SQLite databases

ERROR RESPONSES
Condition : No permission to view other user's report.
Code : 403 Forbidden

json
{
    "message": "Forbidden: You do not have permission to view this report."
}
Condition : User not assigned to any projects.
Code : 200 OK (with empty metrics)

json
{
    "user_id": 456,
    "message": "User is not assigned to any project.",
    "metrics": {
        "total_tasks": 0,
        "completed_tasks": 0,
        "completion_rate": "0.00%",
        "total_estimated_hours": 0
    }
}
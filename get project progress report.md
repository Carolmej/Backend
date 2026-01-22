# REPORTS MANAGEMENT

## GET PROJECT PROGRESS REPORT

_URL_ : `/reports/project-progress/:project_id`
_Method_ : `GET`
_Auth required_ : Yes
_Permissions required_ : Project member
_URL parameters_ : `project_id` (required) - Project ID

_Success Response_
_Condition_ : Project exists and user has access.
_Code_ : `200 OK`

```json
{
    "project_name": "PM System Development",
    "start_date": "2024-03-01",
    "end_date": "2024-12-31",
    "metrics": {
        "total_tasks": 155,
        "completed_tasks": 120,
        "pending_tasks": 35,
        "progress_percentage": "77.42%"
    },
    "message": "Report generated successfully"
}
Notes:

Retrieves project info from PostgreSQL

Counts tasks from project's SQLite database

Calculates completion percentage

JSON format only

Error Response
Condition : Project not found.
Code : 404 Not Found

json
{
    "message": "Project not found"
}
Condition : User not a project member.
Code : 401 Unauthorized

json
{
    "message": "Invalid credentials"
}




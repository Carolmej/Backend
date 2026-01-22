# GET MODULE PROGRESS REPORT (PDF)
_URL_ : `/reports/module-progress-pdf/:project_id`
_Method_ : `GET`
_Auth required_ : Yes
_Permissions required_ : Project member
_URL parameters_ : `project_id` (required)

_Success Response Code_ : `200 OK` (with PDF file attachment)
_Content-Type_ : `application/pdf`

_Notes_:
- Generates PDF with project name, summary, and module details
- Includes progress percentages and task counts
- Creates temporary PDF file in `./reports/` directory
- Auto-deletes file after sending
- Uses pdf-lib library for generation

## ERROR RESPONSES
_Condition_ : Project not found.
_Code_ : `404 Not Found`

```json
{
    "message": "Project not found"
}
Condition : PDF generation failed.
Code : 500 Internal Server Error

json
{
    "message": "Failed to generate PDF report"
}
# PROJECT MEMBERS MANAGEMENT

## ADD MEMBER TO PROJECT

_URL_: `/members/:project_id`  
_Method_: `POST`  
_Auth required_: Yes  
_Permissions required_: Project admin or owner  
_URL parameters_: `project_id` (required)  
_Data input_: `body : { user_id }`

_Success Response_ 
_Condition_: User exists and can be added to the project.  
_Code_: `201 Created`

```json
{
    "message": "Member added successfully"
}
Notes:

Adds user to project_members table

Returns success message only

User must exist in users table

Error Response
Condition: Missing project_id or user_id.
Code: 400 Bad Request

json
{
    "message": "Incomplete data"
}
Condition: User already member of project or duplicate entry.
Code: 400 Bad Request (via errorHandler)

Condition: Invalid authentication.
Code: 401 Unauthorized

json
{
    "message": "Invalid token"
}



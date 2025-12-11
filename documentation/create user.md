User:


## User Management and Security

Detailed information on user management, administration, and Two-Factor Authentication (2FA) endpoints.


### Create User (Requires Admin)

Creates a new platform user with a temporary password and sends a notification (email is currently disabled).

*URL* : /user/register

*Method* : POST

*Auth required* : Admin (Role 1)

*Data input* : body : { name, email, phone, role }

| Field   | Type      | Description                            | Required |        Constraints       |
| :------ | :-------- | :------------------------------------- | :------- | :----------------------- |
| name  | string  | User's full name.                      | Yes      |                          |
| email | string  | User's email address (must be unique). | Yes      |                          |
| phone | string  | User's phone number.                   | Yes      |                          |
| role  | integer | User's role level.                     | Yes      | Must be between 1 and 3. |

### Success Response

*Code* : 201 Created

json
{
    "message": "User created successfully"
}



















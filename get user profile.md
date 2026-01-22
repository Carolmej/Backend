# GET USER PROFILE
Retrieves the profile data of the authenticated user, including their assigned projects.

_URL_ : `/user/profile`
_Method_ : `GET`
_Auth required_ : Yes
_Data input_ : None (uses token data)

_Success Response Code_ : `200 OK`

```json
{
    "id": 2,
    "name": "John Doe",
    "email": "john@example.com",
    "role": 2,
    "phone": "1234567890",
    "active": true,
    "projects": [
        {
            "id": "a1b2c3d4",
            "name": "Project Alpha",
            "status": "active",
            "end": "2025-12-31T00:00:00.000Z"
        }
    ]
}



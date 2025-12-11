# UPDATE USER PROFILE
Allows the authenticated user to update their name and phone number.

_URL_ : `/user/profile`
_Method_ : `PUT`
_Auth required_ : Yes
_Data input_ : `body : { name, phone }`

| Field | Type | Description | Required |
| :---- | :----- | :------------- | :------  |
| `name` | string | New user's full name. | **Yes** |
| `phone` | string | New user's phone number. | **Yes** |

_Success Response Code_ : `200 OK`

```json
{
    "message": "User profile updated successfully"
}

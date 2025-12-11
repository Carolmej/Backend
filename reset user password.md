# RESET USER PASSWORD (REQUIRES ADMIN)
Generates a new temporary password, marks the user as inactive (active = false). The user will be forced to change the password upon first login.

_URL_ : `/user/resetPass`
_Method_ : `POST`
_Auth required_ : Admin (Role 1)
_Data input_ : `body : { user_id }`

| Field | Type | Description | Required |
| :--------- | :-------- | :------------------------------------------- | :------- |
| `user_id` | integer | ID of the user whose password will be reset. | **Yes** |

_Success Response Code_ : `200 OK`

```json
{
    "message": "Password reset successfully"
}

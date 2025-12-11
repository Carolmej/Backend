# COMPLETE 2FA LOGIN
Final login step when 2FA is enabled. The user must provide the temporary 2FA token (from /user/login) and the current TOTP code.

_URL_ : `/user/2fa/login`
_Method_ : `POST`
_Auth required_ : No
_Data input_ : `body : { totp, token }`

| Field | Type | Description | Required |
| :----- | :---- | :---------- | :-------- |
| `totp` | string | The 6-digit TOTP code from the authenticator app. | **Yes** |
| `token` | string | The temporary 2FA JWT token obtained from /user/login. | **Yes** |

_Success Response Code_ : `200 OK`

```json
{
    "message": "Login successful",
    "token": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "user": {
        "id": 2,
        "name": "John Doe",
        "email": "john@example.com",
        "role": 2
    }
}
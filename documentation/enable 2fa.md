# ENABLE 2FA
Validates the TOTP code provided by the user and, if valid, permanently enables 2FA for the account.

_URL_ : `/user/2fa/enable`
_Method_ : `POST`
_Auth required_ : No
_Data input_ : `body : { user_id, token }`

| Field | Type | Description | Required |
| :---- | :---- | :----- | :---- |
| `user_id` | integer | ID of the user to enable 2FA for. | **Yes** |
| `token` | string | The 6-digit TOTP code from the authenticator app. | **Yes** |

_Success Response Code_ : `200 OK`

```json
{
    "message": "2FA enabled successfully"
}

# Login into the platform

Checks credentials and returns either full session data or a 2FA challenge token.

**URL** : `/login`

**Method** : `POST`

**Auth required** : No

**Data input** : `body : { email, password }`

## Success Response (2FA disabled)

**Condition** : Credentials are valid and the user does not have 2FA enabled.

**Code** : `200 OK`

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
```

**Notes:**
If the user does not have 2FA active, the session token is returned immediately.

## Success Response (2FA enabled)

**Condition** : Credentials are valid, and the user has 2FA enabled.
Instead of the normal session token, a temporary 2FA token is issued.

**Code** : `200 OK`

```json
{
    "user": {
        "2fa": "temporary.jwt.2fa.token"
    }
}
```

**Notes:**
When 2FA is enabled, this is not the final login.
The user must submit the 6-digit TOTP code together with the temporary token to complete authentication.
See: /user/2fa/login.

## Error Response

**Condition** : Invalid email or password.

**Code** : `401 Unauthorized`

```json
{
    "message": "Incorrect credencials"
}
Error Response
Condition : The account exists but is inactive.
Code : 401 Unauthorized
{
    "message": "Forbidden NO permises"
}
```

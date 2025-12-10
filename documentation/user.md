# USER DOCUMENTATION

#### `Backend/documentation/user.md` (Gestión de Usuarios y 2FA)


## User Management and Security

Detailed information on user management, administration, and Two-Factor Authentication (2FA) endpoints.


### Create User (Requires Admin)

Creates a new platform user with a temporary password and sends a notification (email is currently disabled).

**URL** : `/user/register`

**Method** : `POST`

**Auth required** : Admin (Role 1)

**Data input** : `body : { name, email, phone, role }`

| Field   | Type      | Description                            | Required |        Constraints       |
| :------ | :-------- | :------------------------------------- | :------- | :----------------------- |
| `name`  | `string`  | User's full name.                      | Yes      |                          |
| `email` | `string`  | User's email address (must be unique). | Yes      |                          |
| `phone` | `string`  | User's phone number.                   | Yes      |                          |
| `role`  | `integer` | User's role level.                     | Yes      | Must be between 1 and 3. |

### Success Response

**Code** : `201 Created`

```json
{
    "message": "User created successfully"
}
```
# Reset User Password (Requires Admin)

Generates a new temporary password, marks the user as inactive (active = false), and sends a notification (email is currently disabled). The user will be forced to change the password upon first login.

__URL__ : `/user/resetPass`

__Method__ : `POST`

__Auth required__ : Admin (Role 1)

__Data input__ : `body : { user_id }`

| Field     | Type      | Description                                  | Required |
|:--------- | :-------- | :------------------------------------------- | :------- |
| `user_id` | `integer` | ID of the user whose password will be reset. | Yes      |

__Succes Response:__
__Code:__ 200 ok

```json
{
    "message:" "Password reseted successfully"
}
```

# Get User Profile
Retrieves the profile data of the authenticated user, including their assigned projects.

__URL__ : `/user/profile`

__Method__ : `GET`

__Auth required__ : Yes

__Data input__ : None (uses token data)

__Success Response___
__Code__ : `200 OK`
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
```
# Update User Profile
Allows the authenticated user to update their name and phone number.

__URL__ : `/user/profile`

__Method__ : `PUT`

__Auth required__ : Yes

__Data input__ : `body : { name, phone }`

| Field | Type   | Description    | Required |
| :---- | :----- | :------------- | :------  |
| name  | string | New user's full name.     | Yes
| phone | string | New user's phone number.  |Yes


__Success Response__
__Code__ : 200 OK

```JSON

{
    "message": "User profile updated successfully"
}
```


# Generate 2FA Secret and QR Code
Generates a new TOTP secret for a user and returns the secret key and a QR code image (data URL) for linking with an authenticator app. This operation overwrites any existing secret.

__URL__ : `/user/2fa/generate`

__Method__ : `POST`

__Auth required__ : No

__Data input__ : `body : { user_id }`

__Success Response
Code__ : `200 OK`

```JSON

{
    "secret": "JBSWY3DPEHPK3PXP",
    "qrImage": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAA[...]ElFTkSuQmCC"
}
```

# Enable 2FA
Validates the TOTP code provided by the user and, if valid, permanently enables 2FA for the account.

__URL__ : `/user/2fa/enable`

__Method__ : `POST`

__Auth required__ : No

__Data input__ : `body : { user_id, token }`

| Field | Type | Description | Required  
| :----| :---- |:-----|:----|
| user_id | integer | ID of the user to enable 2FA for. | Yes | 
| token | string | The 6-digit TOTP code from the authenticator app. | Yes

__Success Response
Code__ : `200 OK`
```
JSON

{
    "message": "2FA enabled successfully"
}
```

# Complete 2FA Login
Final login step when 2FA is enabled. The user must provide the temporary 2FA token (from `/user/login`) and the current TOTP code.

__URL__ : `/user/2fa/login`

__Method__ : `POST`

__Auth required__ : No

__Data input__ : `body : { totp, token }`

| Field | Type | Description | Required |
|:----- |:---- | :---------- |:-------- |
| totp| string |The 6-digit TOTP code from the authenticator app.| Yes |
| token | string | The temporary 2FA JWT token obtained from `/user/login`. | Yes| 

__Success Response Code__ :` 200 OK`

```JSON
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

# Error Responses for 2FA
__Condition__ : Invalid TOTP code provided.

__Code__ : `401 Unauthorized`

```JSON

{
    "message": "Invalid TOTP"
}
```
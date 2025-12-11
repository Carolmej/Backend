# GENERATE 2FA SECRET AND QR CODE
Generates a new TOTP secret for a user and returns the secret key and a QR code image (data URL) for linking with an authenticator app. This operation overwrites any existing secret.

_URL_ : `/user/2fa/generate`
_Method_ : `POST`
_Auth required_ : No
_Data input_ : `body : { user_id }`

| Field | Type | Description | Required |
| :---- | :--- | :---------- | :------ |
| `user_id` | integer | ID of the user | **Yes** |

_Success Response Code_ : `200 OK`

```json
{
    "secret": "JBSWY3DPEHPK3PXP",
    "qrImage": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAA[...]ElFTkSuQmCC"
}

# OAuth Service

The `oauth-service` is an authentication and authorization service built with Go. It provides secure and reliable
endpoints for user authentication, registration, token validation, refresh, and public key retrieval. It supports
JWT-based authentication and refresh tokens to manage user sessions securely.

---

## Features

- **User Registration**: Allows new users to register with unique usernames and emails.
- **User Login**: Generates an access token and refresh token for authenticated users.
- **Token Validation**: Validates JWT access tokens to ensure they are not expired or tampered with.
- **Token Refresh**: Provides a new access token and refresh token using an existing valid refresh token.
- **Logout**: Invalidates a user's refresh token to log them out securely.
- **Public Key Retrieval**: Allows clients to retrieve the public key used for validating JWT tokens.
- **Unregister**: Allows users to delete their account and all associated data.

---

## Endpoints

### **1. User Registration**

**Endpoint:** `/register`  
**Method:** `POST`  
**Description:** Registers a new user in the system.

**Request Body:**

```json
{
  "username": "exampleUser",
  "email": "example@example.com",
  "password": "securepassword"
}
```

**Response:**

```json
{
  "user": {
    "id": "uuid",
    "username": "exampleUser",
    "email": "example@example.com",
    "created_at": "2024-12-22T00:00:00Z"
  },
  "access_token": "jwt-token",
  "refresh_token": "refresh-token"
}
```

---

### **2. User Login**

**Endpoint:** `/login`  
**Method:** `POST`  
**Description:** Authenticates a user and generates access and refresh tokens.

**Request Body:**

```json
{
  "username": "exampleUser",
  "password": "securepassword"
}
```

**Response:**

```json
{
  "access_token": "jwt-token",
  "refresh_token": "refresh-token"
}
```

---

### **3. Token Validation**

**Endpoint:** `/validate`  
**Method:** `POST`  
**Description:** Validates if the provided JWT access token is still valid.

**Request Body:**

```json
{
  "token": "jwt-token"
}
```

**Response:**

```json
{
  "valid": true
}
```

---

### **4. Token Refresh**

**Endpoint:** `/refresh`  
**Method:** `POST`  
**Description:** Generates a new access and refresh token using an existing valid refresh token.

**Request Body:**

```json
{
  "refresh_token": "refresh-token"
}
```

**Response:**

```json
{
  "access_token": "new-jwt-token",
  "refresh_token": "new-refresh-token"
}
```

---

### **5. Logout**

**Endpoint:** `/logout`  
**Method:** `POST`  
**Description:** Logs out a user by invalidating their refresh token.

**Request Body:**

```json
{
  "refresh_token": "refresh-token"
}
```

**Response:**

```json
{
  "message": "Logged out successfully"
}
```

---

### **6. Public Key Retrieval**

**Endpoint:** `/public-key`  
**Method:** `GET`  
**Description:** Retrieves the public key used to validate JWT tokens.

**Response:**

```json
{
  "public_key": "publicKey"
}
```

---

### **7. Unregister**

**Endpoint:** `/unregister`  
**Method:** `DELETE`  
**Description:** Allows a user to delete their account and all associated data.

**Request Body:**

```json
{
  "username": "exampleUser",
  "password": "securepassword"
}
```

**Response:**

```json
{
  "message": "User unregistered successfully"
}
```

---

## Environment Variables

The following environment variables are used to configure the OAuth service:

| Variable Name          | Required          | Description                                               | Example Value                       |
|------------------------|-------------------|-----------------------------------------------------------|-------------------------------------|
| `DB_TYPE`              | Yes               | Database type                                             | `postgres`                          |
| `DB_HOST`              | Yes               | Database host address                                     | `auth-db`                           |
| `DB_PORT`              | Yes               | Database port                                             | `5432`                              |
| `DB_USER`              | Yes               | Database username                                         | `user`                              |
| `DB_PASSWORD`          | Yes               | Database password                                         | `password`                          |
| `DB_NAME`              | Yes               | Name of the database                                      | `auth`                              |
| `ACCESS_TOKEN_EXPIRY`  | No                | Access token expiration duration in seconds               | `3600` (default 1 hour)             |
| `REFRESH_TOKEN_EXPIRY` | No                | Refresh token expiration duration in seconds              | `604800` (default 7 days)           |
| `SERVICE_NAME`         | Yes               | Name of the service (used in token claims)                | `oauth-service`                     |
| `PUBLIC_KEY_PATH`      | Yes               | Path to the public key for JWT validation                 | `/run/secrets/public.key`           |
| `PRIVATE_KEY_PATH`     | Required (One of) | Path to the private key for JWT signing                   | `/run/secrets/private.key`          |
| `REFRESH_KEY_PATH`     | Required (One of) | Path to the refresh key for refresh token validation      | `/run/secrets/refresh.key`          |
| `PRIVATE_KEY`          | Required (One of) | The actual private key value for JWT signing              | (Use instead of `PRIVATE_KEY_PATH`) |
| `REFRESH_KEY`          | Required (One of) | The actual refresh key value for refresh token validation | (Use instead of `REFRESH_KEY_PATH`) |

### Notes on Key Configuration

- **PRIVATE_KEY_PATH** or **PRIVATE_KEY**: One of these is required. Specify either the path to the private key file (
  `PRIVATE_KEY_PATH`) or directly provide the private key as a string using the `PRIVATE_KEY` environment variable.
- **REFRESH_KEY_PATH** or **REFRESH_KEY**: One of these is required. Specify either the path to the refresh key file (
  `REFRESH_KEY_PATH`) or directly provide the refresh key as a string using the `REFRESH_KEY` environment variable.
- **PUBLIC_KEY_PATH**: Always required to specify the path to the public key used for JWT validation.

---



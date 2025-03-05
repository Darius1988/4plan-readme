# API Endpoints Documentation
Host: `https://api4plan.burbulis.lt`

## Authentication

### Get secret key for future registration request

- **REQUEST**: `POST` to `/api/auth/token`
- **RESPONSE**:

```json
{
  "uuid": "1234567890",
  "key": "1234567890"
}
```

### Register

- **REQUEST**: `POST` to `/api/auth/register`
- **DATA**:

```json
{
  "name": "John Doe",
  "surname": "Doe",
  "email": "test@test.com",
  "password": "Password.123",
  "token": {
    uuid: {{uuid}}, // From previous request
    data: {{encoded_data}} // Encoded data with key from previous request
  }
}
```

`encoded_data` - {name, surname, email, password} encoded with `encodeDataWithSecretToken(encoded_data, secretKey)`  
`secretKey` - `key` from `/api/auth/token` request

- **RESPONSE**:

```json
{
  "success": true,
  "message": "User registered successfully",
  "email": "test@test.com"
}
```

### Validate registration

- **REQUEST**: `POST` to `/api/auth/register/validate`
- **DATA**:

```json
{
  "token": "123456",
  "email": "test@test.com"
}
```

- **RESPONSE HEADER**:

```json
{
  "x-auth": "{{authToken}}"
}
```

- **RESPONSE BODY**:

```json
{
  "id": 1,
  "name": "John Doe",
  "surname": "Doe",
  "email": "test@test.com",
  "licences": []
}
```

### Login

- **REQUEST**: `POST` to `/api/auth/login`
- **DATA**:

```json
{
  "email": "test@test.com",
  "password": "Password.123"
}
```

- **RESPONSE HEADER**:

```json
{
  "x-auth": "{{authToken}}"
}
```

- **RESPONSE BODY**:

```json
{
  "id": 1,
  "name": "John Doe",
  "surname": "Doe",
  "email": "test@test.com",
  "licences": []
}
```

### Apple login

- **REQUEST**: `POST` to `/api/auth/apple-login`
- **DATA**:

```json
{
  "accessToken": "1234567890"
}
```

- **RESPONSE HEADER**:

```json
{
  "x-auth": "{{authToken}}"
}
```

- **RESPONSE BODY**:

```json
{
  "id": 1,
  "name": "John Doe",
  "surname": "Doe",
  "email": "test@test.com",
  "licences": []
}
```

### Password reminder

- **REQUEST**: `POST` to `/api/auth/password-reminder`
- **DATA**:

```json
{
  "email": "test@test.com"
}
```

- **RESPONSE**:

```json
{
  "success": true,
  "message": "Password reminder sent successfully"
}
```

### Validate password reminder

- **REQUEST**: `POST` to `/api/auth/password-reminder/validate`
- **DATA**:

```json
{
  "token": "123456",
  "email": "test@test.com"
}
```

- **RESPONSE**:

```json
{
  "success": true,
  "message": "Password reminder validated successfully"
}
```

### Reset password

- **REQUEST**: `POST` to `/api/auth/password-reset`
- **DATA**:

```json
{
  "token": "123456",
  "email": "test@test.com",
  "password": "Password.123"
}
```

- **RESPONSE**:

```json
{
  "success": true,
  "message": "Password reset successfully"
}
```

### Get user

- **REQUEST**: `GET` to `/api/user/me`

- **RESPONSE BODY**:

```json
{
  "id": 1,
  "name": "John Doe",
  "surname": "Doe",
  "email": "test@test.com",
  "licences": []
}
```

### Get user licenses

- **REQUEST**: `GET` to `/api/user/licenses`

### Post user license

- **REQUEST**: `POST` to `/api/user/licenses`
- **DATA**:

```json
{
  "type": "apple",
  "data": "{{encodedData}}"
}
```

License structure:
```json
{
  "subId": "xxxxxx",
  "productId": "productId (mponghtl memebrship)"
  "expiresAt": "Date of expireation"
}
```

Function to encode post data with secret key:

```
const encodeDataWithSecretToken = (data, secretToken) => {
    // Generate random IV
    const iv = crypto.randomBytes(16);
    // Create key buffer from secret token
    const key = crypto.scryptSync(secretToken, 'salt', 32);
    const cipher = crypto.createCipheriv('aes-256-ctr', key, iv);
    const jsonData = JSON.stringify(data);
    let encodedData = cipher.update(jsonData, 'utf8', 'hex');
    encodedData += cipher.final('hex');
    // Prepend IV to encoded data
    return iv.toString('hex') + encodedData;
}
```

Same function in swift (not tested):

```
import Foundation
import CryptoKit

func encodeDataWithSecretToken<T: Encodable>(_ data: T, secretToken: String) -> String? {
    // Convert secret token to key using PBKDF2 (similar to scryptSync)
    let salt = "salt".data(using: .utf8)! // Use a proper salt in production
    let key = deriveKey(from: secretToken, salt: salt, keyLength: 32)

    // Generate a random IV (Initialization Vector)
    var iv = Data(count: 16)
    _ = iv.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 16, $0.baseAddress!) }

    // Convert data to JSON string
    guard let jsonData = try? JSONEncoder().encode(data),
          let jsonString = String(data: jsonData, encoding: .utf8) else {
        return nil
    }

    // Encrypt data using AES-256-CTR
    guard let encryptedData = aesEncrypt(data: jsonString.data(using: .utf8)!, key: key, iv: iv) else {
        return nil
    }

    // Prepend IV to encrypted data
    let combinedData = iv + encryptedData
    return combinedData.base64EncodedString()
}

// Derive a 256-bit key using PBKDF2 (Password-Based Key Derivation Function 2)
func deriveKey(from password: String, salt: Data, keyLength: Int) -> Data {
    let passwordData = password.data(using: .utf8)!
    var key = Data(repeating: 0, count: keyLength)

    key.withUnsafeMutableBytes { keyBytes in
        salt.withUnsafeBytes { saltBytes in
            _ = CCKeyDerivationPBKDF(
                CCPBKDFAlgorithm(kCCPBKDF2),
                password, passwordData.count,
                saltBytes.baseAddress?.assumingMemoryBound(to: UInt8.self), salt.count,
                CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                10000, // Iterations (adjust based on security/performance needs)
                keyBytes.baseAddress?.assumingMemoryBound(to: UInt8.self), keyLength
            )
        }
    }
    return key
}

// AES-256-CTR encryption function
func aesEncrypt(data: Data, key: Data, iv: Data) -> Data? {
    let algorithm = kCCAlgorithmAES
    let options = kCCModeCTR

    var cryptData = Data(count: data.count)
    var numBytesEncrypted: size_t = 0

    let cryptStatus = cryptData.withUnsafeMutableBytes { cryptBytes in
        data.withUnsafeBytes { dataBytes in
            iv.withUnsafeBytes { ivBytes in
                key.withUnsafeBytes { keyBytes in
                    CCCrypt(
                        CCOperation(kCCEncrypt),
                        CCAlgorithm(algorithm),
                        CCOptions(options),
                        keyBytes.baseAddress, key.count,
                        ivBytes.baseAddress,
                        dataBytes.baseAddress, data.count,
                        cryptBytes.baseAddress, cryptData.count,
                        &numBytesEncrypted
                    )
                }
            }
        }
    }

    if cryptStatus == kCCSuccess {
        return cryptData.prefix(numBytesEncrypted)
    } else {
        return nil
    }
}
```

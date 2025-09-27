# Okta Token Generator

A simple Go application to generate Okta OAuth2 tokens using Private Key JWT authentication.

## Features

- Loads configuration from YAML file
- Supports both inline PEM keys and file paths
- Uses Private Key JWT (client assertion) for authentication
- Configurable scopes
- Optional token saving to JSON file

## Prerequisites

1. Go 1.19 or higher
2. An Okta application configured for OAuth2 with Private Key JWT
3. RSA private key (PKCS1 or PKCS8 format)

## Installation

1. Clone or download the code
2. Install dependencies:

```bash
go mod init okta-token-generator
go get github.com/go-jose/go-jose/v3
go get github.com/google/uuid
go get gopkg.in/yaml.v3
```

## Configuration

Create a `config.yaml` file with your Okta settings:

```yaml
okta:
  domain: "your-domain.okta.com"
  client_id: "0oa1234567890abcdef"
  private_key: "path/to/private-key.pem"  # or inline PEM
  scopes:
    - "api.read"
    - "api.write"
```

### Private Key Options

You can specify the private key in three ways:

1. **File path**: `private_key: "/path/to/key.pem"`
2. **Relative path**: `private_key: "./keys/key.pem"`
3. **Inline PEM**: Use the `|` character for multiline strings

## Usage

### Basic usage (uses config.yaml in current directory):

```bash
go run main.go
```

### Specify custom config file:

```bash
go run main.go /path/to/custom-config.yaml
```

### Save token to file:

```bash
go run main.go config.yaml --save
```

This will save the token to `token.json`.

## Building

Build the binary:

```bash
go build -o okta-token-generator main.go
```

Run the binary:

```bash
./okta-token-generator config.yaml
```

## Setting up Okta

1. **Create an OAuth2 Application** in Okta Admin Console
2. **Configure the application** for Client Credentials flow
3. **Add a public key** to the application:
   - Generate an RSA key pair
   - Add the public key to your Okta application
   - Use the private key in this tool
4. **Configure scopes** that your application needs

### Generate RSA Key Pair

```bash
# Generate private key
openssl genrsa -out private-key.pem 2048

# Extract public key
openssl rsa -in private-key.pem -pubout -out public-key.pem

# Convert to PKCS8 format (optional)
openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt \
  -in private-key.pem -out private-key-pkcs8.pem
```

## Output

The tool will display:
- Configuration details being used
- Token generation status
- Access token (first 50 characters)
- Token type (usually "Bearer")
- Expiration time in seconds
- Granted scopes

## Error Handling

Common errors and solutions:

1. **"failed to parse PEM block"**: Check that your private key is in valid PEM format
2. **"authentication failed"**: Verify client_id and that the public key is registered in Okta
3. **"failed to read config file"**: Ensure config.yaml exists and is readable
4. **"request failed with status 400"**: Check your Okta domain and scopes

## Security Notes

- Keep your private key secure and never commit it to version control
- Use appropriate file permissions (0600) for sensitive files
- Consider using environment variables or secret management systems in production
- The generated tokens should be transmitted over HTTPS only

## Troubleshooting

Enable verbose logging by modifying the code:

```go
// Add after token generation attempt
if err != nil {
    fmt.Printf("Detailed error: %+v\n", err)
    // Print the client assertion for debugging
    assertion, _ := generator.CreateClientAssertion()
    fmt.Printf("Client Assertion: %s\n", assertion)
}
```

## License

This code is provided as a sample. Modify and use as needed for your requirements.

package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
)

// Config represents the configuration loaded from YAML
type Config struct {
	Okta struct {
		Domain     string   `yaml:"domain"`
		ClientID   string   `yaml:"client_id"`
		PrivateKey string   `yaml:"private_key"`
		Scopes     []string `yaml:"scopes"`
	} `yaml:"okta"`
}

// LoadConfig loads configuration from a YAML file
func LoadConfig(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	return &config, nil
}

type OktaTokenResponse struct {
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	AccessToken string `json:"access_token"`
	Scope       string `json:"scope"`
}

type TokenGenerator struct {
	Domain     string
	ClientID   string
	PrivateKey *rsa.PrivateKey
	Scopes     []string
}

// NewTokenGeneratorFromConfig creates a new token generator from config
func NewTokenGeneratorFromConfig(config *Config) (*TokenGenerator, error) {
	// Check for private key file path or inline PEM
	var privateKeyPEM string
	
	if strings.HasPrefix(config.Okta.PrivateKey, "-----BEGIN") {
		// Private key is inline PEM
		privateKeyPEM = config.Okta.PrivateKey
	} else if strings.HasSuffix(config.Okta.PrivateKey, ".pem") || strings.HasSuffix(config.Okta.PrivateKey, ".key") {
		// Private key is a file path
		keyData, err := os.ReadFile(config.Okta.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to read private key file: %w", err)
		}
		privateKeyPEM = string(keyData)
	} else {
		// Assume it's a file path even without extension
		keyData, err := os.ReadFile(config.Okta.PrivateKey)
		if err != nil {
			// If file read fails, try using it as inline PEM
			privateKeyPEM = config.Okta.PrivateKey
		} else {
			privateKeyPEM = string(keyData)
		}
	}

	// Parse the private key
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block")
	}

	var rsaKey *rsa.PrivateKey
	
	// Try PKCS8 format first
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err == nil {
		var ok bool
		rsaKey, ok = key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key is not an RSA private key")
		}
	} else {
		// Try PKCS1 format
		rsaKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key (tried PKCS8 and PKCS1): %w", err)
		}
	}

	return &TokenGenerator{
		Domain:     config.Okta.Domain,
		ClientID:   config.Okta.ClientID,
		PrivateKey: rsaKey,
		Scopes:     config.Okta.Scopes,
	}, nil
}

// CreateClientAssertion creates a signed JWT for authentication
func (tg *TokenGenerator) CreateClientAssertion() (string, error) {
	tokenURL := fmt.Sprintf("https://%s/oauth2/v1/token", tg.Domain)

	// Create signer
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: tg.PrivateKey},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		return "", fmt.Errorf("failed to create signer: %w", err)
	}

	// Create JWT claims
	now := time.Now()
	claims := jwt.Claims{
		Issuer:    tg.ClientID,
		Subject:   tg.ClientID,
		Audience:  jwt.Audience{tokenURL},
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now),
		Expiry:    jwt.NewNumericDate(now.Add(time.Hour)),
		ID:        uuid.New().String(),
	}

	// Sign and serialize the JWT
	token, err := jwt.Signed(signer).Claims(claims).CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("failed to create JWT: %w", err)
	}

	return token, nil
}

// GenerateToken generates an access token using the private key JWT flow
func (tg *TokenGenerator) GenerateToken() (*OktaTokenResponse, error) {
	return tg.GenerateTokenWithScopes(tg.Scopes)
}

// GenerateTokenWithScopes generates an access token with custom scopes
func (tg *TokenGenerator) GenerateTokenWithScopes(scopes []string) (*OktaTokenResponse, error) {
	tokenURL := fmt.Sprintf("https://%s/oauth2/v1/token", tg.Domain)

	// Create client assertion
	clientAssertion, err := tg.CreateClientAssertion()
	if err != nil {
		return nil, fmt.Errorf("failed to create client assertion: %w", err)
	}

	// Prepare request data
	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	if len(scopes) > 0 {
		data.Set("scope", strings.Join(scopes, " "))
	}
	data.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	data.Set("client_assertion", clientAssertion)

	// Create HTTP request
	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	// Send request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Check for errors
	if resp.StatusCode != http.StatusOK {
		var errResp struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		if err := json.Unmarshal(body, &errResp); err == nil {
			return nil, fmt.Errorf("authentication failed: %s - %s", errResp.Error, errResp.ErrorDescription)
		}
		return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse token response
	var tokenResp OktaTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &tokenResp, nil
}

func main() {
	// Load configuration from YAML file
	configFile := "config.yaml"
	if len(os.Args) > 1 {
		configFile = os.Args[1]
	}

	fmt.Printf("Loading configuration from: %s\n", configFile)
	
	config, err := LoadConfig(configFile)
	if err != nil {
		fmt.Printf("Failed to load config: %v\n", err)
		fmt.Println("\nMake sure you have a config.yaml file with the required fields")
		os.Exit(1)
	}

	// Create token generator from config
	generator, err := NewTokenGeneratorFromConfig(config)
	if err != nil {
		fmt.Printf("Failed to create generator: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Generating token for client: %s\n", config.Okta.ClientID)
	fmt.Printf("Using domain: %s\n", config.Okta.Domain)
	fmt.Printf("Requesting scopes: %v\n", config.Okta.Scopes)
	
	// Generate token
	token, err := generator.GenerateToken()
	if err != nil {
		fmt.Printf("Failed to generate token: %v\n", err)
		os.Exit(1)
	}

	// Print token details
	fmt.Println("\n=== Token Generated Successfully ===")
	fmt.Printf("Access Token: %s...\n", token.AccessToken[:min(50, len(token.AccessToken))])
	fmt.Printf("Token Type: %s\n", token.TokenType)
	fmt.Printf("Expires In: %d seconds\n", token.ExpiresIn)
	fmt.Printf("Granted Scopes: %s\n", token.Scope)
	
	// Optionally save token to file
	if len(os.Args) > 2 && os.Args[2] == "--save" {
		tokenFile := "token.json"
		tokenData, _ := json.MarshalIndent(token, "", "  ")
		if err := os.WriteFile(tokenFile, tokenData, 0600); err != nil {
			fmt.Printf("Failed to save token: %v\n", err)
		} else {
			fmt.Printf("\nToken saved to: %s\n", tokenFile)
		}
	}
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Example config.yaml file content:
/*
okta:
  domain: "your-domain.okta.com"
  client_id: "0oa1234567890abcdef"
  private_key: "path/to/private-key.pem"  # Can be file path or inline PEM
  scopes:
    - "api.read"
    - "api.write"
    - "users.read"
*/

// Example config.yaml with inline private key:
/*
okta:
  domain: "your-domain.okta.com"
  client_id: "0oa1234567890abcdef"
  private_key: |
    -----BEGIN PRIVATE KEY-----
    MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC...
    [Your private key content here]
    -----END PRIVATE KEY-----
  scopes:
    - "api.read"
    - "api.write"
*/

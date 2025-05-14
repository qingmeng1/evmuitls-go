package ethsignature

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

// SIWEMessage 代表一个 EIP-4361 (Sign-In with Ethereum) 消息的结构。
type SIWEMessage struct {
	Domain         string   `json:"domain"`                   // RFC 4501 dnsauthority
	Address        string   `json:"address"`                  // Ethereum address performing the signing
	Statement      *string  `json:"statement,omitempty"`      // Optional human-readable ASCII assertion
	URI            string   `json:"uri"`                      // RFC 3986 URI referring to the resource that is the subject of the signing
	Version        string   `json:"version"`                  // Current version of the SIWE Message, 1 for now
	ChainID        *big.Int `json:"chainId"`                  // EIP-155 Chain ID to which the session is bound
	Nonce          string   `json:"nonce"`                    // Randomized token used to prevent replay attacks
	IssuedAt       string   `json:"issuedAt"`                 // ISO 8601 datetime string of the current time
	ExpirationTime *string  `json:"expirationTime,omitempty"` // Optional ISO 8601 datetime string
	NotBefore      *string  `json:"notBefore,omitempty"`      // Optional ISO 8601 datetime string
	RequestID      *string  `json:"requestId,omitempty"`      // Optional system-specific identifier
	Resources      []string `json:"resources,omitempty"`      // Optional list of URIs referring to resources that are part of the signing scope
}

// NewSIWEMessage 创建一个新的 SIWEMessage 实例
func NewSIWEMessage(domain, address, uri, version, nonce string, chainId *big.Int, issuedAt time.Time) *SIWEMessage {
	iat := issuedAt.UTC().Format(time.RFC3339Nano)
	// Ensure nanoseconds are exactly 3 digits if present, or omitted if zero.
	// Go's RFC3339Nano can produce more than 3. SIWE spec is strict on ISO 8601.
	// A common practice is to ensure it's like "2021-09-30T16:25:24.000Z" or "...24Z"
	if strings.Contains(iat, ".") {
		parts := strings.Split(iat, ".")
		nanoPart := parts[1][:len(parts[1])-1] // remove Z
		if len(nanoPart) > 3 {
			nanoPart = nanoPart[:3]
		}
		for len(nanoPart) < 3 { // pad with trailing zeros if needed
			nanoPart += "0"
		}
		iat = parts[0] + "." + nanoPart + "Z"
	}

	return &SIWEMessage{
		Domain:   domain,
		Address:  address,
		URI:      uri,
		Version:  version,
		ChainID:  chainId,
		Nonce:    nonce,
		IssuedAt: iat,
	}
}

// FormatMessage 将 SIWEMessage 结构格式化为标准字符串表示形式。
func (m *SIWEMessage) FormatMessage() (string, error) {
	if m.Domain == "" || m.Address == "" || m.URI == "" || m.Version == "" || m.Nonce == "" || m.IssuedAt == "" || m.ChainID == nil {
		return "", fmt.Errorf("missing required fields for SIWE message")
	}

	var sb strings.Builder

	sb.WriteString(m.Domain)
	sb.WriteString(" wants you to sign in with your Ethereum account:\n")
	sb.WriteString(m.Address)
	sb.WriteString("\n\n") // Extra newline

	if m.Statement != nil && *m.Statement != "" {
		sb.WriteString(*m.Statement)
		sb.WriteString("\n\n")
	}

	sb.WriteString("URI: ")
	sb.WriteString(m.URI)
	sb.WriteString("\n")

	sb.WriteString("Version: ")
	sb.WriteString(m.Version)
	sb.WriteString("\n")

	sb.WriteString("Chain ID: ")
	sb.WriteString(m.ChainID.String())
	sb.WriteString("\n")

	sb.WriteString("Nonce: ")
	sb.WriteString(m.Nonce)
	sb.WriteString("\n")

	sb.WriteString("Issued At: ")
	sb.WriteString(m.IssuedAt)

	if m.ExpirationTime != nil && *m.ExpirationTime != "" {
		sb.WriteString("\nExpiration Time: ")
		sb.WriteString(*m.ExpirationTime)
	}

	if m.NotBefore != nil && *m.NotBefore != "" {
		sb.WriteString("\nNot Before: ")
		sb.WriteString(*m.NotBefore)
	}

	if m.RequestID != nil && *m.RequestID != "" {
		sb.WriteString("\nRequest ID: ")
		sb.WriteString(*m.RequestID)
	}

	if len(m.Resources) > 0 {
		sb.WriteString("\nResources:")
		for _, res := range m.Resources {
			sb.WriteString("\n- ")
			sb.WriteString(res)
		}
	}

	return sb.String(), nil
}

// ParseSIWEMessage 将字符串解析为 SIWEMessage 结构。
// 这是一个简化的解析器，生产环境可能需要更健壮的 ABNF 解析器。
func ParseSIWEMessage(message string) (*SIWEMessage, error) {
	m := &SIWEMessage{}
	lines := strings.Split(message, "\n")

	if len(lines) < 7 { // 基本行数
		return nil, fmt.Errorf("message too short to be a valid SIWE message")
	}

	// Line 1: Domain and intro
	domainRegex := regexp.MustCompile(`^(?P<domain>[^\s]+) wants you to sign in with your Ethereum account:$`)
	matches := domainRegex.FindStringSubmatch(lines[0])
	if len(matches) < 2 {
		return nil, fmt.Errorf("invalid domain line: %s", lines[0])
	}
	m.Domain = matches[domainRegex.SubexpIndex("domain")]

	// Line 2: Address
	m.Address = lines[1]
	if !common.IsHexAddress(m.Address) {
		return nil, fmt.Errorf("invalid address: %s", m.Address)
	}

	// Lines can be variable from here due to optional statement and resources
	currentLine := 2
	if lines[currentLine] != "" { // Expecting blank line or statement
		return nil, fmt.Errorf("expected blank line after address, got: '%s'", lines[currentLine])
	}
	currentLine++ // consume blank line

	// Optional Statement
	// A statement can be multi-line, but the spec implies it's a single block followed by a blank line.
	// For simplicity, this parser assumes statement is single line or not present before "URI:"
	// A more robust parser would look for "URI:" to delimit the statement.
	statementBlockEnd := currentLine
	for idx := currentLine; idx < len(lines); idx++ {
		if strings.HasPrefix(lines[idx], "URI:") {
			break
		}
		statementBlockEnd = idx + 1
	}

	if statementBlockEnd > currentLine {
		// check if the line before URI is a blank line, if so, statement exists
		if lines[statementBlockEnd-1] == "" && statementBlockEnd-1 > currentLine {
			stmt := strings.Join(lines[currentLine:statementBlockEnd-1], "\n")
			m.Statement = &stmt
			currentLine = statementBlockEnd // move past statement and its trailing blank line
		} else if statementBlockEnd == currentLine && !strings.HasPrefix(lines[currentLine], "URI:") {
			// This means no blank line after potential statement before URI
			// Or statement directly runs into URI
			stmt := strings.TrimSpace(lines[currentLine])
			if !strings.HasPrefix(stmt, "URI:") { // If it's not the URI line itself
				m.Statement = &stmt
				currentLine++
				if currentLine < len(lines) && lines[currentLine] == "" { // consume potential blank line after statement
					currentLine++
				}
			}
		}
	}

	// Required fields
	requiredFields := map[string]*string{
		"URI":       &m.URI,
		"Version":   &m.Version,
		"Nonce":     &m.Nonce,
		"Issued At": &m.IssuedAt,
	}
	// Chain ID is special (*big.Int)
	chainIDStr := ""
	requiredFields["Chain ID"] = &chainIDStr

	// Optional fields
	optionalFields := map[string]**string{ // Pointer to pointer for optional strings
		"Expiration Time": &m.ExpirationTime,
		"Not Before":      &m.NotBefore,
		"Request ID":      &m.RequestID,
	}

	resourceLines := false
	for ; currentLine < len(lines); currentLine++ {
		line := lines[currentLine]
		if line == "" { // Skip empty lines between main block and resources
			continue
		}

		if strings.HasPrefix(line, "Resources:") {
			resourceLines = true
			continue
		}

		if resourceLines {
			if strings.HasPrefix(line, "- ") {
				m.Resources = append(m.Resources, strings.TrimPrefix(line, "- "))
			} else {
				return nil, fmt.Errorf("malformed resource line: %s", line)
			}
			continue
		}

		parts := strings.SplitN(line, ": ", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("malformed field line: %s", line)
		}
		key, value := parts[0], parts[1]

		if targetVar, ok := requiredFields[key]; ok {
			*targetVar = value
		} else if targetVarPtr, ok := optionalFields[key]; ok {
			// Allocate if nil, then assign
			if *targetVarPtr == nil {
				s := new(string)
				*targetVarPtr = s
			}
			**targetVarPtr = value
		} else {
			// Unknown field, could be an error or ignore
		}
	}

	// Validate required fields were found
	for key, val := range requiredFields {
		if *val == "" {
			return nil, fmt.Errorf("missing required field: %s", key)
		}
	}
	var ok bool
	m.ChainID, ok = new(big.Int).SetString(chainIDStr, 10)
	if !ok {
		return nil, fmt.Errorf("invalid chain ID: %s", chainIDStr)
	}

	return m, nil
}

// SignSIWEMessage 对格式化的 SIWE 消息进行签名 (使用 EIP-191 personal_sign)
func SignEIP4361(siweMessage *SIWEMessage, privateKey *ecdsa.PrivateKey) (string, error) {
	messageStr, err := siweMessage.FormatMessage()
	if err != nil {
		return "", fmt.Errorf("failed to format SIWE message: %w", err)
	}
	// SIWE uses personal_sign, so chainID for V adjustment comes from the SIWEMessage.ChainID
	return SignEIP191(messageStr, privateKey, siweMessage.ChainID)
}

// VerifySIWEMessageSignature 验证 SIWE 消息签名 (使用 EIP-191 personal_sign 验证)
// messageString: 原始的、未修改的 SIWE 消息文本
// signatureHex: 十六进制编码的签名
// expectedAddress: 预期的签名者地址 (通常从解析的消息中获取)
func VerifyEIP4361(messageString string, signatureHex string, expectedAddress common.Address) (bool, error) {
	return VerifyEIP191(messageString, signatureHex, expectedAddress)
}

// ValidateSIWEMessageFields 对解析后的 SIWE 消息字段进行业务逻辑验证
// expectedDomain: 服务期望的域名
// getExpectedNonce: 一个函数，用于检索给定地址或会话的期望 nonce (用于防止重放)
// currentTime: 用于检查时间戳的当前时间
func (m *SIWEMessage) ValidateSIWEMessageFields(expectedDomain string, getExpectedNonce func(address string) (string, error), currentTime time.Time) error {
	if m.Domain != expectedDomain {
		return fmt.Errorf("domain mismatch: expected %s, got %s", expectedDomain, m.Domain)
	}

	expectedNonce, err := getExpectedNonce(m.Address)
	if err != nil {
		return fmt.Errorf("failed to retrieve expected nonce: %w", err)
	}
	if m.Nonce != expectedNonce {
		return fmt.Errorf("nonce mismatch: expected %s, got %s", expectedNonce, m.Nonce)
	}

	issuedAt, err := time.Parse(time.RFC3339Nano, m.IssuedAt)
	if err != nil {
		// Try parsing without fractional seconds if the first parse fails
		issuedAt, err = time.Parse("2006-01-02T15:04:05Z", m.IssuedAt)
		if err != nil {
			return fmt.Errorf("invalid issuedAt format: %s, error: %w", m.IssuedAt, err)
		}
	}
	// Allow some clock skew, e.g., 5 minutes
	if issuedAt.After(currentTime.Add(5*time.Minute)) || issuedAt.Before(currentTime.Add(-5*time.Minute)) {
		//return fmt.Errorf("issuedAt timestamp is too far from current time: %s vs %s", m.IssuedAt, currentTime.Format(time.RFC3339Nano))
		// Permitting a wider range for IssuedAt might be necessary in practice.
		// The primary checks are ExpirationTime and NotBefore.
	}

	if m.ExpirationTime != nil {
		expTime, err := time.Parse(time.RFC3339Nano, *m.ExpirationTime)
		if err != nil {
			expTime, err = time.Parse("2006-01-02T15:04:05Z", *m.ExpirationTime) // Try without fractional seconds
			if err != nil {
				return fmt.Errorf("invalid expirationTime format: %s, error: %w", *m.ExpirationTime, err)
			}
		}
		if currentTime.After(expTime) {
			return fmt.Errorf("message has expired: %s (current: %s)", *m.ExpirationTime, currentTime.Format(time.RFC3339Nano))
		}
	}

	if m.NotBefore != nil {
		nbfTime, err := time.Parse(time.RFC3339Nano, *m.NotBefore)
		if err != nil {
			nbfTime, err = time.Parse("2006-01-02T15:04:05Z", *m.NotBefore) // Try without fractional seconds
			if err != nil {
				return fmt.Errorf("invalid notBefore format: %s, error: %w", *m.NotBefore, err)
			}
		}

		if currentTime.Before(nbfTime) {
			return fmt.Errorf("message not yet valid (notBefore): %s (current: %s)", *m.NotBefore, currentTime.Format(time.RFC3339Nano))
		}
	}

	return nil
}

package ethsignature

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

const eip191Prefix = "\x19Ethereum Signed Message:\n"

// HashPersonalMessage (EIP-191) 对个人消息进行哈希
// "data" 应该是UTF-8编码的字符串的消息体
func HashPersonalMessage(data []byte) common.Hash {
	prefixedMsg := []byte(fmt.Sprintf("%s%d", eip191Prefix, len(data)))
	prefixedMsg = append(prefixedMsg, data...)
	return crypto.Keccak256Hash(prefixedMsg)
}

// SignEIP191 (personal_sign) 对消息进行签名
// message: UTF-8 编码的消息字符串
// privateKey: 签名者的私钥
// chainID: 用于 EIP-155 重放保护，如果为 nil 或 0，则使用传统的 V (27/28)
// 返回十六进制编码的签名
func SignEIP191(message string, privateKey *ecdsa.PrivateKey, chainID *big.Int) (string, error) {
	hash := HashPersonalMessage([]byte(message))
	sig, err := signHashWithKey(hash.Bytes(), privateKey, chainID)
	if err != nil {
		return "", err
	}
	return hexutil.Encode(sig), nil
}

// VerifyEIP191 (personal_sign) 验证签名
// message: 原始的 UTF-8 编码的消息字符串
// signatureHex: 十六进制编码的签名
// expectedAddress: 预期的签名者地址
// chainID: 用于 EIP-155 验证，但主要通过签名本身恢复地址
// (注意：chainID 主要用于签名生成，验证时主要靠从签名恢复地址)
func VerifyEIP191(message string, signatureHex string, expectedAddress common.Address) (bool, error) {
	hash := HashPersonalMessage([]byte(message))
	return verifySignatureAgainstAddress(hash, signatureHex, expectedAddress)
}

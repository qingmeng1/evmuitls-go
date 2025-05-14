package ethsignature

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

// GenerateKey 生成一个新的 ECDSA 密钥对
func GenerateKey() (*ecdsa.PrivateKey, error) {
	return crypto.GenerateKey()
}

// PrivateKeyToHex 将 ECDSA私钥转换为十六进制字符串
func PrivateKeyToHex(priv *ecdsa.PrivateKey) string {
	return hexutil.Encode(crypto.FromECDSA(priv))
}

// HexToPrivateKey 将十六进制字符串转换为 ECDSA私钥
func HexToPrivateKey(hexKey string) (*ecdsa.PrivateKey, error) {
	b, err := hexutil.Decode(hexKey)
	if err != nil {
		return nil, err
	}
	return crypto.ToECDSA(b)
}

// PublicKeyToAddress 从 ECDSA公钥派生以太坊地址
func PublicKeyToAddress(pub *ecdsa.PublicKey) common.Address {
	return crypto.PubkeyToAddress(*pub)
}

// signHash 对给定的哈希进行签名，并根据 chainID 调整 V 值 (EIP-155)
func signHashWithKey(hash []byte, prv *ecdsa.PrivateKey, chainID *big.Int) ([]byte, error) {
	sig, err := crypto.Sign(hash, prv)
	if err != nil {
		return nil, err
	}

	// crypto.Sign 返回的 V 是 0 或 1
	// 根据 EIP-155 进行调整
	if chainID != nil && chainID.Sign() > 0 {
		sig[64] = sig[64] + byte(chainID.Uint64()*2) + 35
	} else {
		sig[64] = sig[64] + 27 // Pre-EIP-155 V
	}
	return sig, nil
}

// verifySignature 验证签名是否由预期地址签署
// signatureHex 是包含调整后 V 的签名
func verifySignatureAgainstAddress(hash common.Hash, signatureHex string, expectedAddress common.Address) (bool, error) {
	sigBytes, err := hexutil.Decode(signatureHex)
	if err != nil {
		return false, fmt.Errorf("failed to decode signature: %w", err)
	}
	if len(sigBytes) != 65 {
		return false, fmt.Errorf("signature must be 65 bytes long, got %d", len(sigBytes))
	}

	// crypto.SigToPub 内部处理不同 V 值 (27, 28, EIP-155) 的规范化
	recoveredPubKey, err := crypto.SigToPub(hash.Bytes(), sigBytes)
	if err != nil {
		// 尝试不带 EIP-155 的传统 V 值 (27/28)
		// 有些钱包可能仍然会生成这种格式的 personal_sign，即使提供了 chainId
		var sigCopy [65]byte
		copy(sigCopy[:], sigBytes)
		if sigCopy[64] >= 35 { // 如果看起来像 EIP-155，尝试回退
			sigCopy[64] -= 35
			if sigCopy[64]%2 != 0 { // V should be 0 or 1 after removing offset part
				sigCopy[64] = (sigCopy[64] - 1) / 2 // V was 1
			} else {
				sigCopy[64] = sigCopy[64] / 2 // V was 0
			}
			sigCopy[64] += 27 // Convert to 27/28
		}
		recoveredPubKey, err = crypto.SigToPub(hash.Bytes(), sigCopy[:])
		if err != nil {
			return false, fmt.Errorf("failed to recover public key: %w", err)
		}
	}

	recoveredAddress := crypto.PubkeyToAddress(*recoveredPubKey)
	return recoveredAddress == expectedAddress, nil
}

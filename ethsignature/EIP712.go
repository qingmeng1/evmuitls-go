package ethsignature

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"math/big"
	"reflect"
	"sort"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

const eip712DomainType = "EIP712Domain"
const eip712PrefixBytes = "\x19\x01"

// EIP712Type 描述 EIP-712 结构中的一个字段类型
type EIP712Type struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// EIP712Types 是类型定义的映射
type EIP712Types map[string][]EIP712Type

// EIP712Domain 定义了签名的作用域
// 使用指针类型和 json.Number 来更好地处理可选字段和 JSON 解析
type EIP712Domain struct {
	Name              string          `json:"name,omitempty"`
	Version           string          `json:"version,omitempty"`
	ChainId           *json.Number    `json:"chainId,omitempty"` // 使用 json.Number 以灵活处理数字或字符串形式的 chainId
	VerifyingContract *common.Address `json:"verifyingContract,omitempty"`
	Salt              *string         `json:"salt,omitempty"` // 十六进制编码的 bytes32 字符串, e.g., "0x..."
}

// TypedData 是 EIP-712 签名的完整结构
type TypedData struct {
	Types       EIP712Types            `json:"types"`
	PrimaryType string                 `json:"primaryType"`
	Domain      EIP712Domain           `json:"domain"` // 可以直接使用结构体
	Message     map[string]interface{} `json:"message"`
}

// getDependencies 递归查找给定类型所依赖的所有唯一结构体类型。
func (td *TypedData) getDependencies(typeName string, allDependencies map[string]bool) {
	if allDependencies[typeName] {
		return
	}
	// 只有在 td.Types 中定义的类型才被认为是结构体依赖
	if _, isStruct := td.Types[typeName]; !isStruct {
		return
	}
	allDependencies[typeName] = true

	schema := td.Types[typeName] // 已经确认存在

	for _, field := range schema {
		baseFieldType := strings.TrimSuffix(field.Type, "[]") // 处理数组类型，获取元素类型
		// 递归查找，即使 baseFieldType 不是结构体，getDependencies 内部也会处理
		td.getDependencies(baseFieldType, allDependencies)
	}
}

// encodeType 为给定的主结构体类型生成 EIP-712 类型字符串。
// 例如："Mail(Person from,Person to,string contents)Person(string name,address wallet)"
func (td *TypedData) encodeType(primaryType string) (string, error) {
	allReferencedStructs := make(map[string]bool)
	td.getDependencies(primaryType, allReferencedStructs)

	// 从所有引用结构体中移除 primaryType 本身，以便对其余依赖进行排序
	// primaryType 的定义将首先出现
	delete(allReferencedStructs, primaryType)

	otherStructNames := make([]string, 0, len(allReferencedStructs))
	for name := range allReferencedStructs {
		if _, isStruct := td.Types[name]; isStruct { // 确保只添加在Types中定义的结构体
			otherStructNames = append(otherStructNames, name)
		}
	}
	sort.Strings(otherStructNames) // 按字母顺序对其他依赖结构体名称进行排序

	var result strings.Builder

	// 1. 添加主类型的定义
	primarySchema, ok := td.Types[primaryType]
	if !ok {
		return "", fmt.Errorf("primaryType '%s' not found in types definition", primaryType)
	}
	result.WriteString(primaryType)
	result.WriteString("(")
	for i, field := range primarySchema {
		if i > 0 {
			result.WriteString(",")
		}
		result.WriteString(field.Type)
		result.WriteString(" ")
		result.WriteString(field.Name)
	}
	result.WriteString(")")

	// 2. 按字母顺序追加其他依赖结构体的定义
	for _, depName := range otherStructNames {
		depSchema, ok := td.Types[depName] // 此时 depName 必然是已定义的结构体
		if !ok {                           // 理论上不应发生
			return "", fmt.Errorf("internal error: dependent type '%s' schema not found", depName)
		}
		result.WriteString(depName)
		result.WriteString("(")
		for i, field := range depSchema {
			if i > 0 {
				result.WriteString(",")
			}
			result.WriteString(field.Type)
			result.WriteString(" ")
			result.WriteString(field.Name)
		}
		result.WriteString(")")
	}
	return result.String(), nil
}

// typeHash 计算类型的 keccak256 哈希。
func (td *TypedData) typeHash(typeName string) (common.Hash, error) {
	encodedTypeStr, err := td.encodeType(typeName)
	if err != nil {
		return common.Hash{}, err
	}
	return crypto.Keccak256Hash([]byte(encodedTypeStr)), nil
}

// solidityTypeToAbiType 将 EIP-712 (类 Solidity) 类型字符串转换为 abi.Type。
func solidityTypeToAbiType(solType string) (abi.Type, error) {
	// 尝试直接使用 abi.NewType 解析，它能处理 "uint256", "address", "bytes32[]" 等
	abiTyp, err := abi.NewType(solType, "", nil)
	if err == nil {
		return abiTyp, nil
	}
	// 如果直接解析失败 (可能因为它不是一个有效的 Solidity ABI 类型字符串，例如 "Person")
	// 对于 EIP-712 中的自定义结构体名或无法直接映射的，此函数不应处理，
	// encodeData 中会对这些情况进行特殊处理 (例如递归调用 hashStruct)。
	return abi.Type{}, fmt.Errorf("cannot convert EIP-712 type '%s' to abi.Type for primitive encoding: %w", solType, err)
}

// encodeData 根据 EIP-712 规则对单个数据值进行编码，结果总是 bytes32。
func (td *TypedData) encodeData(fieldType string, value interface{}) ([]byte, error) {
	// 1. 数组类型
	if strings.HasSuffix(fieldType, "[]") {
		val := reflect.ValueOf(value)
		if val.Kind() != reflect.Slice {
			return nil, fmt.Errorf("expected slice for array type %s, got %T", fieldType, value)
		}

		elementType := strings.TrimSuffix(fieldType, "[]")
		var concatenatedElementsData bytes.Buffer
		for i := 0; i < val.Len(); i++ {
			elemVal := val.Index(i).Interface()
			encodedElem, err := td.encodeData(elementType, elemVal) // 每个元素编码为 bytes32
			if err != nil {
				return nil, fmt.Errorf("failed to encode array element %d for type %s: %w", i, fieldType, err)
			}
			if len(encodedElem) != 32 { // 防御性检查
				return nil, fmt.Errorf("internal error: encoded array element is not 32 bytes (type: %s, index: %d)", elementType, i)
			}
			concatenatedElementsData.Write(encodedElem)
		}
		hashedArray := crypto.Keccak256(concatenatedElementsData.Bytes())
		return hashedArray, nil
	}

	// 2. 自定义结构体类型 (在 TypedData.Types 中定义)
	if _, isCustomStruct := td.Types[fieldType]; isCustomStruct {
		mapValue, ok := value.(map[string]interface{})
		if !ok {
			// 尝试通过 JSON 序列化/反序列化来转换
			jsonBytes, err := json.Marshal(value)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal struct value for custom type '%s': %w", fieldType, err)
			}
			err = json.Unmarshal(jsonBytes, &mapValue)
			if err != nil {
				return nil, fmt.Errorf("value for custom type '%s' is not map[string]interface{} or compatible struct (type: %T): %w", fieldType, value, err)
			}
		}
		hashedStruct, err := td.hashStruct(fieldType, mapValue) // hashStruct 返回 common.Hash (bytes32)
		if err != nil {
			return nil, err
		}
		return hashedStruct.Bytes(), nil
	}

	// 3. 基本/原子类型
	switch fieldType {
	case "string":
		strVal, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("expected string for type 'string', got %T", value)
		}
		return crypto.Keccak256([]byte(strVal)), nil
	case "bytes":
		var bytesVal []byte
		switch v := value.(type) {
		case []byte:
			bytesVal = v
		case string: // 假设是十六进制字符串
			decoded, err := hexutil.Decode(v)
			if err != nil {
				return nil, fmt.Errorf("invalid hex string for 'bytes' type: '%s', error: %w", v, err)
			}
			bytesVal = decoded
		default:
			return nil, fmt.Errorf("expected []byte or hex string for 'bytes' type, got %T", value)
		}
		return crypto.Keccak256(bytesVal), nil
	default:
		// 对于 address, bool, bytesN, uintN, intN - 使用 ABI 编码得到 bytes32
		abiType, err := solidityTypeToAbiType(fieldType) // 使用 abi.NewType 获取准确的 ABI 类型
		if err != nil {
			// 如果 solidityTypeToAbiType 失败，说明它不是一个可直接 ABI 编码的基本类型
			return nil, fmt.Errorf("type '%s' is not a recognized primitive ABI type for EIP-712 'encodeData': %w", fieldType, err)
		}

		var concreteValue interface{} = value

		// 对特定类型的值进行预处理和转换
		switch abiType.T {
		case abi.IntTy, abi.UintTy:
			strVal := ""
			switch v := value.(type) {
			case json.Number:
				strVal = string(v)
			case string:
				strVal = v
			case float32, float64: // JSON 反序列化到 map[string]interface{} 时数字可能变成 float
				strVal = fmt.Sprintf("%.0f", v) // 转换为整数形式的字符串
			case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
				concreteValue = v // 直接使用，Pack 会处理
			case *big.Int:
				concreteValue = v // 直接使用
			}
			if strVal != "" && concreteValue == value { // 如果 concreteValue 未被上面 case 覆盖且 strVal 有值
				bigIntVal, ok := new(big.Int).SetString(strVal, 0) // 自动检测进制 ("0x" 或十进制)
				if !ok {
					return nil, fmt.Errorf("failed to convert '%s' to big.Int for type '%s'", strVal, fieldType)
				}
				concreteValue = bigIntVal
			}
		case abi.AddressTy:
			switch v := value.(type) {
			case string:
				if !common.IsHexAddress(v) {
					return nil, fmt.Errorf("invalid address string for type 'address': '%s'", v)
				}
				concreteValue = common.HexToAddress(v)
			case common.Address:
				concreteValue = v // 已经是 common.Address
			default:
				return nil, fmt.Errorf("expected address string or common.Address for type 'address', got %T", value)
			}
		case abi.BoolTy:
			switch v := value.(type) {
			case bool:
				concreteValue = v
			case string:
				lowerV := strings.ToLower(v)
				if lowerV == "true" {
					concreteValue = true
				} else if lowerV == "false" {
					concreteValue = false
				} else {
					return nil, fmt.Errorf("invalid string for 'bool' type: '%s'", v)
				}
			default:
				return nil, fmt.Errorf("unsupported type for 'bool' conversion: %T", value)
			}
		case abi.FixedBytesTy: // bytes1...bytes32
			var bytesN []byte
			switch v := value.(type) {
			case string: // 假设是十六进制字符串
				decoded, err := hexutil.Decode(v)
				if err != nil {
					return nil, fmt.Errorf("invalid hex string for '%s': %w", fieldType, err)
				}
				bytesN = decoded
			case []byte:
				bytesN = v
			default:
				return nil, fmt.Errorf("unsupported value for '%s': %T", fieldType, v)
			}
			// ABI Pack 需要的是 Go 原生切片，但长度需要与 abiType.Size 匹配
			if len(bytesN) != abiType.Size {
				// EIP-712 对 bytes<M> 的编码是值本身，然后 hashStruct 的连接会处理。
				// 但这里我们希望得到一个 bytes32 的 ABI 编码槽。
				// 如果是 bytesM M<32, 它会被右填充。
				// 对于直接作为参数传递给 Pack 的 bytesN，如果 abiType.Size < 32，Pack 会右填充。
				// 如果 len(bytesN) > abiType.Size，Pack 会报错。
				// 如果 len(bytesN) < abiType.Size，Pack 会报错（因为它期望一个完整的固定大小数组）。
				// 因此，我们需要传递一个Go的固定大小数组类型或者确保切片长度正确。
				// 为了简化，这里假设 bytesN 已经是正确长度的字节。Pack 函数本身会进行验证。
				// 如果类型是 bytesN，那么 concreteValue 应该是 [N]byte 类型或长度为 N 的 []byte。
				// Pack 的行为：对于 `[N]byte`，它会直接使用。对于 `[]byte` 作为 `bytesM` 的值，Pack会检查长度。
				// 让我们确保传递给Pack的是一个Go的固定大小数组的反射，或者正确长度的slice。
				// 最简单的方式是让Pack处理，如果类型是bytesM，确保输入是M字节。
				if abiType.Size > 0 && len(bytesN) != abiType.Size {
					return nil, fmt.Errorf("length mismatch for %s: expected %d bytes, got %d", fieldType, abiType.Size, len(bytesN))
				}
				concreteValue = bytesN // Pack 会处理 []byte for bytesM
			}
		case abi.BytesTy: // 动态 bytes, 与顶层 "bytes" case 逻辑一致，对值本身 Keccak
			// 此 case 应该已被顶层 switch fieldType == "bytes" 捕获
			// 如果到这里，说明 solidityTypeToAbiType 将其解析为 abi.BytesTy
			// 但 EIP-712 的 "bytes" 类型是直接哈希，不经过 Pack。
			return nil, fmt.Errorf("internal error: dynamic 'bytes' type reached primitive ABI packing section")

		default:
			return nil, fmt.Errorf("unhandled primitive ABI type '%s' for EIP-712 'encodeData'", abiType.String())
		}

		arguments := abi.Arguments{{Type: abiType}}
		packedBytes, err := arguments.Pack(concreteValue)
		if err != nil {
			return nil, fmt.Errorf("failed to ABI pack value for type '%s' (value: %+v, concrete: %+v): %w", fieldType, value, concreteValue, err)
		}
		if len(packedBytes) != 32 { // Pack 对单个参数应该总是产生 32 字节（或其倍数，但这里是单个参数）
			return nil, fmt.Errorf("ABI packing for primitive type '%s' did not result in 32 bytes, got %d bytes. Input: %+v", fieldType, len(packedBytes), concreteValue)
		}
		return packedBytes, nil
	}
}

// hashStruct 计算结构体实例的 EIP-712 哈希，结果为 common.Hash (bytes32)。
func (td *TypedData) hashStruct(typeName string, data map[string]interface{}) (common.Hash, error) {
	structTypeHash, err := td.typeHash(typeName) // typeHash(S)
	if err != nil {
		return common.Hash{}, fmt.Errorf("failed to get typeHash for struct '%s': %w", typeName, err)
	}

	var concatenatedData bytes.Buffer
	concatenatedData.Write(structTypeHash.Bytes()) // typeHash 是第一个元素

	schema, ok := td.Types[typeName]
	if !ok {
		return common.Hash{}, fmt.Errorf("type '%s' not found in types definition for hashing struct", typeName)
	}

	for _, field := range schema {
		fieldValue, valueExists := data[field.Name]
		if !valueExists {
			// EIP-712 规范要求所有在类型定义中声明的字段都必须在数据中存在
			return common.Hash{}, fmt.Errorf("field '%s' not found in data for struct type '%s'", field.Name, typeName)
		}

		encodedValue, err := td.encodeData(field.Type, fieldValue) // encodeData(valueᵢ)
		if err != nil {
			return common.Hash{}, fmt.Errorf("failed to encode field '%s' (type %s) for struct '%s': %w", field.Name, field.Type, typeName, err)
		}
		if len(encodedValue) != 32 { // 防御性检查
			return common.Hash{}, fmt.Errorf("internal error: encoded data for field '%s' in struct '%s' is not 32 bytes (got %d)", field.Name, typeName, len(encodedValue))
		}
		concatenatedData.Write(encodedValue)
	}
	return crypto.Keccak256Hash(concatenatedData.Bytes()), nil
}

// HashDomain 计算 EIP-712 Domain Separator 的哈希。
func (td *TypedData) HashDomain() (common.Hash, error) {
	domainMap := make(map[string]interface{})
	var domainSchemaFields []EIP712Type

	// 根据实际提供的 Domain 字段构建临时的 domainMap 和 schema
	if td.Domain.Name != "" {
		domainMap["name"] = td.Domain.Name
		domainSchemaFields = append(domainSchemaFields, EIP712Type{Name: "name", Type: "string"})
	}
	if td.Domain.Version != "" {
		domainMap["version"] = td.Domain.Version
		domainSchemaFields = append(domainSchemaFields, EIP712Type{Name: "version", Type: "string"})
	}
	if td.Domain.ChainId != nil {
		chainIdStr := string(*td.Domain.ChainId)
		bigChainId, ok := new(big.Int).SetString(chainIdStr, 10) // EIP-712 通常是 uint256
		if !ok {
			return common.Hash{}, fmt.Errorf("invalid chainId string in domain: '%s'", chainIdStr)
		}
		domainMap["chainId"] = bigChainId // encodeData 会处理 *big.Int
		domainSchemaFields = append(domainSchemaFields, EIP712Type{Name: "chainId", Type: "uint256"})
	}
	if td.Domain.VerifyingContract != nil && (*td.Domain.VerifyingContract != common.Address{}) {
		domainMap["verifyingContract"] = *td.Domain.VerifyingContract // encodeData 会处理 common.Address
		domainSchemaFields = append(domainSchemaFields, EIP712Type{Name: "verifyingContract", Type: "address"})
	}
	if td.Domain.Salt != nil && *td.Domain.Salt != "" {
		saltBytes, err := hexutil.Decode(*td.Domain.Salt)
		if err != nil {
			return common.Hash{}, fmt.Errorf("invalid hex for domain salt: '%s', error: %w", *td.Domain.Salt, err)
		}
		// EIP-712 规定 salt 是 bytes32
		if len(saltBytes) != 32 && len(saltBytes) > 0 { // 允许空 salt 不被编码，但如果提供了，必须是32字节
			return common.Hash{}, fmt.Errorf("domain salt, if provided, must be 32 bytes (or hex for 32 bytes), got %d bytes from '%s'", len(saltBytes), *td.Domain.Salt)
		}
		if len(saltBytes) > 0 { // 只有当 salt 实际有内容时才加入 map 和 schema
			domainMap["salt"] = saltBytes // encodeData 会处理 []byte for bytes32
			domainSchemaFields = append(domainSchemaFields, EIP712Type{Name: "salt", Type: "bytes32"})
		}
	}

	// 如果 domainMap 为空 (所有 domain 字段都未提供)，则不应进行哈希
	// 但 EIP-712 要求 domain separator 始终存在，即使所有字段都可选且未提供，
	// 此时的 domain struct 也是一个有效的（空）结构体，其 typeHash 仍会被计算。
	// 如果 domainSchemaFields 为空，意味着这是一个"空"的 EIP712Domain 结构体。

	// 创建一个临时的 TypedData 副本，仅用于哈希 Domain。
	// 这样做是为了让 td.hashStruct 能正确找到 EIP712Domain 的（临时）类型定义。
	tempTypes := make(EIP712Types)
	for k, v := range td.Types { // 复制用户定义的其他类型，以防 Domain 结构引用它们（虽然不常见）
		tempTypes[k] = v
	}
	tempTypes[eip712DomainType] = domainSchemaFields // 添加（可能为空的）Domain 模式

	tempTdForDomainHashing := &TypedData{
		Types:       tempTypes,
		PrimaryType: eip712DomainType, // 不重要，因为 hashStruct 会用参数
		Message:     domainMap,        // 不重要
	}

	return tempTdForDomainHashing.hashStruct(eip712DomainType, domainMap)
}

// HashMessage 计算消息部分的哈希。
func (td *TypedData) HashMessage() (common.Hash, error) {
	if td.PrimaryType == "" {
		return common.Hash{}, fmt.Errorf("PrimaryType is not set in TypedData")
	}
	if td.Message == nil { // 允许空消息体，如果 schema 也允许
		// return common.Hash{}, fmt.Errorf("Message is not set in TypedData")
	}
	return td.hashStruct(td.PrimaryType, td.Message)
}

// DigestToSign 计算最终需要签名的哈希 (domain 和 message 结合)。
func (td *TypedData) DigestToSign() (common.Hash, error) {
	domainSeparator, err := td.HashDomain()
	if err != nil {
		return common.Hash{}, fmt.Errorf("failed to compute domain separator: %w", err)
	}

	messageStructHash, err := td.HashMessage()
	if err != nil {
		return common.Hash{}, fmt.Errorf("failed to compute message struct hash: %w", err)
	}

	var dataToHash []byte
	dataToHash = append(dataToHash, []byte(eip712PrefixBytes)...) // \x19\x01
	dataToHash = append(dataToHash, domainSeparator.Bytes()...)
	dataToHash = append(dataToHash, messageStructHash.Bytes()...)

	return crypto.Keccak256Hash(dataToHash), nil
}

// SignEIP712 对 TypedData 进行签名。
func SignEIP712(typedData *TypedData, privateKey *ecdsa.PrivateKey) (string, error) {
	digest, err := typedData.DigestToSign()
	if err != nil {
		return "", fmt.Errorf("failed to get EIP-712 digest to sign: %w", err)
	}

	var signingChainID *big.Int
	if typedData.Domain.ChainId != nil {
		var ok bool
		signingChainID, ok = new(big.Int).SetString(string(*typedData.Domain.ChainId), 10)
		if !ok {
			return "", fmt.Errorf("invalid chainId string in domain for signing: '%s'", string(*typedData.Domain.ChainId))
		}
		if signingChainID.Sign() <= 0 { // 如果 chainID 是 0 或负数，不用于 EIP-155 V 值调整
			signingChainID = nil
		}
	}

	sigBytes, err := signHashWithKey(digest.Bytes(), privateKey, signingChainID) // signHashWithKey 来自 utils.go
	if err != nil {
		return "", err
	}
	return hexutil.Encode(sigBytes), nil
}

// VerifyEIP712 验证 EIP-712 签名。
func VerifyEIP712(typedData *TypedData, signatureHex string, expectedAddress common.Address) (bool, error) {
	digest, err := typedData.DigestToSign()
	if err != nil {
		return false, fmt.Errorf("failed to compute EIP-712 digest for verification: %w", err)
	}
	// verifySignatureAgainstAddress 来自 utils.go
	return verifySignatureAgainstAddress(digest, signatureHex, expectedAddress)
}

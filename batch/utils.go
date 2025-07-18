package batch

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

var (
	nonceMutex   sync.Mutex
	currentNonce uint64
)

func NewClient(nodeURL, proxyUrl string) (*ethclient.Client, error) {
	var ethClient *ethclient.Client
	var err error

	if proxyUrl != "" {
		parsedProxyURL, parseErr := url.Parse(proxyUrl)
		if parseErr != nil {
			return nil, fmt.Errorf("无效的代理 URL '%s': %v", proxyUrl, parseErr)
		}
		transport := &http.Transport{Proxy: http.ProxyURL(parsedProxyURL)}
		httpClient := &http.Client{Transport: transport, Timeout: 60 * time.Second}
		rpcClient, dialErr := rpc.DialOptions(context.Background(), nodeURL, rpc.WithHTTPClient(httpClient))
		if dialErr != nil {
			return nil, fmt.Errorf("无法通过代理连接到以太坊节点 '%s': %v", nodeURL, dialErr)
		}
		ethClient = ethclient.NewClient(rpcClient)
	} else {
		ethClient, err = ethclient.Dial(nodeURL)
		if err != nil {
			return nil, fmt.Errorf("无法连接到以太坊节点 '%s': %v", nodeURL, err)
		}
	}
	return ethClient, nil
}

func mustCreateClients(nodeURL string, proxys []string) []*ethclient.Client {
	clients := make([]*ethclient.Client, len(proxys))
	current := 0
	for i := range proxys {
		client, err := NewClient(nodeURL, proxys[i])
		if err != nil {
			continue
		}
		clients[current] = client
		current++
	}
	return clients
}

func mustParsePrivateKey(key string) *ecdsa.PrivateKey {
	privateKey, err := crypto.HexToECDSA(key)
	if err != nil {
		log.Fatalf("Failed to parse private key: %v", err)
	}
	return privateKey
}

func mustGetNonce(client *ethclient.Client, address common.Address) uint64 {
	nonce, err := client.PendingNonceAt(context.Background(), address)
	for err != nil {
		log.Printf("Failed to get initial nonce: %v", err)
		time.Sleep(3 * time.Second)
		nonce, err = client.PendingNonceAt(context.Background(), address)
	}
	return nonce
}

func mustGetBalance(client *ethclient.Client, address common.Address) *big.Int {
	balanceWei, err := client.BalanceAt(context.Background(), address, nil)
	if err != nil {
		log.Fatalf("Failed to get balance: %v", err)
	}
	return balanceWei
}

func SendTransfer(client *ethclient.Client, privateKeyHex string, toAddress common.Address, amount *big.Int, dataStr string, useGlobalNonce bool) (*common.Hash, error) {
	privateKey := mustParsePrivateKey(privateKeyHex)
	fromAddress := getAddressFromPrivateKey(privateKey)

	var nonce uint64
	if useGlobalNonce {
		nonceMutex.Lock()
		nonce = currentNonce
		currentNonce++
		nonceMutex.Unlock()
	} else {
		nonce = mustGetNonce(client, fromAddress)
	}

	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to suggest gas price: %v", err)
	}

	chainID, err := client.NetworkID(context.Background())
	if err != nil {
		return nil, err
	}

	data, err := hex.DecodeString(dataStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode method ID: %v", err)
	}

	msg := ethereum.CallMsg{
		From:  fromAddress,
		To:    &toAddress,
		Value: amount,
		Data:  data,
	}
	gasLimit, err := client.EstimateGas(context.Background(), msg)
	if err != nil {
		return nil, err
	}

	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   chainID,
		Nonce:     nonce,
		GasFeeCap: gasPrice,
		Gas:       gasLimit,
		To:        &toAddress,
		Value:     amount,
		Data:      data,
	})

	signedTx, err := types.SignTx(tx, types.LatestSignerForChainID(chainID), privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign transaction: %v", err)
	}

	if err := client.SendTransaction(context.Background(), signedTx); err != nil {
		return nil, fmt.Errorf("failed to send transaction: %v", err)
	}

	hash := signedTx.Hash()
	return &hash, nil
}

func getAddressFromPrivateKey(privateKey *ecdsa.PrivateKey) common.Address {
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("Failed to cast public key to ECDSA")
	}
	return crypto.PubkeyToAddress(*publicKeyECDSA)
}

func BatchCall(nodeURL, tokenAddress, dataStr string, amount *big.Int, keys, proxys []string) {
	dataStr = strings.Replace(dataStr, "0x", "", -1)
	clients := mustCreateClients(nodeURL, proxys)

	chainID, err := clients[0].NetworkID(context.Background())
	if err != nil {
		log.Printf("无法获取 chainID: %v", err)
		return
	}

	gasPrice, err := clients[0].SuggestGasPrice(context.Background())
	if err != nil {
		log.Printf("failed to suggest gas price: %v\n", err)
		return
	}

	concurrency := len(proxys)
	semaphore := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for i := 0; i < len(keys); i++ {
		wg.Add(1)
		semaphore <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-semaphore }()
			client := clients[i%concurrency]

			fromPrivateKey := mustParsePrivateKey(keys[i])
			fromAddress := getAddressFromPrivateKey(fromPrivateKey)

			toAddress := common.HexToAddress(tokenAddress)

			log.Printf("[%d] From:	%s\n", i, fromAddress)
			log.Printf("[%d] To:	%s\n", i, toAddress)

			nonce := mustGetNonce(client, fromAddress)

			for t := 0; t < 1; t++ {
				data, err := hex.DecodeString(strings.Replace(dataStr, "{from}", strings.Replace(fromAddress.String(), "0x", "", -1), -1))
				if err != nil {
					log.Printf("failed to decode method ID: %v\n", err)
					t--
					continue
				}

				msg := ethereum.CallMsg{
					From:  fromAddress,
					To:    &toAddress,
					Value: amount,
					Data:  data,
				}
				gasLimit, err := client.EstimateGas(context.Background(), msg)
				if err != nil {
					log.Printf("failed to suggest gas limit: %v\n", err)
					t--
					continue
				}

				tx := types.NewTx(&types.DynamicFeeTx{
					ChainID:   chainID,
					Nonce:     nonce,
					GasFeeCap: gasPrice,
					Gas:       gasLimit,
					To:        &toAddress,
					Value:     amount,
					Data:      data,
				})

				signedTx, err := types.SignTx(tx, types.LatestSignerForChainID(chainID), fromPrivateKey)
				if err != nil {
					log.Printf("failed to sign transaction: %v\n", err)
					t--
					continue
				}

				if err := client.SendTransaction(context.Background(), signedTx); err != nil {
					log.Printf("failed to send transaction: %v\n", err)
					t--
					continue
				}

				if err != nil {
					log.Printf("Failed to send transfer: %v\n", err)
					t--
					continue
				}
				log.Printf("[%d/%d] Tx:	%s\n", i, t, signedTx.Hash())
			}
		}(i)
	}
	wg.Wait()
}

func parseMethodSignature(signature string) (abi.Arguments, error) {
	openParen := strings.Index(signature, "(")
	closeParen := strings.Index(signature, ")")
	if openParen == -1 || closeParen == -1 || openParen >= closeParen {
		return nil, fmt.Errorf("invalid method signature format: %s", signature)
	}
	argsString := signature[openParen+1 : closeParen]
	var args abi.Arguments
	if argsString == "" {
		return args, nil
	}
	argTypes := strings.Split(argsString, ",")
	for _, argTypeStr := range argTypes {
		argTypeStr = strings.TrimSpace(argTypeStr)
		parsedType, err := abi.NewType(argTypeStr, "", nil)
		if err != nil {
			return nil, fmt.Errorf("failed to parse argument type '%s': %w", argTypeStr, err)
		}
		arg := abi.Argument{
			Type: parsedType,
			Name: "",
		}
		args = append(args, arg)
	}
	return args, nil
}

func MethodPack(method string, params ...any) string {
	/*
	   method := "withdrawNFT(address,uint256)"
	   contractAddress := common.HexToAddress("0x290xxxxx")
	   tokenId := big.NewInt(123)
	   MethodPack(method, contractAddress, tokenId)
	*/
	methodID := crypto.Keccak256([]byte(method))[:4]
	arguments, err := parseMethodSignature(method)
	if err != nil {
		log.Fatalf("Failed to parse method signature: %v", err)
	}
	packedArgs, err := arguments.Pack(params...)
	if err != nil {
		log.Fatalf("Failed to pack arguments: %v", err)
	}
	callData := append(methodID, packedArgs...)
	return fmt.Sprintf("0x%x", callData)
}

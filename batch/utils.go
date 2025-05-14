package batch

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"github.com/ethereum/go-ethereum"
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
	if err != nil {
		log.Fatalf("Failed to get initial nonce: %v", err)
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

func batchSendTransfer(client *ethclient.Client, privateKeyHex string, toAddress common.Address, amount *big.Int) (*common.Hash, error) {
	privateKey := mustParsePrivateKey(privateKeyHex)
	fromAddress := getAddressFromPrivateKey(privateKey)

	nonceMutex.Lock()
	nonce := currentNonce
	currentNonce++
	nonceMutex.Unlock()

	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to suggest gas price: %v", err)
	}

	chainID, err := client.NetworkID(context.Background())
	if err != nil {
		return nil, err
	}

	data, err := hex.DecodeString("")
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

func sendTransfer(client *ethclient.Client, privateKeyHex string, toAddress common.Address, amount *big.Int) (*common.Hash, error) {
	privateKey := mustParsePrivateKey(privateKeyHex)
	fromAddress := getAddressFromPrivateKey(privateKey)

	nonce := mustGetNonce(client, fromAddress)

	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to suggest gas price: %v", err)
	}

	chainID, err := client.NetworkID(context.Background())
	if err != nil {
		return nil, err
	}

	data, err := hex.DecodeString("")
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
	strings.Replace(dataStr, "0x", "", 1)
	clients := mustCreateClients(nodeURL, proxys)

	chainID, err := clients[0].NetworkID(context.Background())
	if err != nil {
		log.Printf("无法获取 chainID: %v", err)
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
			log.Printf("[%d] To:		%s\n", i, toAddress)

			nonce := mustGetNonce(client, fromAddress)

			for t := 0; t < 1; t++ {
				gasPrice, err := client.SuggestGasPrice(context.Background())
				if err != nil {
					log.Println("failed to suggest gas price: %v", err)
					t--
					continue
				}

				data, err := hex.DecodeString(strings.Replace(dataStr, "{from}", strings.Replace(fromAddress.String(), "0x", "", 1), 1))
				if err != nil {
					log.Println("failed to decode method ID: %v", err)
					t--
					continue
				}

				log.Println(hex.EncodeToString(data))

				msg := ethereum.CallMsg{
					From:  fromAddress,
					To:    &toAddress,
					Value: amount,
					Data:  data,
				}
				gasLimit, err := client.EstimateGas(context.Background(), msg)
				if err != nil {
					log.Println("failed to suggest gas limit: %v", err)
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
					log.Println("failed to sign transaction: %v", err)
					t--
					continue
				}

				if err := client.SendTransaction(context.Background(), signedTx); err != nil {
					log.Println("failed to send transaction: %v", err)
					t--
					continue
				}

				if err != nil {
					log.Println("Failed to send transfer:", err)
					t--
					continue
				}
				log.Printf("[%d/%d] Tx: %s\n", i, t, signedTx.Hash())
			}
		}(i)
	}
	wg.Wait()
}

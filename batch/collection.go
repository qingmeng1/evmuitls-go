package batch

import (
	"context"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/qingmeng1/evmuitls-go/contracts"
	"log"
	"math/big"
	"sync"
)

func CollectEth(nodeURL string, keys, proxys []string) {
	clients := mustCreateClients(nodeURL, proxys)

	toPrivateKey := mustParsePrivateKey(keys[0])
	toAddress := getAddressFromPrivateKey(toPrivateKey)

	concurrency := len(proxys)
	semaphore := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for i := 1; i < len(keys); i++ {
		wg.Add(1)
		semaphore <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-semaphore }()
			client := clients[i%concurrency]

			fromPrivateKey := mustParsePrivateKey(keys[i])
			fromAddress := getAddressFromPrivateKey(fromPrivateKey)

			gasPrice, err := client.SuggestGasPrice(context.Background())
			if err != nil {
				log.Fatalf("Failed to suggest gas price: %v", err)
			}

			balance := mustGetBalance(client, fromAddress)
			if balance.Cmp(new(big.Int).Mul(gasPrice, big.NewInt(21000))) <= 0 {
				log.Printf("[%d] [%s] Balance: %s\n", i, fromAddress, balance)
				return
			}

			log.Printf("[%d] From: %s\n", i, fromAddress)
			log.Printf("[%d] To: %s\n", i, toAddress)

			for t := 0; t < 1; t++ {
				hash, err := SendTransfer(client, keys[i], toAddress, new(big.Int).Sub(balance, new(big.Int).Mul(gasPrice, big.NewInt(21000))), "", false)
				if err != nil {
					log.Println("Failed to send transfer:", err)
					t--
					continue
				}
				log.Printf("[%d/%d] Tx: %s\n", i, t, hash)
			}
		}(i)
	}
	wg.Wait()
}

func CollectToken(nodeURL, tokenAddress string, keys, proxys []string) {
	clients := mustCreateClients(nodeURL, proxys)

	toPrivateKey := mustParsePrivateKey(keys[0])
	toAddress := getAddressFromPrivateKey(toPrivateKey)

	chainID, err := clients[0].NetworkID(context.Background())
	if err != nil {
		log.Printf("无法获取 chainID: %v", err)
		return
	}

	concurrency := len(proxys)
	semaphore := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for i := 1; i < len(keys); i++ {
		wg.Add(1)
		semaphore <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-semaphore }()
			client := clients[i%concurrency]

			fromPrivateKey := mustParsePrivateKey(keys[i])
			fromAddress := getAddressFromPrivateKey(fromPrivateKey)

			erc20, err := contracts.NewERC20(common.HexToAddress(tokenAddress), client)
			if err != nil {
				log.Fatalf("Failed to connect ERC20 contract: %v", err)
			}
			balance, err := erc20.BalanceOf(nil, fromAddress)
			if err != nil {
				log.Fatalf("Failed to get balance: %v", err)
			}
			if balance.Cmp(big.NewInt(0)) <= 0 {
				log.Printf("[%d] [%s] Balance: %s\n", i, fromAddress, balance)
				return
			}

			log.Printf("[%d] From: %s\n", i, fromAddress)
			log.Printf("[%d] To: %s\n", i, toAddress)

			for t := 0; t < 1; t++ {
				auth, err := bind.NewKeyedTransactorWithChainID(fromPrivateKey, chainID)
				if err != nil {
					log.Printf("无法创建 transactor: %v", err)
					t--
					continue
				}

				transfer, err := erc20.Transfer(auth, toAddress, balance)
				if err != nil {
					log.Println("Failed to send transfer:", err)
					t--
					continue
				}
				log.Printf("[%d/%d] Tx: %s\n", i, t, transfer.Hash())
			}
		}(i)
	}
	wg.Wait()
}

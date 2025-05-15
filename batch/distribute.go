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

func BatchFillBalance(nodeURL string, keys, proxys []string, fillBalance *big.Int) {
	clients := mustCreateClients(nodeURL, proxys)

	fromPrivateKey := mustParsePrivateKey(keys[0])
	fromAddress := getAddressFromPrivateKey(fromPrivateKey)
	currentNonce = mustGetNonce(clients[0], fromAddress)

	concurrency := len(proxys)
	semaphore := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for i := 1; i < len(keys); i++ {
		wg.Add(1)
		semaphore <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-semaphore }()

			toPrivateKey := mustParsePrivateKey(keys[i])
			toAddress := getAddressFromPrivateKey(toPrivateKey)

			balance := mustGetBalance(clients[i%concurrency], toAddress)
			if balance.Cmp(fillBalance) >= 0 {
				log.Printf("[%d] [%s] Balance: %s\n", i, toAddress, balance)
				return
			}

			log.Printf("[%d] From: %s\n", i, fromAddress)
			log.Printf("[%d] To: %s\n", i, toAddress)

			for t := 0; t < 1; t++ {
				hash, err := sendTransfer(clients[i%concurrency], keys[0], toAddress, new(big.Int).Sub(fillBalance, balance), true)
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

func BatchTransfer(nodeURL string, keys, proxys []string, amount *big.Int) {
	clients := mustCreateClients(nodeURL, proxys)

	fromPrivateKey := mustParsePrivateKey(keys[0])
	fromAddress := getAddressFromPrivateKey(fromPrivateKey)
	currentNonce = mustGetNonce(clients[0], fromAddress)

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

			toPrivateKey := mustParsePrivateKey(keys[i])
			toAddress := getAddressFromPrivateKey(toPrivateKey)

			log.Printf("[%d] From: %s\n", i, fromAddress)
			log.Printf("[%d] To: %s\n", i, toAddress)

			for t := 0; t < 1; t++ {
				hash, err := sendTransfer(client, keys[0], toAddress, amount, true)
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

func BatchTokenFillBalance(nodeURL, tokenAddress string, keys, proxys []string, fillBalance *big.Int) {
	clients := mustCreateClients(nodeURL, proxys)

	fromPrivateKey := mustParsePrivateKey(keys[0])
	fromAddress := getAddressFromPrivateKey(fromPrivateKey)
	currentNonce = mustGetNonce(clients[0], fromAddress)

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

			toPrivateKey := mustParsePrivateKey(keys[i])
			toAddress := getAddressFromPrivateKey(toPrivateKey)

			erc20, err := contracts.NewERC20(common.HexToAddress(tokenAddress), client)
			if err != nil {
				log.Fatalf("Failed to connect ERC20 contract: %v", err)
			}
			balance, err := erc20.BalanceOf(nil, toAddress)
			if err != nil {
				log.Fatalf("Failed to get balance: %v", err)
			}

			if balance.Cmp(fillBalance) >= 0 {
				log.Printf("[%d] [%s] Balance: %s\n", i, toAddress, balance)
				return
			}

			log.Printf("[%d] From: %s\n", i, fromAddress)
			log.Printf("[%d] To: %s\n", i, toAddress)

			nonceMutex.Lock()
			nonce := currentNonce
			currentNonce++
			nonceMutex.Unlock()

			for t := 0; t < 1; t++ {
				auth, err := bind.NewKeyedTransactorWithChainID(fromPrivateKey, chainID)
				if err != nil {
					log.Printf("无法创建 transactor: %v", err)
					t--
					continue
				}
				auth.Nonce = big.NewInt(int64(nonce))

				transfer, err := erc20.Transfer(auth, toAddress, new(big.Int).Sub(fillBalance, balance))
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

func BatchTokenTransfer(nodeURL, tokenAddress string, keys, proxys []string, amount *big.Int) {
	clients := mustCreateClients(nodeURL, proxys)

	fromPrivateKey := mustParsePrivateKey(keys[0])
	fromAddress := getAddressFromPrivateKey(fromPrivateKey)
	currentNonce = mustGetNonce(clients[0], fromAddress)

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

			toPrivateKey := mustParsePrivateKey(keys[i])
			toAddress := getAddressFromPrivateKey(toPrivateKey)

			erc20, err := contracts.NewERC20(common.HexToAddress(tokenAddress), client)
			if err != nil {
				log.Fatalf("Failed to connect ERC20 contract: %v", err)
			}

			log.Printf("[%d] From: %s\n", i, fromAddress)
			log.Printf("[%d] To: %s\n", i, toAddress)

			nonceMutex.Lock()
			nonce := currentNonce
			currentNonce++
			nonceMutex.Unlock()

			for t := 0; t < 1; t++ {
				auth, err := bind.NewKeyedTransactorWithChainID(fromPrivateKey, chainID)
				if err != nil {
					log.Printf("无法创建 transactor: %v", err)
					t--
					continue
				}
				auth.Nonce = big.NewInt(int64(nonce))

				transfer, err := erc20.Transfer(auth, toAddress, amount)
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

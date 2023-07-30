package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"os"
)

func decryptAES(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(ciphertext, ciphertext)

	return ciphertext, nil
}

func readDecryptedFile(filepath string, key []byte) ([]byte, error) {
	// Read the encrypted content from the specified file
	encryptedData, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}

	// Decrypt the encrypted data using the provided encryption key
	decryptedData, err := decryptAES(key, encryptedData)
	if err != nil {
		return nil, err
	}

	return decryptedData, nil
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: ./reader <filename> <encryption_key>")
		return
	}

	filePath := os.Args[1]
	encryptionKey := []byte(os.Args[2])

	// Read and print the decrypted content of the specified file
	decryptedData, err := readDecryptedFile(filePath, encryptionKey)
	if err != nil {
		fmt.Println("Error reading decrypted data:", err)
		return
	}

	fmt.Println("Decrypted content of", filePath, ":")
	fmt.Println(string(decryptedData))
}

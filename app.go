package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"github.com/fatih/color"
	"golang.org/x/crypto/scrypt"
)

var key []byte

func generateKey(passphrase string) []byte {
	salt := []byte("some-random-salt") 
	key, _ := scrypt.Key([]byte(passphrase), salt, 16384, 8, 1, 32)
	return key
}

func encrypt(plainText string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	cipherText := make([]byte, aes.BlockSize+len(plainText))
	iv := cipherText[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], []byte(plainText))
	return base64.URLEncoding.EncodeToString(cipherText), nil
}

func decrypt(cipherText string) (string, error) {
	cipherTextBytes, _ := base64.URLEncoding.DecodeString(cipherText)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	if len(cipherTextBytes) < aes.BlockSize {
		return "", fmt.Errorf("cipher text too short")
	}
	iv := cipherTextBytes[:aes.BlockSize]
	cipherTextBytes = cipherTextBytes[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipherTextBytes, cipherTextBytes)
	return string(cipherTextBytes), nil
}

func addCredential(filename, service, username, password string) {
	credentials := loadCredentials(filename)
	encryptedPassword, _ := encrypt(password)
	credentials[service] = map[string]string{"username": username, "password": encryptedPassword}
	saveCredentials(filename, credentials)
}

func selectService(credentials map[string]map[string]string) string {

	notice := color.New(color.FgGreen).SprintFunc()
	errorText := color.New(color.FgRed).SprintFunc()
	
	fmt.Println(notice("Available services:"))
	services := make([]string, 0, len(credentials))
	for service := range credentials {
		services = append(services, service)
	}
	for i, service := range services {
		fmt.Printf("%d. %s\n", i+1, service)
	}
	
	var choice int
	fmt.Print(notice("Select the service number: "))
	_, err := fmt.Scan(&choice)
	if err != nil || choice < 1 || choice > len(services) {
		fmt.Println(errorText("Invalid choice. Please select a valid service number."))
		return ""
	}
	return services[choice-1]
}

func getCredential(filename string) {
	credentials := loadCredentials(filename)
	if len(credentials) == 0 {
		fmt.Println(color.New(color.FgYellow).Sprint("No credentials found."))
		return
	}
	
	selectedService := selectService(credentials)
	if selectedService == "" {
		return
	}
	
	fmt.Printf("Service: %s\n", selectedService)
	creds := credentials[selectedService]
	fmt.Printf("Username: %s\n", creds["username"])
	decryptedPassword, _ := decrypt(creds["password"])
	fmt.Printf("Password: %s\n", decryptedPassword)
}

func loadCredentials(filename string) map[string]map[string]string {
	file, err := os.Open(filename)
	if err != nil {
		return make(map[string]map[string]string)
	}
	defer file.Close()
	var credentials map[string]map[string]string
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&credentials); err != nil {
		return make(map[string]map[string]string)
	}
	return credentials
}

func saveCredentials(filename string, credentials map[string]map[string]string) {
	file, err := os.Create(filename)
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	if err := encoder.Encode(credentials); err != nil {
		fmt.Println("Error encoding JSON:", err)
	}
}

func main() {
	filename := "passwords.json"
	var passphrase string

	title := color.New(color.FgCyan).Add(color.Bold).SprintFunc()
	section := color.New(color.FgYellow).SprintFunc()
	notice := color.New(color.FgGreen).SprintFunc()
	errorText := color.New(color.FgRed).SprintFunc()

	fmt.Println(title("Welcome to the Password Manager"))
	fmt.Print(notice("Enter your master password: "))
	fmt.Scan(&passphrase)

	key = generateKey(passphrase)

	for {
		fmt.Println(section("===================================="))
		fmt.Println(notice("1. Add Credential"))
		fmt.Println(notice("2. Get Credential"))
		fmt.Println(notice("3. Exit"))
		fmt.Println(section("===================================="))

		var choice int
		fmt.Print(notice("Select an option: "))
		_, err := fmt.Scan(&choice)
		if err != nil {
			fmt.Println(errorText("Invalid input. Please enter a number."))
			continue
		}

		switch choice {
		case 1:
			var service, username, password string
			fmt.Print(notice("Enter service: "))
			fmt.Scan(&service)
			fmt.Print(notice("Enter username: "))
			fmt.Scan(&username)
			fmt.Print(notice("Enter password: "))
			fmt.Scan(&password)
			addCredential(filename, service, username, password)
			fmt.Println(notice("Credential added successfully!"))
		case 2:
			getCredential(filename)
		case 3:
			fmt.Println(notice("Exiting..."))
			os.Exit(0)
		default:
			fmt.Println(errorText("Invalid choice. Please select a valid option."))
		}
	}
}


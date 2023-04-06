package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"math"
	"os"
)

func ChkErr(err error) {
	if err != nil {
		fmt.Printf("%s\n", err.Error())
	}
}

func ReadStr(filePath string) string {
	buffer, err := os.ReadFile(filePath)
	ChkErr(err)

	return string(buffer)
}

func Size(filePath string) int64 {
	file, err := os.Open(filePath)
	ChkErr(err)

	fileinfo, err := file.Stat()
	ChkErr(err)

	return fileinfo.Size()
}

func CreateChecksum(content *[]byte) string {
	checksumBytes := sha256.Sum256(*content)

	checksumBase16 := fmt.Sprintf("%x\n", checksumBytes)

	return checksumBase16
}

func GenRSAKeyPair(bits int) (rsa.PublicKey, rsa.PrivateKey) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	ChkErr(err)

	return privateKey.PublicKey, *privateKey
}

func DecryptRSA(privateKeyPtr *rsa.PrivateKey, contentEncrypted []byte) []byte {
	contentDecrypted, err := rsa.DecryptPKCS1v15(rand.Reader, privateKeyPtr, contentEncrypted)
	ChkErr(err)

	return contentDecrypted
}

// RSA can only decrypt upto 256 bytes. To circumvent this restriction the following function splits the byte payload received into an array of byte slices each of 256 bytes and decrypts them one at a time.
func DecryptRSA256Longer(privateKeyPtr *rsa.PrivateKey, contentEncryptedBytesPtr *[]byte) [][]byte {
	var contentEncryptedByteSlicesArray [][]byte

	bytesDone := new(int64)
	*bytesDone = int64(0)

	endSliceIndex := new(int64)
	*endSliceIndex = int64(0)

	numOfSlices := int(math.Ceil(float64(len([]byte(*contentEncryptedBytesPtr))) / 256))

	for i := 0; i < numOfSlices; i++ {
		*endSliceIndex = int64(*bytesDone + 256)

		contentEncryptedByteSlicesArray = append(contentEncryptedByteSlicesArray, DecryptRSA(privateKeyPtr, (*contentEncryptedBytesPtr)[*bytesDone:*endSliceIndex]))

		*bytesDone = *bytesDone + 256
	}

	return contentEncryptedByteSlicesArray
}

func EncryptRSA(publicKeyPtr *rsa.PublicKey, content []byte) []byte {
	contentEncrypted, err := rsa.EncryptPKCS1v15(rand.Reader, publicKeyPtr, content)
	ChkErr(err)

	return contentEncrypted
}

func EncryptRSA256Longer(publicKeyPtr *rsa.PublicKey, contentPtr *string) [][]byte {
	contentBytes := []byte(*contentPtr)

	var contentBytesEncryptedArray [][]byte

	bytesDone := new(int64)
	*bytesDone = int64(0)

	endSliceIndex := new(int64)
	*endSliceIndex = int64(0)

	numOfByteSlicesInArray := int(math.Ceil(float64(len([]byte(*contentPtr))) / 128))

	for i := 0; i < numOfByteSlicesInArray; i++ {
		*endSliceIndex = int64(*bytesDone + 128)
		if i == numOfByteSlicesInArray-1 {
			*endSliceIndex = int64(len(contentBytes))
		}

		contentBytesEncryptedArray = append(contentBytesEncryptedArray, EncryptRSA(publicKeyPtr, contentBytes[*bytesDone:*endSliceIndex]))

		*bytesDone = *bytesDone + 128
	}

	return contentBytesEncryptedArray
}

func ByteSlicesArrayToByteSlices(byteSlicesArray [][]byte) []byte {
	byteSlices := *(new([]byte))

	for i := 0; i < len(byteSlicesArray); i++ {
		byteSlices = append(byteSlices, byteSlicesArray[i]...)
	}

	return byteSlices
}

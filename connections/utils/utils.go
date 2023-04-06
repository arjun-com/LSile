package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
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

func DecryptRSA(privateKey *rsa.PrivateKey, contentEncrypted *[]byte) ([]byte, error) {
	var contentDecryptedSlicesArray [][]byte

	bytesDone := new(int64)
	*bytesDone = int64(0)

	endSliceIndex := new(int64)
	*endSliceIndex = int64(0)

	numOf256ByteSlices := int(math.Ceil(float64(len(*contentEncrypted)) / 256.0))

	for i := 0; i < numOf256ByteSlices; i++ {
		*endSliceIndex = int64(*bytesDone + 256)
		contentSliceDecrypted, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, (*contentEncrypted)[*bytesDone:*endSliceIndex])
		if err != nil {
			return nil, errors.New("*** ERROR: Error while decrypting, data sent by host was not encrypted with the supplied public key.")
		}

		contentDecryptedSlicesArray = append(contentDecryptedSlicesArray, contentSliceDecrypted)

		*bytesDone = *bytesDone + 256

		fmt.Printf("Decrypting data.\n")
	}

	return ByteSlicesArrayToByteSlices(contentDecryptedSlicesArray), nil
}

func EncryptRSA(publicKey *rsa.PublicKey, content *[]byte) ([]byte, error) {
	var contentEncryptedSlicesArray [][]byte

	bytesDone := new(int64)
	*bytesDone = int64(0)

	endSliceIndex := new(int64)
	*endSliceIndex = int64(0)

	numOf128ByteSlices := int(math.Ceil(float64(len(*content)) / 128))

	for i := 0; i < numOf128ByteSlices; i++ {
		*endSliceIndex = int64(*bytesDone + 128)
		if i == numOf128ByteSlices-1 {
			*endSliceIndex = int64(len(*content))
		}

		contentSliceEncrypted, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, (*content)[*bytesDone:*endSliceIndex])
		if err != nil {
			return nil, errors.New("*** ERROR: Error while encrypting, invalid public key received from client.")
		}

		contentEncryptedSlicesArray = append(contentEncryptedSlicesArray, contentSliceEncrypted)

		*bytesDone = *bytesDone + 128
	}

	return ByteSlicesArrayToByteSlices(contentEncryptedSlicesArray), nil
}

func ByteSlicesArrayToByteSlices(byteSlicesArray [][]byte) []byte {
	byteSlices := *(new([]byte))

	for i := 0; i < len(byteSlicesArray); i++ {
		byteSlices = append(byteSlices, byteSlicesArray[i]...)
	}

	return byteSlices
}

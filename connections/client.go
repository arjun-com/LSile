package connections

import (
	"bytes"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/arjun-com/LSile/connections/utils"
)

const (
	RSA_KEY_BITS_LEN = 2048
)

type RecvedFile struct {
	Path string

	Name               string
	NameBytes          []byte
	NameLength         int64
	NameEncryptedBytes []byte

	Data               string
	DataBytes          []byte
	DataEncryptedBytes []byte

	Size int64

	Checksum                     string
	ChecksumEncryptedBytes       []byte
	ChecksumEncryptedBytesLength int
}

func recvFileData(connPtr *net.Conn, File *RecvedFile) ([]byte, error) {
	buffer := new(bytes.Buffer)

	binary.Read(*connPtr, binary.LittleEndian, &File.Size)
	_, err := io.CopyN(buffer, *connPtr, File.Size)
	if err != nil {
		return nil, errors.New("*** ERROR: Error while reading data of file to buffer.")
	}

	return buffer.Bytes(), nil
}

func recvFileName(connPtr *net.Conn, File *RecvedFile) ([]byte, error) {
	buffer := new(bytes.Buffer)

	binary.Read(*connPtr, binary.LittleEndian, &File.NameLength)
	_, err := io.CopyN(buffer, *connPtr, File.NameLength)
	if err != nil {
		return nil, errors.New("*** ERROR: Error while reading name of file to buffer.")

	}

	return buffer.Bytes(), nil
}

func CreateClientTCPConnection(ip string, port string) *net.Conn {
	serverConn, err := net.Dial("tcp", ip+":"+port)
	utils.ChkErr(err)

	return &serverConn
}

func Client(connPtr *net.Conn, File *RecvedFile) {
	if File.Path == "" {
		fmt.Printf("No file path was supplied in arguments.\n")
		os.Exit(1)
	}

	diskFile, err := os.Create(File.Path + "/inDownload.foobar")
	utils.ChkErr(err)

	publicKey, privateKey := utils.GenRSAKeyPair(RSA_KEY_BITS_LEN)
	publicKeyBytes := x509.MarshalPKCS1PublicKey(&publicKey)

	_, err = (*connPtr).Write(publicKeyBytes)
	utils.ChkErr(err)

	File.ChecksumEncryptedBytes = make([]byte, 256)
	File.ChecksumEncryptedBytesLength, err = (*connPtr).Read(File.ChecksumEncryptedBytes)
	utils.ChkErr(err)
	checksumBytes, err := utils.DecryptRSA(&privateKey, &File.ChecksumEncryptedBytes)
	File.Checksum = string(checksumBytes)

	File.DataEncryptedBytes, err = recvFileData(connPtr, File)
	if err != nil {
		fmt.Printf("%s", err.Error())
		return
	}

	File.DataBytes, err = utils.DecryptRSA(&privateKey, &File.DataEncryptedBytes)
	if err != nil {
		fmt.Printf("%s", err.Error())
		return
	}

	if File.Checksum != utils.CreateChecksum(&File.DataBytes) {
		fmt.Printf("Checksum sent by the server and checksum generated locally do not match.\nData was modified during transfer.\nThe file has not been saved to disk.\nEXITTING PROGRAM\n\n")
		os.Exit(1)
	}

	diskFile.Write(File.DataBytes)

	File.NameEncryptedBytes, err = recvFileName(connPtr, File)
	if err != nil {
		fmt.Printf("%s", err.Error())
		return
	}

	File.NameBytes, err = utils.DecryptRSA(&privateKey, &File.NameEncryptedBytes)
	if err != nil {
		fmt.Printf("%s", err.Error())
		return
	}

	File.Name = string(File.NameBytes)

	diskFile.Close()

	os.Rename(File.Path+"/inDownload.foobar", File.Path+"/"+File.Name)

	(*connPtr).Close()
}

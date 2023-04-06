package connections

import (
	"bytes"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"github.com/arjun-com/LSile/connections/utils"
)

type ClientSpecificEncryptedFile struct {
	NameEncryptedBytes     []byte
	ChecksumEncryptedBytes []byte
	DataEncryptedBytes     []byte
}

type ServedFile struct {
	Path string

	Name      string
	NameBytes []byte

	Data      string
	DataBytes []byte

	Size int64

	Checksum      string
	ChecksumBytes []byte
}

func sendFile(connPtr *net.Conn, bytesPtr *[]byte, bytesSizePtr int64) {
	err := binary.Write(*connPtr, binary.LittleEndian, bytesSizePtr)
	utils.ChkErr(err)

	bytesWritten, err := io.CopyN(*connPtr, bytes.NewReader(*bytesPtr), bytesSizePtr)

	fmt.Printf("Wrote %d bytes to a client\n\n", bytesWritten)
}

func sendFileName(connPtr *net.Conn, contentBytesPtr *[]byte) {
	err := binary.Write(*connPtr, binary.LittleEndian, int64(len(*contentBytesPtr)))
	utils.ChkErr(err)

	bytesWritten, err := io.CopyN(*connPtr, bytes.NewReader(*contentBytesPtr), int64(len(*contentBytesPtr)))

	fmt.Printf("Wrote %d bytes to a client\n\n", bytesWritten)
}

func CreateTCPServer(ip string, port string) *net.Listener {
	tcpServer, err := net.Listen("tcp", ip+":"+port)
	utils.ChkErr(err)

	return &tcpServer
}

func Serve(server *net.Listener, File *ServedFile) {
	file, err := os.Open(File.Path)
	utils.ChkErr(err)

	File.Data = utils.ReadStr(File.Path)
	File.DataBytes = []byte(File.Data)

	File.Size = utils.Size(File.Path)

	File.Name = file.Name()
	File.Name = strings.ReplaceAll(File.Name, "\\", "/")
	File.Name = File.Name[strings.LastIndex(File.Name, "/")+1:]
	File.NameBytes = []byte(File.Name)

	File.Checksum = utils.CreateChecksum(&File.DataBytes)
	File.ChecksumBytes = []byte(File.Checksum)

	for {
		clientConn, err := (*server).Accept()
		utils.ChkErr(err)

		fmt.Println("Established connection with a client.")
		go handleClientConn(&clientConn, File)
	}
}

func handleClientConn(connPtr *net.Conn, File *ServedFile) {
	conn := *connPtr

	encryptedFile := ClientSpecificEncryptedFile{}

	publicKeyBytes := make([]byte, 270) // The public key sent by a client will always be 270 bytes in length when sent from LSile.
	publicKeyBytesLength, err := conn.Read(publicKeyBytes)
	if publicKeyBytesLength != 270 {
		fmt.Printf("*** ERROR: Length of the public key sent by the client is not parsable, closing connection with this client.")
		return
	}

	publicKey, err := x509.ParsePKCS1PublicKey(publicKeyBytes)
	if err != nil {
		fmt.Printf("*** ERROR: Error while parsing public key sent by client, closing connection with this client.")
		return
	}

	encryptedFile.ChecksumEncryptedBytes, err = utils.EncryptRSA(publicKey, &File.ChecksumBytes)
	if err != nil {
		fmt.Printf("%s", err.Error())
		return
	}

	_, err = conn.Write(encryptedFile.ChecksumEncryptedBytes)
	utils.ChkErr(err)

	encryptedFile.DataEncryptedBytes, err = utils.EncryptRSA(publicKey, &File.DataBytes)
	if err != nil {
		fmt.Printf("%s", err.Error())
		return
	}

	sendFile(connPtr, &encryptedFile.DataEncryptedBytes, int64(len(encryptedFile.DataEncryptedBytes)))

	encryptedFile.NameEncryptedBytes, err = utils.EncryptRSA(publicKey, &File.NameBytes)
	if err != nil {
		fmt.Printf("%s", err.Error())
		return
	}

	sendFileName(connPtr, &encryptedFile.NameEncryptedBytes)

	conn.Close()
}

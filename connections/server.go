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
	Path      string
	Name      string
	Data      string
	DataBytes []byte
	Size      int64
	Checksum  string
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

	File.Size = utils.Size(File.Path)

	File.Name = file.Name()
	File.Name = strings.ReplaceAll(File.Name, "\\", "/")
	File.Name = File.Name[strings.LastIndex(File.Name, "/")+1:]

	File.DataBytes = []byte(File.Data)
	File.Checksum = utils.CreateChecksum(&File.DataBytes)

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

	publicKeyBytes := make([]byte, 384)
	publicKeyBytesLength, err := conn.Read(publicKeyBytes)
	utils.ChkErr(err)
	publicKeyPtr, err := x509.ParsePKCS1PublicKey(publicKeyBytes[:publicKeyBytesLength])
	utils.ChkErr(err)

	encryptedFile.ChecksumEncryptedBytes = utils.EncryptRSA(publicKeyPtr, []byte(File.Checksum))
	utils.ChkErr(err)
	_, err = conn.Write(encryptedFile.ChecksumEncryptedBytes)
	utils.ChkErr(err)

	encryptedFile.DataEncryptedBytes = utils.ByteSlicesArrayToByteSlices(utils.EncryptRSA256Longer(publicKeyPtr, &File.Data))
	sendFile(connPtr, &encryptedFile.DataEncryptedBytes, int64(len(encryptedFile.DataEncryptedBytes)))

	encryptedFile.NameEncryptedBytes = utils.ByteSlicesArrayToByteSlices(utils.EncryptRSA256Longer(publicKeyPtr, &File.Name))
	sendFileName(connPtr, &encryptedFile.NameEncryptedBytes)

	conn.Close()
}

package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/arjun-com/LSile/connections"
)

func printHelp() {
	fmt.Printf("First argument: method - ( serve, download )\n")
	fmt.Printf("Second argument: IPv4 Address and port - ( IPv4:Port )\n")
	fmt.Printf("Third argument: path - ( path to file for 'serve', path to directory to download to for 'download' )\n\n\n")

	fmt.Printf("EXAMPLE 1: go run main.go serve 127.0.0.1:8080 C:\\Users\\Example\\Documents\\FileToShare.pdf")
	fmt.Printf("Here 'serve' indicates that you want to serve a file to connecting clients.\nThe next argument '127.0.0.1:8080' indicates which IPv4 address and port you want to serve the file on ( Change it to which IPv4 address and port you intend to serve the file on. ).\nThe final argument is the path to the file to be served to connecting clients.\n\n")

	fmt.Printf("EXAMPLE 2: go run main.go download 127.0.0.1:8080 C:\\Users\\Example\\Documents")
	fmt.Printf("Here 'download' indicates that you want to download a file from a server.\nThe next argument '127.0.0.1:8080' indicates which IPv4 address and port of the server from which you will download the file from ( Change it to which IPv4 address and port of the server from which you will download the file from. ).\nThe final argument is the path to the directory to be the file will be downloaded.\n\n")

	fmt.Printf("NOTE: Downloading files using this program can only occur while connecting to a TCP server running this program on 'serve' mode.\nVice-Versa for serving files to clients.")
}

func main() {
	// go run main.go serve 192.168.100.22:9928 C:\Users\Example\Documents\file.txt
	// go run main.go download 192.168.100.22:9928 C:\Users\Example\Downloads

	args := os.Args[1:]

	socketDetails := strings.Split(args[1], ":")

	method := strings.Trim(args[0], " ")
	if method == "serve" {
		conn := connections.CreateTCPServer(socketDetails[0], socketDetails[1])
		connections.Serve(conn, &connections.ServedFile{Path: strings.Join(args[2:], " ")})
	} else if method == "download" {
		conn := connections.CreateClientTCPConnection(socketDetails[0], socketDetails[1])
		connections.Client(conn, &connections.RecvedFile{Path: strings.Join(args[2:], " ")})
	} else if method == "help" {
		printHelp()
		os.Exit(1)
	} else {
		fmt.Printf("Invalid argument \"%s\" is not an accepted argument.\ngo run main.go help for more information.\n", method)
		os.Exit(1)
	}

}


# LSile

LSile is a _program_ used for transferring **securely** files over a **local network**.

NOTE: When serving files, the serving program on the host machine will stop if unrecognizable is sent to it. Therefore files are only meant to be served only over a local network.

# Why LSile?

LSile prevents 'Man in The Middle' and packet sniffing attacks while sending files.

# How does it work?

An LSile program is run on the host machine which will serve the file.

An LSile program is run on the client(s) machine(s), which want to download the file served by the host securely. 

An RSA public and RSA private key are generated on each client machine.
Each client machine sends its public key to the server.
The server encrypts the checksum of the data in the file and the file data of the file with the public key sent by the client. ( Each client will receive the same file but with different encryption, as each client will generate a unique public and private key )

The LSile host sends unique encrypted data to each one of the clients.

Each client will compare the SHA256 checksum of the decrypted data stored on it and the checksum sent by the host and ensure they match, to make sure no data has been tampered with.

Each client decrypts the data using its private key and writes the data to a file on its disk.





## Run Locally

Clone the repo

```bash
  git clone https://github.com/arjun-com/LSile.git
```

Change directory into the downloaded folder

```bash
  cd LSile
```

Run the program

```bash
  go run main.go help
```


## Authors

- [@Arjun](https://www.github.com/arjun-com)


## Feedback

If you have any **unresolvable** _issues_, please reach out to me at *arjun.main@proton.me*


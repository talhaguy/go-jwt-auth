package main

import "github.com/talhaguy/go-jwt-auth/server"

func main() {
	// TODO: get port from args
	server.StartServer("8080")
}

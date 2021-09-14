package main

import (
	"flag"
	"log"
	nebulahelper "nebula-helper"
	"os"
	"syscall"
)

func main() {

	action := flag.String("action", "oidc_login", "action to run: enroll or oidc_login")
	configPath := flag.String("config_path", ".", "config path")
	ott := flag.String("token", "", "one time token for enrollment")
	serverUrl := flag.String("server", "", "enrollment server")

	flag.Parse()

	switch *action {
	case "oidc_login":
		err := os.Chdir(*configPath)
		if err != nil {
			log.Printf("Could not chdir to config path: %v\n", err)
			syscall.Exit(1)
		}

		//load metadata
		if *serverUrl == "" {
			metadata := nebulahelper.LoadTunnelMetadata(*configPath)
			if metadata == nil {
				log.Printf("Could not load metadata.json\n")
				syscall.Exit(1)
			}

			serverUrl = &metadata.ControllerURL
		}

		if *serverUrl == "" {
			log.Printf("No server url in arguments or metadata.json.\n")
			syscall.Exit(1)
		}

		info, err := nebulahelper.GetControllerInfo(*serverUrl)
		if err != nil {
			log.Printf("Could not obtain controller info: %v\n", err)
			syscall.Exit(1)
		}

		accessToken, err := nebulahelper.DoOIDCLogin(info.OidcConfigURL, info.OidcClientID)
		if err != nil {
			log.Printf("Could not obtain access_token: %v\n", err)
			syscall.Exit(1)
		}

		err = nebulahelper.ConfigureOIDCTunnel(accessToken, *configPath, info)
		if err != nil {
			log.Printf("Could not create temporary config: %v\n", err)
			syscall.Exit(1)
		}

		log.Printf("Successfully obtained mesh config\n")
		syscall.Exit(0)

	case "enroll":
		if *serverUrl == "" {
			log.Printf("Cannot enroll without server URL.\n")
			syscall.Exit(1)
		}

		if *ott == "" {
			log.Printf("Cannot enroll without token.\n")
			syscall.Exit(1)
		}

		err := os.Chdir(*configPath)
		if err != nil {
			log.Printf("Could not chdir to config path: %v\n", err)
			syscall.Exit(1)
		}

		info, err := nebulahelper.GetControllerInfo(*serverUrl)
		if err != nil {
			log.Printf("Could not obtain controller info: %v\n", err)
			syscall.Exit(1)
		}

		err = nebulahelper.ConfigureEnrolledTunnel(*serverUrl, *ott, *configPath, info)
		if err != nil {
			log.Printf("Could not enroll on server: %v\n", err)
			syscall.Exit(1)
		}

		log.Printf("Successfully obtained mesh config\n")
		syscall.Exit(0)
	default:
		flag.Usage()
	}
}

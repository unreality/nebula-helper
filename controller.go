package nebula_helper

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"github.com/slackhq/nebula/cert"
	"golang.org/x/crypto/curve25519"
	"gopkg.in/yaml.v3"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
)

type NebulaConfig struct {
	CertEndpoint       string `json:"certEndpoint"`
	OidcClientID       string `json:"oidcClientID"`
	OidcConfigURL      string `json:"oidcConfigURL"`
	SignEndpoint       string `json:"signEndpoint"`
	NodeConfigEndpoint string `json:"nodeConfigEndpoint"`
	CACert             string `json:"ca"`
}

type NebulaControllerError struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

type ConfigMetadata struct {
	ControllerURL string `json:"controller_url,omitempty"`
	TunnelName    string `json:"tunnel_name,omitempty"`
	Fingerprint   string `json:"fingerprint,omitempty"`
}

type SignResponse struct {
	Certificate string              `json:"certificate"`
	StaticHosts map[string][]string `json:"static_host_map"`
	LightHouses []string            `json:"lighthouses"`
	BlockList   []string            `json:"blocklist"`
}

type EnrollRequest struct {
	OTT       string `json:"ott"`
	PublicKey string `json:"public_key"`
}

type SignRequest struct {
	PublicKey string `json:"public_key"`
	Duration  int    `json:"duration,omitempty"`
	IP        string `json:"ip,omitempty"`
}

type PKIConfig struct {
	CA        string   `yaml:"ca"`
	Cert      string   `yaml:"cert"`
	Key       string   `yaml:"key"`
	BlockList []string `yaml:"blocklist"`
}

type LighthouseConfig struct {
	AmLighthouse bool     `yaml:"am_lighthouse"`
	Hosts        []string `yaml:"hosts"`
}

type MinNodeConfig struct {
	PKI         PKIConfig           `yaml:"pki"`
	StaticHosts map[string][]string `yaml:"static_host_map"`
	Lighthouse  LighthouseConfig    `yaml:"lighthouse"`
}

var nebulaConfig *NebulaConfig

func createTempKey(configDir string) (string, string) {
	var pubkey, privkey [32]byte
	if _, err := io.ReadFull(rand.Reader, privkey[:]); err != nil {
		panic(err)
	}
	curve25519.ScalarBaseMult(&pubkey, &privkey)

	pubKeyPath := path.Join(configDir, "node.pub")

	os.Remove(pubKeyPath)
	err := ioutil.WriteFile(pubKeyPath, cert.MarshalX25519PublicKey(pubkey[:]), 0600)
	if err != nil {
		log.Fatalf("Could not save temp public key!")
	}

	privKeyPath := path.Join(configDir, "node.key")
	os.Remove(privKeyPath)
	err = ioutil.WriteFile(privKeyPath, cert.MarshalX25519PrivateKey(privkey[:]), 0600)
	if err != nil {
		log.Fatalf("error while writing out-key: %s", err)
	}

	return pubKeyPath, privKeyPath
}

func signPublicKey(nebulaConfig *NebulaConfig, accessToken string, pubKeyFile string) (*SignResponse, error) {

	pubKeyBytes, err := os.ReadFile(pubKeyFile)

	if err != nil {
		return nil, err
	}

	var signReq SignRequest
	signReq.PublicKey = string(pubKeyBytes)

	signReqJson, err := json.Marshal(signReq)
	if err != nil {
		return nil, err
	}

	client := &http.Client{}
	req, err := http.NewRequest("POST", nebulaConfig.SignEndpoint, bytes.NewBuffer(signReqJson))

	if err != nil {
		log.Printf("%v\n", err)
		return nil, err
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	req.Header.Add("Content-Type", "application/json")

	signResp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	defer signResp.Body.Close()

	if signResp.StatusCode != 200 {
		b, _ := io.ReadAll(signResp.Body)
		log.Fatalf("%s", b)
	}

	var signResponse SignResponse

	err = json.NewDecoder(signResp.Body).Decode(&signResponse)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	return &signResponse, nil
}

func CreateTempConfig(signResponse *SignResponse, configPath string, privKeyFile string, caCert string) error {

	certFilePath := filepath.Join(configPath, "node.crt")
	os.Remove(certFilePath)
	out, err := os.Create(certFilePath)
	if err != nil {
		return fmt.Errorf("Could not create certificate file!")
	}
	out.WriteString(signResponse.Certificate)
	out.Close()

	caFilePath := filepath.Join(configPath, "ca.crt")
	os.Remove(caFilePath)
	out, err = os.Create(caFilePath)
	if err != nil {
		return fmt.Errorf("Could not create ca file!")
	}
	out.WriteString(caCert)
	out.Close()

	mnc := MinNodeConfig{
		PKI: PKIConfig{
			CA:        filepath.Base(caFilePath),
			Cert:      filepath.Base(certFilePath),
			Key:       filepath.Base(privKeyFile),
			BlockList: signResponse.BlockList,
		},
		StaticHosts: signResponse.StaticHosts,
		Lighthouse: LighthouseConfig{
			AmLighthouse: false,
			Hosts:        signResponse.LightHouses,
		},
	}

	controllerSetConfigPath := filepath.Join(configPath, "zz_controller_config.yml")
	os.Remove(controllerSetConfigPath)
	out, err = os.Create(controllerSetConfigPath)
	if err != nil {
		return fmt.Errorf("Could not create controller config set!")
	}
	outBytes, err := yaml.Marshal(mnc)
	out.Write(outBytes)
	out.Close()

	defaultConfigPath := filepath.Join(configPath, "default.yml")

	if _, err := os.Stat(defaultConfigPath); err == nil {
		// path/to/whatever exists
	} else if os.IsNotExist(err) {
		//copy default config in
		if _, err := os.Stat("default.yml"); err == nil {
			defaultConfigBytes, err := os.ReadFile("default.yml")
			if err != nil {
				return fmt.Errorf("Could not open default.yml!")
			}

			out, err = os.Create(defaultConfigPath)
			if err != nil {
				return fmt.Errorf("Could not copy default.yml!")
			}
			out.Write(defaultConfigBytes)
			out.Close()
		} else {
			log.Println("Warning - no default.yml found, config will be minimal")
		}
	}

	return nil
}

func GetControllerInfo(urlStr string) (*NebulaConfig, error) {
	u, err := url.Parse(urlStr)
	u.Path = path.Join(u.Path, "config")

	client := &http.Client{}
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	nebulaConfigResp, err := client.Do(req)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	defer nebulaConfigResp.Body.Close()

	var nebulaConfig NebulaConfig

	err = json.NewDecoder(nebulaConfigResp.Body).Decode(&nebulaConfig)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	return &nebulaConfig, nil
}

func LoadTunnelMetadata(configPath string) *ConfigMetadata {

	metadataPath := filepath.Join(configPath, "metadata.json")
	metadataRaw, err := ioutil.ReadFile(metadataPath)

	if err != nil {
		return nil
	}

	var metaData ConfigMetadata

	err = json.Unmarshal(metadataRaw, &metaData)

	if err != nil {
		return nil
	}

	return &metaData
}

func ConfigureOIDCTunnel(accessToken string, configPath string, nebulaConfig *NebulaConfig) error {
	pubKeyFile, privKeyFile := createTempKey(configPath)

	signResponse, err := signPublicKey(nebulaConfig, accessToken, pubKeyFile)
	if err != nil {
		return fmt.Errorf("Bad sign response from controller: %v", err)
	}

	return CreateTempConfig(signResponse, configPath, privKeyFile, nebulaConfig.CACert)

}

func ConfigureEnrolledTunnel(serverURL string, ott string, configPath string, nebulaConfig *NebulaConfig) error {
	pubKeyFile, privKeyFile := createTempKey(configPath)

	signResponse, err := EnrollOnServer(serverURL, ott, pubKeyFile)
	if err != nil {
		return fmt.Errorf("Bad response from controller: %v", err)
	}

	return CreateTempConfig(signResponse, configPath, privKeyFile, nebulaConfig.CACert)

}

func EnrollOnServer(serverURL string, ott string, pubKeyFile string) (*SignResponse, error) {
	pubKeyPEM, err := os.ReadFile(pubKeyFile)

	if err != nil {
		return nil, err
	}

	u, err := url.Parse(serverURL)
	u.Path = path.Join(u.Path, "enroll")

	enrollRequest := EnrollRequest{
		OTT:       ott,
		PublicKey: string(pubKeyPEM),
	}

	enrollRequestJSON, err := json.Marshal(enrollRequest)

	client := &http.Client{}
	req, err := http.NewRequest("POST", u.String(), bytes.NewBuffer(enrollRequestJSON))
	if err != nil {
		log.Println(err)
		return nil, err
	}
	req.Header.Add("Content-Type", "application/json")

	enrollResp, err := client.Do(req)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	defer enrollResp.Body.Close()

	if enrollResp.StatusCode != 200 {
		var controllerError NebulaControllerError
		err = json.NewDecoder(enrollResp.Body).Decode(&controllerError)
		if err != nil {
			log.Println(err)
			return nil, err
		}

		return nil, fmt.Errorf("%s", controllerError.Message)
	}

	var signResponse SignResponse

	err = json.NewDecoder(enrollResp.Body).Decode(&signResponse)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	return &signResponse, nil
}

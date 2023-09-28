package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

type RuleReq struct {
	GwIP string `json:"gwip"`
	//Teid []string `json:"teid"`
	Ip []string `json:"ip"`
}

type RegisterReq struct {
	GwIP      string `json:"gwip"`
	CoreMac   string `json:"coremac"`
	AccessMac string `json:"accessmac"`
	Hostname  string `json:"hostname"`
}

type GWRegisterReq struct {
	GwIP  string `json:"gwip"`
	GwMac string `json:"gwmac"`
}

type operation int

const (
	add operation = iota
	del
)

var addedRule map[string]string
var registeredUPFs map[string]string // [gwip] coremac

func main() {
	log.SetLevel(log.TraceLevel)
	log.Traceln("application started")
	addedRule = make(map[string]string)
	registeredUPFs = make(map[string]string)
	http.HandleFunc("/addrule", addRuleHandler)
	http.HandleFunc("/register", registerHandler)
	server := http.Server{Addr: ":8080"}

	server.ListenAndServe()

}

func addRuleHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "PUT":
		fallthrough
	case "POST":
		body, err := io.ReadAll(r.Body)
		if err != nil {
			log.Errorln("http req read body failed.")
			sendHTTPResp(http.StatusBadRequest, w)
		}

		log.Traceln(string(body))

		//var nwSlice NetworkSlice
		var rulereq RuleReq
		//fmt.Println("parham log : http body = ", body)
		err = json.Unmarshal(body, &rulereq)
		if err != nil || rulereq.GwIP == "" || len(rulereq.Ip) == 0 {
			log.Errorln("Json unmarshal failed for http request")
			sendHTTPResp(http.StatusBadRequest, w)
		}
		for _, i := range rulereq.Ip {
			added := false
			gwip, added := addedRule[i]
			if !added {
				err = execRule(rulereq.GwIP, i, add)
				if err != nil {
					sendHTTPResp(http.StatusInternalServerError, w)
					return
				}
				addedRule[i] = rulereq.GwIP
				continue
			}
			if rulereq.GwIP != gwip {
				err = execRule(gwip, i, del)
				if err != nil {
					sendHTTPResp(http.StatusInternalServerError, w)
					return
				}
				err = execRule(rulereq.GwIP, i, add)
				if err != nil {
					sendHTTPResp(http.StatusInternalServerError, w)
					return
				}
				addedRule[i] = rulereq.GwIP
			}

		}
		if err != nil {
			sendHTTPResp(http.StatusInternalServerError, w)
			return
		}
		sendHTTPResp(http.StatusCreated, w)
	default:
		log.Traceln(w, "Sorry, only PUT and POST methods are supported.")
		sendHTTPResp(http.StatusMethodNotAllowed, w)
	}
}

func markFromIP(ip string) string {
	octets := strings.Split(ip, ".")
	if len(octets) == 4 {
		mark := octets[3]
		return mark
	} else {
		log.Errorln("invalind gateway ip format. GwIP = ", ip)
		return ""
	}
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "PUT":
		fallthrough
	case "POST":
		body, err := io.ReadAll(r.Body)
		if err != nil {
			log.Errorln("http req read body failed.")
			sendHTTPResp(http.StatusBadRequest, w)
		}

		log.Traceln(string(body))

		//var nwSlice NetworkSlice
		var regReq RegisterReq
		//fmt.Println("parham log : http body = ", body)
		err = json.Unmarshal(body, &regReq)
		if err != nil || regReq.CoreMac == "" || regReq.GwIP == "" {
			log.Errorln("Json unmarshal failed for http request")
			sendHTTPResp(http.StatusBadRequest, w)
		}
		fmt.Println("regReq = ", regReq)
		if regUPFCore, ok := registeredUPFs[regReq.GwIP]; ok && regUPFCore == regReq.CoreMac {
			sendHTTPResp(http.StatusCreated, w)
			return
		}
		var arpExists bool
		if _, ok := registeredUPFs[regReq.GwIP]; ok {
			arpExists = true
		}
		iface := getifaceName(regReq.GwIP)
		execArp(regReq.GwIP, regReq.AccessMac, iface, arpExists)
		go sendGWMac(iface, regReq.Hostname, regReq.GwIP)
		registeredUPFs[regReq.GwIP] = regReq.CoreMac
		sendHTTPResp(http.StatusCreated, w)
		return

	default:
		log.Traceln(w, "Sorry, only PUT and POST methods are supported.")
		sendHTTPResp(http.StatusMethodNotAllowed, w)
	}
}

func execArp(gwIp, mac string, iface string, arpExists bool) error {

	var cmd *exec.Cmd

	if arpExists == true {
		cmd = exec.Command("arp", "-d", gwIp, "-i", iface)
		combinedOutput, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Printf("Error executing command: %v\nCombined Output: %s", cmd.String(), combinedOutput)
			return err
		}
		log.Traceln("static arp deleted successfully for ip : ", gwIp)
	}
	cmd = exec.Command("arp", "-s", gwIp, mac, "-i", iface)
	combinedOutput, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Error executing command: %v\nCombined Output: %s", cmd.String(), combinedOutput)
		return err
	}

	log.Traceln("static arp applied successfully for ip : ", gwIp)
	return nil
}

func getifaceName(gwIp string) string {
	cmd := exec.Command("ifconfig", "|", "grep", "-B1", gwIp, "|", "head", "-n1", "awk", "'{print $1;}'")
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Error running ip command: %v\n", err)
		return ""
	}

	// Parse the route information to extract the gateway IP address
	iface := string(output)
	return iface

}
func GetMac(ifname string) string {

	// Get the list of network interfaces.
	ifaces, err := net.Interfaces()
	if err != nil {
		fmt.Println("Error:", err)
		return ""
	}

	// Find the interface with the specified name.
	var targetInterface net.Interface
	for _, iface := range ifaces {
		if iface.Name == ifname {
			targetInterface = iface
			break
		}
	}

	if targetInterface.Name == "" {
		return ""
	}

	return targetInterface.HardwareAddr.String()
}
func sendGWMac(ifname, hostname, gwIP string) {
	gwMac := GetMac(ifname)
	GWRegisterReq := GWRegisterReq{
		GwIP:  gwIP,
		GwMac: gwMac,
	}
	fmt.Println("GWRegisterReq = ", GWRegisterReq)
	registerReqJson, _ := json.Marshal(GWRegisterReq)

	requestURL := fmt.Sprintf("http://%v:8080/registergw", hostname)

	jsonBody := []byte(registerReqJson)

	bodyReader := bytes.NewReader(jsonBody)
	req, err := http.NewRequest(http.MethodPost, requestURL, bodyReader)
	if err != nil {
		log.Errorf("client: could not create request: %s\n", err)
	}

	req.Header.Set("Content-Type", "application/json")

	client := http.Client{
		Timeout: 10 * time.Second,
	}
	done := false
	for !done {
		resp, err := client.Do(req)
		if err != nil {
			log.Errorf("client: error making http request: %s\n", err)
		} else if resp.StatusCode == http.StatusCreated {
			done = true
			return
		}
		time.Sleep(1 * time.Second)
	}

}

func decimalToHex(ipString string) (string, error) {
	parts := strings.Split(ipString, ".")
	if len(parts) != 4 {
		return "", fmt.Errorf("Invalid IP address format")
	}

	hexParts := make([]string, 4)
	for i, part := range parts {
		decimal, err := strconv.Atoi(part)
		if err != nil || decimal < 0 || decimal > 255 {
			return "", fmt.Errorf("Invalid IP address")
		}
		hexParts[i] = fmt.Sprintf("%02x", decimal)
	}

	return strings.Join(hexParts, ""), nil
}

func execRule(gwip, ueip string, op operation) error {
	mark := markFromIP(gwip)
	hexIP, err := decimalToHex(ueip)
	if err != nil {
		return err
	}
	var oper string
	switch op {
	case add:
		oper = "-A"
	case del:
		oper = "-D"
	}
	m32Rule := fmt.Sprint(`56&0xffffffff=0x`, hexIP, ``)
	cmd := exec.Command("iptables", "-t", "mangle", oper, "PREROUTING", "-d", "192.168.252.3", "-p", "udp", "--dport", "2152", "-m", "u32", "--u32", m32Rule, "-j", "MARK", "--set-mark", mark)
	log.Traceln("executing command : ", cmd.String())
	combinedOutput, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Error executing command: %v\nCombined Output: %s", cmd.String(), combinedOutput)
		return err
	}
	log.Traceln("iptables rule applied successfully for ip : ", ueip)
	return nil
}

func sendHTTPResp(status int, w http.ResponseWriter) {
	w.WriteHeader(status)
	w.Header().Set("Content-Type", "application/json")

	resp := make(map[string]string)

	switch status {
	case http.StatusCreated:
		resp["message"] = "Status Created"
	default:
		resp["message"] = "Failed to add slice"
	}

	jsonResp, err := json.Marshal(resp)
	if err != nil {
		log.Errorln("Error happened in JSON marshal. Err: ", err)
	}

	_, err = w.Write(jsonResp)
	if err != nil {
		log.Errorln("http response write failed : ", err)
	}
}

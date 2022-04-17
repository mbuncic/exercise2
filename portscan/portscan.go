// Package scans a target passed as CLI argument. Target can be a single IP or CIDR address.
// If a previous scan was run, package compares the two scans and displays differences.

package main

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
)

const LOGDIR = "./data/"
const LOGFILE = LOGDIR + "portscan.xml"

// ScanMap type is a string map of a slice of strings (PortsMap type) inside another string map.
// It is used to store reduced data from Nmaprun struct.
// Example PortsMap map[80]["+", "tcp", "open"]string
// Example HostsMap map[192.168.1.1]map[80]["+", "tcp", "open"]string
type PortsMap map[string][]string
type HostsMap map[string]PortsMap

// Nmaprun struct is a generated struct to store data from XML log file.
type Nmaprun struct {
	XMLName          xml.Name `xml:"nmaprun"`
	Text             string   `xml:",chardata"`
	Scanner          string   `xml:"scanner,attr"`
	Args             string   `xml:"args,attr"`
	Start            string   `xml:"start,attr"`
	Startstr         string   `xml:"startstr,attr"`
	Version          string   `xml:"version,attr"`
	Xmloutputversion string   `xml:"xmloutputversion,attr"`
	Scaninfo         struct {
		Text        string `xml:",chardata"`
		Type        string `xml:"type,attr"`
		Protocol    string `xml:"protocol,attr"`
		Numservices string `xml:"numservices,attr"`
		Services    string `xml:"services,attr"`
	} `xml:"scaninfo"`
	Verbose struct {
		Text  string `xml:",chardata"`
		Level string `xml:"level,attr"`
	} `xml:"verbose"`
	Debugging struct {
		Text  string `xml:",chardata"`
		Level string `xml:"level,attr"`
	} `xml:"debugging"`
	Hosthint []struct {
		Text   string `xml:",chardata"`
		Status struct {
			Text      string `xml:",chardata"`
			State     string `xml:"state,attr"`
			Reason    string `xml:"reason,attr"`
			ReasonTtl string `xml:"reason_ttl,attr"`
		} `xml:"status"`
		Address []struct {
			Text     string `xml:",chardata"`
			Addr     string `xml:"addr,attr"`
			Addrtype string `xml:"addrtype,attr"`
			Vendor   string `xml:"vendor,attr"`
		} `xml:"address"`
		Hostnames string `xml:"hostnames"`
	} `xml:"hosthint"`
	Host []struct {
		Text      string `xml:",chardata"`
		Starttime string `xml:"starttime,attr"`
		Endtime   string `xml:"endtime,attr"`
		Status    struct {
			Text      string `xml:",chardata"`
			State     string `xml:"state,attr"`
			Reason    string `xml:"reason,attr"`
			ReasonTtl string `xml:"reason_ttl,attr"`
		} `xml:"status"`
		Address []struct {
			Text     string `xml:",chardata"`
			Addr     string `xml:"addr,attr"`
			Addrtype string `xml:"addrtype,attr"`
			Vendor   string `xml:"vendor,attr"`
		} `xml:"address"`
		Hostnames struct {
			Text     string `xml:",chardata"`
			Hostname struct {
				Text string `xml:",chardata"`
				Name string `xml:"name,attr"`
				Type string `xml:"type,attr"`
			} `xml:"hostname"`
		} `xml:"hostnames"`
		Ports struct {
			Text       string `xml:",chardata"`
			Extraports struct {
				Text         string `xml:",chardata"`
				State        string `xml:"state,attr"`
				Count        string `xml:"count,attr"`
				Extrareasons []struct {
					Text   string `xml:",chardata"`
					Reason string `xml:"reason,attr"`
					Count  string `xml:"count,attr"`
					Proto  string `xml:"proto,attr"`
					Ports  string `xml:"ports,attr"`
				} `xml:"extrareasons"`
			} `xml:"extraports"`
			Port []struct {
				Text     string `xml:",chardata"`
				Protocol string `xml:"protocol,attr"`
				Portid   string `xml:"portid,attr"`
				State    struct {
					Text      string `xml:",chardata"`
					State     string `xml:"state,attr"`
					Reason    string `xml:"reason,attr"`
					ReasonTtl string `xml:"reason_ttl,attr"`
				} `xml:"state"`
				Service struct {
					Text   string `xml:",chardata"`
					Name   string `xml:"name,attr"`
					Method string `xml:"method,attr"`
					Conf   string `xml:"conf,attr"`
				} `xml:"service"`
			} `xml:"port"`
		} `xml:"ports"`
		Times struct {
			Text   string `xml:",chardata"`
			Srtt   string `xml:"srtt,attr"`
			Rttvar string `xml:"rttvar,attr"`
			To     string `xml:"to,attr"`
		} `xml:"times"`
	} `xml:"host"`
	Runstats struct {
		Text     string `xml:",chardata"`
		Finished struct {
			Text    string `xml:",chardata"`
			Time    string `xml:"time,attr"`
			Timestr string `xml:"timestr,attr"`
			Summary string `xml:"summary,attr"`
			Elapsed string `xml:"elapsed,attr"`
			Exit    string `xml:"exit,attr"`
		} `xml:"finished"`
		Hosts struct {
			Text  string `xml:",chardata"`
			Up    string `xml:"up,attr"`
			Down  string `xml:"down,attr"`
			Total string `xml:"total,attr"`
		} `xml:"hosts"`
	} `xml:"runstats"`
}

func main() {
	// Check if nmap exists
	if _, err := exec.LookPath("nmap"); err != nil {
		log.Fatal(err)
	}

	// Check for input argument
	if len(os.Args) != 2 {
		log.Fatal(errors.New("didn't provide IP or CIDR argument"))
	}
	inputAddress := os.Args[1]

	// Check argument format
	if _, _, err := net.ParseCIDR(inputAddress); err != nil {
		if net.ParseIP(inputAddress) == nil {
			log.Fatal(errors.New("invalid IP or CIDR address"))
		}
	}

	// Run scan
	hostsMap, err := doNmapRun(inputAddress)
	if err != nil {
		log.Fatal(err)
	}

	// Print scan results
	fmt.Println("Scan results:")
	sortedHostKeys := sortHostKeys(hostsMap)
	for _, hostKey := range sortedHostKeys {
		fmt.Println(hostKey)
		portsMap := hostsMap[hostKey.String()]
		sortedPortKeys := sortPortKeys(portsMap)
		for _, portKeyInt := range sortedPortKeys {
			portKey := strconv.Itoa(portKeyInt)
			portSlice := portsMap[portKey]
			portDiff := portSlice[0]
			portNumber := portKey
			portProtocol := portSlice[1]
			portState := portSlice[2]
			fmt.Printf("%s %s/%s\t%s\n", portDiff, portNumber, portProtocol, portState)
		}
	}
}

// Function doNmapRun runs a Nmap scan on inputAddress and returns a HostsMap or an error.
func doNmapRun(inputAddress string) (HostsMap, error) {
	// Check if log exists
	if _, err := os.Stat(LOGFILE); errors.Is(err, os.ErrNotExist) {
		if err := createLogFile(LOGFILE); err != nil {
			return nil, err
		}
	}

	// Read previous scan, do a scan, read new results and compare
	oldHostsMap, oldTarget, err := xmlFileToMap(LOGFILE)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command("nmap", "--privileged", "-oX", LOGFILE, "-v0", inputAddress)
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	hostsMap, newTarget, err := xmlFileToMap(LOGFILE)
	if err != nil {
		return nil, err
	}
	if oldTarget == newTarget {
		hostsMap = diffScans(oldHostsMap, hostsMap)
	}
	return hostsMap, nil
}

// Function xmlFileToMap converts XML read from file into a ScanMap.
// Takes in a filename string and returns a HostsMap and scan target, or an error.
func xmlFileToMap(filename string) (HostsMap, string, error) {
	var nmaprun Nmaprun
	hostsMap := make(HostsMap)

	xmlFile, err := os.Open(filename)
	if err != nil {
		return nil, "", err
	}
	defer xmlFile.Close()
	body, _ := io.ReadAll(xmlFile)
	if err := xml.Unmarshal(body, &nmaprun); err != nil {
		return nil, "", err
	}
	for _, host := range nmaprun.Host {
		hostKey := host.Address[0].Addr
		hostsMap[hostKey] = make(PortsMap)
		for _, port := range host.Ports.Port {
			hostsMap[hostKey][port.Portid] = []string{" ", port.Protocol, port.State.State}
		}
	}
	target := nmaprun.Args[strings.LastIndex(nmaprun.Args, " ")+1:]
	return hostsMap, target, nil
}

// Function createLogFile creates a logfile and fills it with empty XML
// structure. Takes in a filename string, and returns an error or nil.
func createLogFile(filename string) error {
	var emptyNmaprun Nmaprun

	if _, err := os.Stat(LOGDIR); errors.Is(err, os.ErrNotExist) {
		os.Mkdir(LOGDIR, 0755)
	}

	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	body, err := xml.Marshal(emptyNmaprun)
	if err != nil {
		return err
	}
	file.Write(body)
	return nil
}

// Function diffScans compares two ScanMaps, combines them, marks removed
// ports with "-", new ports with "+" and returns the combined ScanMap
func diffScans(oldHostsMap HostsMap, newHostsMap HostsMap) HostsMap {
	// iterate through scanned hosts and ports and check for new ones
	for newHostKey, newPortsMap := range newHostsMap {
		for newPortKey, newPortValue := range newPortsMap {
			_, ok := oldHostsMap[newHostKey][newPortKey]
			if !ok {
				newPortValue[0] = "+"
			}
		}
	}

	// iterate through previously scanned hosts and ports and check if they still exist
	for oldHostKey, oldPortsMap := range oldHostsMap {
		for oldPortKey, oldPortValue := range oldPortsMap {
			_, ok := newHostsMap[oldHostKey][oldPortKey]
			if !ok {
				_, ok = newHostsMap[oldHostKey]
				if !ok {
					newHostsMap[oldHostKey] = make(map[string][]string)
				}
				oldPortValue[0] = "-"
				newHostsMap[oldHostKey][oldPortKey] = oldPortValue
			}
		}
	}
	return newHostsMap
}

// Function sortHostKeys takes in a ScanMap and returns a net.IP slice of
// sorted IP addresses.
func sortHostKeys(hostsMap HostsMap) []net.IP {
	sortedHostKeys := make([]net.IP, 0, len(hostsMap))
	for hostKey := range hostsMap {
		sortedHostKeys = append(sortedHostKeys, net.ParseIP(hostKey))
	}
	sort.Slice(sortedHostKeys, func(i, j int) bool {
		return bytes.Compare(sortedHostKeys[i], sortedHostKeys[j]) < 0
	})
	return sortedHostKeys
}

// Function sortPortKeys takes in a PortsMap and resturn an int slice of
// sorted ports.
func sortPortKeys(portsMap PortsMap) []int {
	sortedPortKeys := make([]int, 0, len(portsMap))
	for portKey := range portsMap {
		portKeyInt, _ := strconv.Atoi(portKey)
		sortedPortKeys = append(sortedPortKeys, portKeyInt)
	}
	sort.Ints(sortedPortKeys)
	return sortedPortKeys
}

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/lair-framework/api-server/client"
	"github.com/lair-framework/go-burp"
	"github.com/lair-framework/go-lair"
)

const (
	version = "1.0.1"
	tool    = "burp"
	usage   = `
	Parses a burp XML file into a lair project.
	Usage:
	drone-burp [options] <id> <filename>
	export LAIR_ID=<id>; drone-burp [options] <filename>
	Options:
	-v              show version and exit
	-h              show usage and exit
	-k              allow insecure SSL connections
	-force-ports    disable data protection in the API server for excessive ports
	-limit-hosts    only import hosts that have listening ports
	-tags           a comma separated list of tags to add to every host that is imported
	`
)

type hostMap struct {
	Hosts         map[string]bool
	Vulnerability *lair.Issue
}

func riskToCVSS(risk string) float64 {
	switch risk {
	case "High":
		return 10.0
	case "Medium":
		return 5.0
	case "Low":
		return 3.0
	default:
		return 0.0
	}
}

func buildProject(burp *burp.Issues, projectID string, tags []string) (*lair.Project, error) {
	project := &lair.Project{}
	project.ID = projectID
	project.Tool = tool
	vulnHostMap := make(map[string]hostMap)
	for _, issue := range burp.Issues {
		if riskToCVSS(issue.Severity) == 0.0 {
			continue
		}
		lhost := &lair.Host{Tags: tags}
		u, err := url.Parse(issue.Host.Name)
		if err != nil {
			return nil, err
		}
		host, port, err := net.SplitHostPort(u.Host)
		if err != nil {
			//If the URL doesn't contain a port it will fail out, so we attempt to look at the scheme
			switch u.Scheme {
			case "http":
				host = u.Host
				port = "80"
			case "https":
				host = u.Host
				port = "443"
			default:
				return nil, err
			}
		}
		portNum, err := strconv.Atoi(port)
		if err != nil {
			return nil, err
		}
		//Check if we have a valid IP address.  For some reason Burp can
		//export data without IP set and the DNS name in the URL.
		if issue.Host.IP != "" {
			lhost.IPv4 = issue.Host.IP
		} else if net.ParseIP(host) != nil {
			lhost.IPv4 = host
		} else {
			continue
		}
		lhost.Hostnames = append(lhost.Hostnames, host)
		hostStr := fmt.Sprintf("%s:%s:%d:%s", lhost.IPv4, issue.Path, portNum, "tcp")
		//If the Issue hasn't been seen create it
		if _, ok := vulnHostMap[issue.Type]; !ok {
			v := &lair.Issue{}
			v.Title = issue.Name
			v.Description = issue.IssueBackground
			v.Solution = issue.RemediationBackground
			v.Evidence = issue.IssueDetail
			v.CVSS = riskToCVSS(issue.Severity)
			plugin := &lair.PluginID{Tool: tool, ID: issue.Type}
			v.PluginIDs = append(v.PluginIDs, *plugin)
			v.IdentifiedBy = append(v.IdentifiedBy, lair.IdentifiedBy{Tool: tool})
			vulnHostMap[issue.Type] = hostMap{Hosts: make(map[string]bool), Vulnerability: v}
		}
		v := vulnHostMap[issue.Type]
		//Create a note for each request response for a vulnerability
		note := &lair.Note{}
		note.Title = fmt.Sprintf("%s %s", issue.Host.Name+issue.Path, issue.SerialNumber)
		for _, requestResponse := range issue.RequestResponses {
			request := requestResponse.Request.Data
			response := requestResponse.Response.Data
			note.Content = fmt.Sprintf("Request:\n%s\nResponse:\n%s", request, response)
		}
		v.Vulnerability.Notes = append(v.Vulnerability.Notes, *note)
		v.Hosts[hostStr] = true
		lhost.Services = append(lhost.Services, lair.Service{Port: portNum,
			Protocol: "tcp", Service: u.Scheme})
		project.Hosts = append(project.Hosts, *lhost)
	}
	for _, hm := range vulnHostMap {
		for key := range hm.Hosts {
			tokens := strings.Split(key, ":")
			portNum, err := strconv.Atoi(tokens[2])
			if err != nil {
				return nil, err
			}
			hostKey := &lair.IssueHost{
				IPv4:     tokens[0],
				Port:     portNum,
				Protocol: tokens[3],
			}
			hm.Vulnerability.Hosts = append(hm.Vulnerability.Hosts, *hostKey)
		}
		project.Issues = append(project.Issues, *hm.Vulnerability)
	}
	c := &lair.Command{Tool: tool, Command: "Burp Scan"}
	project.Commands = append(project.Commands, *c)
	return project, nil
}

func main() {
	showVersion := flag.Bool("v", false, "")
	insecureSSL := flag.Bool("k", false, "")
	forcePorts := flag.Bool("force-ports", false, "")
	limitHosts := flag.Bool("limit-hosts", false, "")
	tags := flag.String("tags", "", "")
	flag.Usage = func() {
		fmt.Println(usage)
	}
	flag.Parse()
	if *showVersion {
		log.Println(version)
		os.Exit(0)
	}
	lairURL := os.Getenv("LAIR_API_SERVER")
	if lairURL == "" {
		log.Fatal("Fatal: Missing LAIR_API_SERVER environment variable")
	}
	lairPID := os.Getenv("LAIR_ID")
	if lairPID == "" {
		log.Fatal("Fatal: Missing LAIR_ID")
	}
	var filename string
	switch len(flag.Args()) {
	case 2:
		lairPID = flag.Arg(0)
		filename = flag.Arg(1)
	case 1:
		filename = flag.Arg(0)
	default:
		log.Fatal("Fatal: Missing required argument")
	}

	u, err := url.Parse(lairURL)
	if err != nil {
		log.Fatalf("Fatal: Error parsing LAIR_API_SERVER URL. Error %s", err.Error())
	}
	if u.User == nil {
		log.Fatal("Fatal: Missing username and/or password")
	}
	user := u.User.Username()
	pass, _ := u.User.Password()
	if user == "" || pass == "" {
		log.Fatal("Fatal: Missing username and/or password")
	}
	c, err := client.New(&client.COptions{
		User:               user,
		Password:           pass,
		Host:               u.Host,
		Scheme:             u.Scheme,
		InsecureSkipVerify: *insecureSSL,
	})

	if err != nil {
		log.Fatalf("Fatal: Error setting up client: Error %s", err.Error())
	}

	buf, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatalf("Fatal: Could not open file. Error %s", err.Error())
	}
	burpData, err := burp.Parse(buf)
	if err != nil {
		log.Fatalf("Fatal: Error parsing burp data. Error %s", err.Error())
	}
	hostTags := []string{}
	if *tags != "" {
		hostTags = strings.Split(*tags, ",")
	}
	project, err := buildProject(burpData, lairPID, hostTags)
	if err != nil {
		log.Fatal(err.Error())
	}

	res, err := c.ImportProject(&client.DOptions{ForcePorts: *forcePorts, LimitHosts: *limitHosts}, project)
	if err != nil {
		log.Fatalf("Fatal: Unable to import project. Error %s", err)
	}
	defer res.Body.Close()
	droneRes := &client.Response{}
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Fatalf("Fatal: Error %s", err.Error())
	}
	if err := json.Unmarshal(body, droneRes); err != nil {
		log.Fatalf("Fatal: Could not unmarshal JSON. Error %s", err.Error())
	}
	if droneRes.Status == "Error" {
		log.Fatalf("Fatal: Import failed. Error %s", droneRes.Message)
	}
	log.Println("Success: Operation completed successfully")
}

package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

var wg sync.WaitGroup
var sem = make(chan int8, 64)

// struct to hold required security.txt file fields.
type Sdt struct {
	site     string   // "google.com"
	contacts []string // ["https://g.co/vulnz", "mailto:security@google.com"]
	expires  string   // "Thu, 31 Dec 2020 18:37:07 -0800"
}

// loadHosts - Read hosts from top-1m-alexa.csv. Return as string slice.
func loadHosts(fileName string) []string {
	hosts := make([]string, 0)

	file, err := os.Open(fileName)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var countHost = strings.Split(scanner.Text(), ",")
		hosts = append(hosts, countHost[1])
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	return hosts
}

func choke() {
	<-sem
	wg.Done()
}

// checkHost - Check to see if /.well-known/security.txt is present.
func checkHost(host string, transport *http.Transport, showAll *bool) {
	defer choke()
	path := "/.well-known/security.txt"

	client := &http.Client{
		Timeout:   time.Second * 20,
		Transport: transport,
	}

	getReq, err := http.NewRequest("GET", "https://"+host+path, nil)
	if err != nil {
		log.Println(err)
		log.Println("----------------------------------")
		return
	}

	getReq.Header.Set("User-Agent", "survey-security-dot-txt/0.1")
	getReq.Header.Set("Cache-Control", "no-cache")

	getResp, err := client.Do(getReq)
	if err != nil {
		log.Println(err)
		log.Println("----------------------------------")
		return
	}
	defer getResp.Body.Close()

	if getResp.StatusCode == 200 {
		contentType := getResp.Header.Values("content-type")
		for _, ct := range contentType {
			if strings.Contains(strings.ToLower(ct), "text/plain") {
				log.Printf("Success: %v, %v, %v\n", host, path, getResp.StatusCode)
				body, err := ioutil.ReadAll(getResp.Body)
				if err != nil {
					log.Println(err)
					log.Println("----------------------------------")
					return
				}
				cts := make([]string, 0)
				exp := ""

				r := bytes.NewReader(body)

				scanner := bufio.NewScanner(r)
				for scanner.Scan() {
					line := strings.ToLower(scanner.Text())

					if strings.HasPrefix(line, "contact:") {
						var cline = strings.Split(line, "contact:")
						cts = append(cts, strings.TrimSpace(cline[1]))
						log.Printf("%s\n", strings.TrimSpace(cline[1]))
					}

					if strings.HasPrefix(line, "expires:") {
						var eline = strings.Split(line, "expires:")
						exp = strings.TrimSpace(eline[1])
						log.Printf("%s\n", strings.TrimSpace(eline[1]))
					}
				}

				if err := scanner.Err(); err != nil {
					log.Println(err)
					log.Println("----------------------------------")
					return
				}

				sdt := Sdt{
					site:     host,
					contacts: cts,
					expires:  exp,
				}

				log.Printf("%v\n", string(body))
				log.Println("----------------------------------")

				// Only output if it has more than 1 contact unless the user specified otherwise
				if *showAll || len(sdt.contacts) > 0 {
					fmt.Printf("%q\n", sdt)
				}

				return
			}
		}
	}
}

func main() {
	var hosts = flag.String("hosts", "top.txt", "Plain text file containing a list of domains.")
	var all = flag.Bool("all", false, "Output all security.txt files even if they contain no contacts")
	var help = flag.Bool("help", false, "Show help.")

	flag.Parse()
	if *help || len(os.Args) == 1 {
		flag.PrintDefaults()
		return
	}

	domains := loadHosts(*hosts)
	//log.Printf("%q\n", domains)

	ssl := &tls.Config{InsecureSkipVerify: true}

	transport := &http.Transport{
		TLSClientConfig: ssl,
	}

	for _, domain := range domains {
		wg.Add(1)
		sem <- 1

		go checkHost(domain, transport, all)
	}

	wg.Wait()
	close(sem)
}

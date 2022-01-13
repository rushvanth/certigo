package cli

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"bufio"
	"log"
	"sync"
	"regexp"
	"hash/fnv"
	"time"

	"github.com/rushvanth/certigo/cli/terminal"
	"github.com/rushvanth/certigo/lib"
	"github.com/rushvanth/certigo/starttls"
	"gopkg.in/alecthomas/kingpin.v2"
)

var (
	app     = kingpin.New("certigo", "A command-line utility to examine and validate certificates to help with debugging SSL/TLS issues.")
	verbose = app.Flag("verbose", "Print verbose").Short('v').Bool()

	dump         = app.Command("dump", "Display information about a certificate from a file or stdin.")
	dumpFiles    = dump.Arg("file", "Certificate file to dump (or stdin if not specified).").ExistingFiles()
	dumpType     = dump.Flag("format", "Format of given input (PEM, DER, JCEKS, PKCS12; heuristic if missing).").Short('f').String()
	dumpPassword = dump.Flag("password", "Password for PKCS12/JCEKS key stores (reads from TTY if missing).").Short('p').String()
	dumpPem      = dump.Flag("pem", "Write output as PEM blocks instead of human-readable format.").Short('m').Bool()
	dumpJSON     = dump.Flag("json", "Write output as machine-readable JSON format.").Short('j').Bool()
	dumpBulkRead = dump.Flag("dumpBulkRead", "Takes a text file with IPs. The format of the file is one IP address per line.").Short('w').String()
    dumpBulkOutputFolder = dump.Flag("dumpBulkOutputFolder", "The name of the output folder to store the results").Short('k').String()

	connect         = app.Command("connect", "Connect to a server and print its certificate(s).")
	connectTo       = connect.Arg("server[:port]", "Hostname or IP to connect to, with optional port.").String()
	connectName     = connect.Flag("name", "Override the server name used for Server Name Indication (SNI).").Short('n').String()
	connectCaPath   = connect.Flag("ca", "Path to CA bundle (system default if unspecified).").ExistingFile()
	connectCert     = connect.Flag("cert", "Client certificate chain for connecting to server (PEM).").ExistingFile()
	connectKey      = connect.Flag("key", "Private key for client certificate, if not in same file (PEM).").ExistingFile()
	connectStartTLS = connect.Flag("start-tls", fmt.Sprintf("Enable StartTLS protocol; one of: %v.", starttls.Protocols)).Short('t').PlaceHolder("PROTOCOL").Enum(starttls.Protocols...)
	connectIdentity = connect.Flag("identity", "With --start-tls, sets the DB user or SMTP EHLO name").Default("certigo").String()
	connectProxy    = connect.Flag("proxy", "Optional URI for HTTP(s) CONNECT proxy to dial connections with").URL()
	connectTimeout  = connect.Flag("timeout", "Timeout for connecting to remote server (can be '5m', '1s', etc).").Default("5s").Duration()
	connectPem      = connect.Flag("pem", "Write output as PEM blocks instead of human-readable format.").Short('m').Bool()
	connectJSON     = connect.Flag("json", "Write output as machine-readable JSON format.").Short('j').Bool()
	connectVerify   = connect.Flag("verify", "Verify certificate chain.").Bool()
	connectBulkRead = connect.Flag("bulkread", "Takes a text file with IPs. The format of the file is one IP address per line.").Short('b').String()
    connectBulkRoutines = connect.Flag("bulkroutines", "The number of concurrent routines").Short('r').Int()
    connectBulkOutputFolder = connect.Flag("bulkoutputfolder", "The name of the output folder to store the results").Short('o').String()

	verify         = app.Command("verify", "Verify a certificate chain from file/stdin against a name.")
	verifyFile     = verify.Arg("file", "Certificate file to dump (or stdin if not specified).").ExistingFile()
	verifyType     = verify.Flag("format", "Format of given input (PEM, DER, JCEKS, PKCS12; heuristic if missing).").Short('f').String()
	verifyPassword = verify.Flag("password", "Password for PKCS12/JCEKS key stores (reads from TTY if missing).").Short('p').String()
	verifyName     = verify.Flag("name", "Server name to verify certificate against.").Short('n').Required().String()
	verifyCaPath   = verify.Flag("ca", "Path to CA bundle (system default if unspecified).").ExistingFile()
	verifyJSON     = verify.Flag("json", "Write output as machine-readable JSON format.").Short('j').Bool()
)

const (
	version = "1.12.1"
)

var mu 						sync.Mutex // guards parallel changes
var cur_routines_running 	int

func Run(args []string, tty terminal.Terminal) int {
	terminalWidth := tty.DetermineWidth()
	stdout := tty.Output()
	errOut := tty.Error()

	printErr := func(format string, args ...interface{}) int {
		_, err := fmt.Fprintf(errOut, format, args...)
		if err != nil {
			// If we can't write the error, we bail with a different return code... not much good
			// we can do at this point
			return 3
		}
		return 2
	}
	app.Version(version)

	// Alias starttls to start-tls
	connect.Flag("starttls", "").Hidden().EnumVar(connectStartTLS, starttls.Protocols...)
	// Use long help because many useful flags are under subcommands
	app.UsageTemplate(kingpin.LongHelpTemplate)

	result := lib.SimpleResult{}
	command, err := app.Parse(args)
	if err != nil {
		return printErr("%s, try --help\n", err)
	}
	switch command {
	case dump.FullCommand(): // Dump certificate

		if dumpBulkRead != nil && *dumpBulkRead != "" {
			//var items = readFileIPs(*dumpBulkRead)
			//totalItems := len(items)

			var path = "results"
			if *dumpBulkOutputFolder != "" {
				path = *dumpBulkOutputFolder
			}

			file, err := os.Open(fmt.Sprintf("%s", *dumpBulkRead))
			if err != nil {
				log.Fatalf("failed opening file: %s", err)
			}

			scanner := bufio.NewScanner(file)
			buf := make([]byte, 0, 64*1024)
			scanner.Buffer(buf, 4096*4096)
			for scanner.Scan() {
				item_val := scanner.Text()

				line := strings.Split(item_val, ",")
				hashkey := line[0]
				hashcert := line[1]
				formatted_hachcert := "-----BEGIN CERTIFICATE-----\n" + hashcert + "\n-----END CERTIFICATE-----\n"
				
				err = lib.ReadAsX509String(formatted_hachcert, *dumpType, tty.ReadPassword, func(cert *x509.Certificate, format string, err error) error {
					if err != nil {
						return fmt.Errorf("error parsing block: %s", strings.TrimSuffix(err.Error(), "\n"))
					} else {
						result.Certificates = []*x509.Certificate{cert}
						//result.Formats = append(result.Formats, format)
					}
					return nil
				})

				if *dumpJSON {
					blob, _ := json.Marshal(result)

					// open path and append to file
					f, err := os.OpenFile(fmt.Sprintf("%s-translated.json", path), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
					if err != nil {
						log.Fatalf(err.Error())
					}
					defer f.Close()
					// write hashkey and blob as string to file
					if _, err = f.WriteString(fmt.Sprintf("%s %s\n", hashkey, string(blob))); err != nil {
						log.Fatalf(err.Error())
					}
					fmt.Println(hashkey, string(blob))
				} else {
					for i, cert := range result.Certificates {
						fmt.Fprintf(stdout, "** CERTIFICATE %d **\n", i+1)
						fmt.Fprintf(stdout, "Input Format: %s\n", result.Formats[i])
						fmt.Fprintf(stdout, "%s\n\n", lib.EncodeX509ToText(cert, terminalWidth, *verbose))
					}
				}
			}

		} else {

			if dumpPassword != nil && *dumpPassword != "" {
				tty.SetDefaultPassword(*dumpPassword)
			}

			files, err := inputFiles(*dumpFiles)
			defer func() {
				for _, file := range files {
					file.Close()
				}
			}()


			if *dumpPem {
				err = lib.ReadAsPEMFromFiles(files, *dumpType, tty.ReadPassword, func(block *pem.Block, format string) error {
					block.Headers = nil
					return pem.Encode(stdout, block)
				})
			} else {
				err = lib.ReadAsX509FromFiles(files, *dumpType, tty.ReadPassword, func(cert *x509.Certificate, format string, err error) error {
					if err != nil {
						return fmt.Errorf("error parsing block: %s\n", strings.TrimSuffix(err.Error(), "\n"))
					} else {
						result.Certificates = append(result.Certificates, cert)
						result.Formats = append(result.Formats, format)

					}
					return nil
				})

				if *dumpJSON {
					blob, _ := json.Marshal(result)
					fmt.Println(string(blob))
				} else {
					for i, cert := range result.Certificates {
						fmt.Fprintf(stdout, "** CERTIFICATE %d **\n", i+1)
						fmt.Fprintf(stdout, "Input Format: %s\n", result.Formats[i])
						fmt.Fprintf(stdout, "%s\n\n", lib.EncodeX509ToText(cert, terminalWidth, *verbose))
					}
				}
			}
			if err != nil {
				return printErr("error: %s\n", strings.TrimSuffix(err.Error(), "\n"))
			} else if len(result.Certificates) == 0 && !*dumpPem {
				printErr("warning: no certificates found in input\n")
			}
		}

	case connect.FullCommand(): // Get certs by connecting to a server
		if connectStartTLS == nil && connectIdentity != nil {
			return printErr("error: --identity can only be used with --start-tls")
		}
		if connectBulkRead != nil {

			var ips = readFileIPs(*connectBulkRead)
			var wg sync.WaitGroup
			totalips := len(ips)
			wg.Add(totalips)
			var channelqueusize = *connectBulkRoutines
			var max_routines_in_parallel = *connectBulkRoutines

			var path = "results"
			if *connectBulkOutputFolder != "" {
				path = *connectBulkOutputFolder
			}

			if _, err := os.Stat(path); os.IsNotExist(err) {
				os.Mkdir(path, 0755)
			}

			block_channel := make(chan bool, channelqueusize)

			certs_channel := make(chan string)
			certspath := path + "/certs.txt"
			os.Create(certspath)
			go func(certs_channel chan string, block_channel chan bool) {
				filecerts, errcerts := os.OpenFile(certspath, os.O_WRONLY|os.O_APPEND, 0644)
				if errcerts != nil {
					log.Fatalf("failed opening file: %s", errcerts)
				}
				var msg = ""
				for true {
					msg = <-certs_channel
					if msg == "done" {
						break
					}
					filecerts.WriteString(msg + "\n")
					<-block_channel
				}
				filecerts.Close()
			} (certs_channel, block_channel)

			errors_channel := make(chan string)
			errorspath := path + "/errors.txt"
			os.Create(errorspath)
			go func(errors_channel chan string, block_channel chan bool) {
				fileerrors, errerrors := os.OpenFile(errorspath, os.O_WRONLY|os.O_APPEND, 0644)
				if errerrors != nil {
					log.Fatalf("failed opening file: %s", errerrors)
				}
				var msg = ""
				for true {
					msg = <-errors_channel
					if msg == "done" {
						break
					}
					fileerrors.WriteString(msg + "\n")
					<-block_channel
				}
				fileerrors.Close()
			} (errors_channel, block_channel)

			type hasherrorcodes struct {
				hashstring string
				hash  uint32
			}

			hasherrors_channel := make(chan hasherrorcodes)
			errorcodespath := path + "/hasherrorcodes/" 
			if _, err := os.Stat(errorcodespath); os.IsNotExist(err) {
				os.Mkdir(errorcodespath, 0755)
			}
			go func(hasherrors_channel chan hasherrorcodes, block_channel chan bool) {
				var hashcoderrortable map[uint32]string
				hashcoderrortable = make(map[uint32] string)
				var msg = hasherrorcodes{hashstring: "dummy", hash: 0}
				for true {
					msg = <-hasherrors_channel
					if msg.hashstring == "done" {
						break
					}
					_, ok := hashcoderrortable[msg.hash]
					if ! ok {
						hashcoderrortable[msg.hash] = msg.hashstring
						errorfile := errorcodespath + fmt.Sprint(msg.hash)
						if _, err := os.Stat(errorfile); os.IsNotExist(err) {
							f, err := os.Create(errorfile)
							if err != nil {
								fmt.Fprintf(os.Stderr, "%s\n", strings.TrimSuffix(err.Error(), "\n"))
							}
							w := bufio.NewWriter(f)
							w.WriteString(msg.hashstring)
							w.Flush()
							f.Close()
						}
					}
					<-block_channel
				}
			} (hasherrors_channel, block_channel)

			// Match IPv4 + IPv4:port
			regexmatch := `(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])[:]*[0-9]*|[:]*[0-9]*`
			re := regexp.MustCompile(regexmatch)
			cur_routines_running = 0

			for counter, ip_addr := range ips {
				if counter % 5000 == 0 {
					time.Sleep(750 * time.Millisecond)
				}

				for curRoutines() >= max_routines_in_parallel {
					time.Sleep(100 * time.Millisecond)
				}

				addRoutine()
				block_channel <-true
				go func(ip_addr string, certs_channel chan string, errors_channel chan string, hasherrors_channel chan hasherrorcodes, wg *sync.WaitGroup) {
					<-block_channel
					result_goroutine := lib.SimpleResult{}
					connectTo := ip_addr + ":443"
					connState, cri, err := starttls.GetConnectionState(
						*connectStartTLS, *connectName, connectTo, *connectIdentity,
						*connectCert, *connectKey, *connectProxy, *connectTimeout)
					if err != nil {
						errorstring_ := re.ReplaceAllString(strings.TrimSuffix(err.Error(), "\n"), "")
						errorhash_ := FNV32a(errorstring_)
													
						hasherrors_channel <- hasherrorcodes{hashstring: errorstring_, hash: errorhash_}
						block_channel <-false

						jsonerror := "{\"" + string(ip_addr) + "\":" + fmt.Sprint(errorhash_) + "}"

						errors_channel <- jsonerror
						block_channel <-false
						substractRoutine()

					} else {
						result_goroutine.TLSConnectionState = connState
						result_goroutine.CertificateRequestInfo = cri
						for _, cert := range connState.PeerCertificates {
							if *connectPem {
								pem.Encode(os.Stdout, lib.EncodeX509ToPEM(cert, nil))
							} else {
								result_goroutine.Certificates = append(result_goroutine.Certificates, cert)
							}
						}

						var hostname string
						if *connectName != "" {
							hostname = *connectName
						} else {
							hostname = strings.Split(connectTo, ":")[0]
						}
						verifyResult := lib.VerifyChain(connState.PeerCertificates, connState.OCSPResponse, hostname, *connectCaPath)
						result_goroutine.VerifyResult = &verifyResult

						if *connectJSON {
							blob, _ := json.Marshal(result_goroutine)

							jsoncert := "{\"" + string(ip_addr) + "\":" + string(blob) + "}"
							certs_channel <- jsoncert
							block_channel <-false
							substractRoutine()

						} else if !*connectPem {
							fmt.Fprintf(
								stdout, "%s\n\n",
								lib.EncodeTLSInfoToText(result_goroutine.TLSConnectionState, result_goroutine.CertificateRequestInfo))

							for i, cert := range result_goroutine.Certificates {
								fmt.Fprintf(stdout, "** CERTIFICATE %d **\n", i+1)
								fmt.Fprintf(stdout, "%s\n\n", lib.EncodeX509ToText(cert, terminalWidth, *verbose))
							}
							lib.PrintVerifyResult(stdout, *result_goroutine.VerifyResult)
						}

						if *connectVerify && len(result_goroutine.VerifyResult.Error) > 0 {
							os.Exit(1)
						}
					}
					defer wg.Done()
				}(ip_addr, certs_channel, errors_channel, hasherrors_channel, &wg)
			}
			wg.Wait() // Wait all routines to complete
			certs_channel <- "done"
			errors_channel <- "done"
			hasherrors_channel <- hasherrorcodes{hashstring: "done", hash: 0}


		} else {
			connState, cri, err := starttls.GetConnectionState(
				*connectStartTLS, *connectName, *connectTo, *connectIdentity,
				*connectCert, *connectKey, *connectProxy, *connectTimeout)
			if err != nil {
				return printErr("%s\n", strings.TrimSuffix(err.Error(), "\n"))
			}
			result.TLSConnectionState = connState
			result.CertificateRequestInfo = cri
			for _, cert := range connState.PeerCertificates {
				if *connectPem {
					pem.Encode(stdout, lib.EncodeX509ToPEM(cert, nil))
				} else {
					result.Certificates = append(result.Certificates, cert)
				}
			}

			var hostname string
			if *connectName != "" {
				hostname = *connectName
			} else {
				hostname = strings.Split(*connectTo, ":")[0]
			}
			verifyResult := lib.VerifyChain(connState.PeerCertificates, connState.OCSPResponse, hostname, *connectCaPath)
			result.VerifyResult = &verifyResult

			if *connectJSON {
				blob, _ := json.Marshal(result)
				fmt.Println(string(blob))
			} else if !*connectPem {
				fmt.Fprintf(
					stdout, "%s\n\n",
					lib.EncodeTLSInfoToText(result.TLSConnectionState, result.CertificateRequestInfo))

				for i, cert := range result.Certificates {
					fmt.Fprintf(stdout, "** CERTIFICATE %d **\n", i+1)
					fmt.Fprintf(stdout, "%s\n\n", lib.EncodeX509ToText(cert, terminalWidth, *verbose))
				}
				lib.PrintVerifyResult(stdout, *result.VerifyResult)
			}

			if *connectVerify && len(result.VerifyResult.Error) > 0 {
				return 1
			}
		}
	case verify.FullCommand():
		if verifyPassword != nil && *verifyPassword != "" {
			tty.SetDefaultPassword(*verifyPassword)
		}

		file, err := inputFile(*verifyFile)
		if err != nil {
			return printErr("%s\n", err.Error())
		}
		defer file.Close()

		chain := []*x509.Certificate{}
		err = lib.ReadAsX509FromFiles([]*os.File{file}, *verifyType, tty.ReadPassword, func(cert *x509.Certificate, format string, err error) error {
			if err != nil {
				return err
			} else {
				chain = append(chain, cert)
			}
			return nil
		})
		if err != nil {
			return printErr("error parsing block: %s\n", strings.TrimSuffix(err.Error(), "\n"))
		}

		verifyResult := lib.VerifyChain(chain, nil, *verifyName, *verifyCaPath)
		if *verifyJSON {
			blob, _ := json.Marshal(verifyResult)
			fmt.Println(string(blob))
		} else {
			lib.PrintVerifyResult(stdout, verifyResult)
		}
		if verifyResult.Error != "" {
			return 1
		}
	}
	return 0
}

func inputFile(fileName string) (*os.File, error) {
	if fileName == "" {
		return os.Stdin, nil
	}

	rawFile, err := os.Open(fileName)
	if err != nil {
		return nil, fmt.Errorf("unable to open file: %s\n", err)
	}
	return rawFile, nil
}

func inputFiles(fileNames []string) ([]*os.File, error) {
	var files []*os.File
	if fileNames != nil {
		for _, filename := range fileNames {
			rawFile, err := os.Open(filename)
			if err != nil {
				return nil, fmt.Errorf("unable to open file: %s\n", err)
			}
			files = append(files, rawFile)
		}
	} else {
		files = append(files, os.Stdin)
	}
	return files, nil
}

func readFileIPs(filename string) []string {
	file, err := os.Open(fmt.Sprintf("%s", filename))
	if err != nil {
		log.Fatalf("failed opening file: %s", err)
	}

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	var txtlines []string

	for scanner.Scan() {
		txtlines = append(txtlines, scanner.Text())
	}

	file.Close()

	return txtlines
}

func FNV32a(text string) uint32 {
	algorithm := fnv.New32a()
	algorithm.Write([]byte(text))

	return algorithm.Sum32()
}

func addRoutine() {
	mu.Lock()
	cur_routines_running++
	mu.Unlock()
}

func substractRoutine() {
	mu.Lock()
	cur_routines_running--
	mu.Unlock()
}

func curRoutines() int {
	mu.Lock()
	r := cur_routines_running
	mu.Unlock()
	return r
}

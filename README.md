# tfps

## Overview

Telephony Fraud Prevention System TFPS is designed to prevent international traffic pumping. It works by screening and matching several attributes of a phone call against specific rules (user rules and system defined). The service is delivered thru a HTTP, SIP redirects or thru our free SBC.

The system was created for IP PBX users and ITSP (Internet Telephony Service Providers). Below, we describe the benefits to use the system.

### PBX owners

* Control the use of your phone system against fraud traffic
* Avoid fraudulent charges in your phone bill

### Service providers

* Avoid disputes and customer loss after a fraud event
* Avoid payment defaults in telephone bills by customers

## How It Works!

TFPS learns the address, dialed numbers and behavior from strategically placed honeypots. We learn in realitime, IP addresses and Premium Rate Numbers associated to fraudulent activities. We also learn from our own detection process. Some customers have in-site honeypots to detect targeted attacks. Once an address is learned it is updated in real-time in the blacklist database. Beyond the blacklist rules, calls will also be checked against pre or dynamically set rules, such as:

* Country of Origin (IP Geolocation)
* Country of Destination (Dialed #)
* Exclusive Anomaly detection off the traffic

If the call is screened and nothing is found the system returns and approval code (e.g A00). In the other hand if the call is rejected an specific code depending on the detection method is returned (e.g R03). It is up to the PBX owner to decide what to do with rejected calls. You can simply discard or send the call to an operator for manual acceptance.

## Integration

Your phone system can be integrated to the TFPS using SIP redirects or Restful APIs. We have instructions and code on how to integrate with Asterisk, FreePBX, FreeSwitch and OpenSIPS. 

## Configuration Overview

There are three methods of operation, Free, Basic and ITSP. In the Free Plan, the system is completely automated, there is nothing to configure. In the Basic mode you can configure call thresholds and Geo restrictions. In the ITSP mode you can have your own domain and configure different policies for different users. We will have a detailed description of the system in the next chapters.

# More information at our WIKI https://github.com/flaviogoncalves/tfps/wiki

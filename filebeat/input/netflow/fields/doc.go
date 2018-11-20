package fields

//go:generate go run gen.go -skip-lines 1 -output zfields_ipfix.go -export IpfixFields --column-id=1 --column-name=2 --column-type=3 ipfix-information-elements.csv
//go:generate go run gen.go -skip-lines 1 -output zfields_cert.go -export CertFields --column-pen=2 --column-id=3 --column-name=1 --column-type=4 cert_pen6871.csv
//go:generate go run gen.go -output zfields_cisco.go -export CiscoFields --column-pen=2 --column-id=3 --column-name=1 --column-type=4 cisco.csv

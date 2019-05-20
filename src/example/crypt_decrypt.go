package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/adamhassel/dkimcrypt"
)

var (
	encrypt     = flag.Bool("e", false, "Encrypt data and write it to STDOUT")
	domain      = flag.String("D", "", "Recipient domain of encrypted data, or origin domain for signature to check")
	decrypt     = flag.Bool("d", false, "Decrypt data and write to STDOUT")
	b64         = flag.Bool("b", false, "Output base64 when encrypting/signing, or expect base64 crypted data or signature when decrypting/verifying")
	sign        = flag.Bool("s", false, "Generate a signature for data, and write it to STDOUT")
	verify      = flag.Bool("v", false, "Verify a signature data")
	input       = flag.String("i", "", "Input data. If '-', read from STDIN. If valid filename, read from there")
	signature   = flag.String("S", "", "Signature to verify with -s. If '-', read from STDIN. If valid filename, read signature from there")
	selector    = flag.String("c", "", "Selector to use when looking up DKIM keys")
	privkeypath = flag.String("p", "", "Path to private key file")
)

//var config Conf

func init() {

	flag.Usage = func() {

		fmt.Fprint(os.Stderr, `
Examples:
  Sign some data: 
	crypt_decrypt -s -p /path/to/private.key -i 'some data to sign'

  Sign data in a file, and save the signature to another file, encoded in base64:
	crypt_decrypt -s -p /path/to/private.key -b -i /path/to/datafile > /path/to/signature

  Verify that a signature fits some data given on STDIN:
	crypt_decrypt -v -D example.com -c selector -S /path/to/signature -i - < /path/to/data

  Encrypt data:
    crypt_decrypt -e -p /path/to/private.key -c selector -i 'data to encrypt' -D example.com
`)

		fmt.Fprintf(os.Stderr, "\nUsage:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if !OneTrue(*encrypt, *decrypt, *sign, *verify) {
		fmt.Fprint(os.Stderr, "Exactly one of -e, -d, -s, -v must be set\n")
		os.Exit(1)
	}

	if (*encrypt || *decrypt || *verify) && *selector == "" {
		fmt.Fprintf(os.Stderr, "Must supply selector for operation\n")
		os.Exit(1)
	}

	if (*decrypt || *sign) && *privkeypath == "" {
		fmt.Fprintf(os.Stderr, "Must supply path to private key file for operation\n")
		os.Exit(1)
	}
}

func main() {
	if len(*input) <= 0 {
		fmt.Fprint(os.Stderr, "No data to process\n")
		os.Exit(1)
	}

	indata := GetData(*input)

	if *encrypt {
		if *domain == "" {
			fmt.Fprint(os.Stderr, "No domain configured for encryption\n")
		}
		os.Stdout.Write(Encrypt(indata))
		os.Exit(0)
	}

	if *decrypt {
		os.Stdout.Write(Decrypt(indata))
		os.Exit(0)
	}

	if *sign {
		os.Stdout.Write(Sign(indata))
		os.Exit(0)
	}

	if *verify {
		if *signature == "" {
			fmt.Fprint(os.Stderr, "No signature given. Use -S option.\n")
			os.Exit(1)
		}

		sig := GetData(*signature)
		fmt.Println(sig)
		if Verify(indata, sig) {
			fmt.Print("Signature good\n")
			os.Exit(0)
		} else {
			fmt.Print("Signature not good\n")
			os.Exit(1)
		}
	}

}

func GetData(input string) (out []byte) {
	if input == "-" {
		// read from STDIN
		if o, err := ioutil.ReadAll(os.Stdin); err != nil {
			fmt.Fprint(os.Stderr, "Error reading stdin: %s\n", err)
			os.Exit(1)
		} else {
			out = o
		}
	} else if _, err := os.Stat(input); err == nil {
		var e error
		var tmp []byte
		if tmp, e = ioutil.ReadFile(input); e != nil {
			fmt.Printf("Couldn't read file %s: %s\n", input, e)
			os.Exit(1)
		}
		out = tmp
	} else {
		out = []byte(input)
	}

	return out
}

func Encrypt(in []byte) (out []byte) {
	var err error

	if out, err = dkimcrypt.EncryptSingle(*selector, *domain, in); err != nil {
		fmt.Fprintf(os.Stderr, "Error during encryption: %s\n", err)
		os.Exit(1)
	}

	if *b64 {
		out = b64encode(out)
	}

	return
}

func Decrypt(in []byte) (out []byte) {
	var err error

	if *b64 {
		if in, err = b64decode(in); err != nil {
			fmt.Fprintf(os.Stderr, "Error during base64 decode: %s", err)
			os.Exit(1)
		}
	}

	if out, err = dkimcrypt.DecryptSingle(*selector, *privkeypath, in); err != nil {
		fmt.Fprintf(os.Stderr, "Error during decryption: %s\n", err)
		os.Exit(1)
	}

	return
}

func Sign(in []byte) (out []byte) {
	var err error

	if out, err = dkimcrypt.Sign(in, *privkeypath); err != nil {
		fmt.Fprintf(os.Stderr, "Error signing message: %s\n", err)
		os.Exit(1)
	}

	if *b64 {
		out = b64encode(out)
	}

	return
}

func Verify(data []byte, sig []byte) bool {
	var err error

	if *b64 {
		if sig, err = b64decode(sig); err != nil {
			fmt.Fprintf(os.Stderr, "Error during base64 decode: %s\n", err)
			os.Exit(1)
		}
	}

	return dkimcrypt.Verify(data, sig, *selector, *domain) == nil
}

func b64encode(in []byte) (out []byte) {

	out = make([]byte, base64.StdEncoding.EncodedLen(len(in)))

	base64.StdEncoding.Encode(out, in)

	return
}

func b64decode(in []byte) (out []byte, e error) {
	var l int
	out = make([]byte, base64.StdEncoding.DecodedLen(len(in)))

	if l, e = base64.StdEncoding.Decode(out, in); e != nil {
		return nil, e
	}

	return out[:l], nil
}

// Check if exactly one element in b is true
func OneTrue(b ...bool) bool {

	// found first
	var f bool

	//found previously
	var p bool

	for _, v := range b {
		if v {
			f = true
			if p {
				return false
			} else {
				p = true
			}
		}
	}

	return f
}

package awg

import (
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestGenIpcConfigIncludesAwg31Options(t *testing.T) {
	ipc, err := genIpcConfig(option.AwgEndpointOptions{
		PrivateKey:             "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		Jc:                     5,
		Jmin:                   10,
		Jmax:                   50,
		S1:                     139,
		S2:                     60,
		S3:                     43,
		S4:                     12,
		H1:                     "1",
		H2:                     "2",
		H3:                     "3",
		H4:                     "4",
		HeaderProtectionKey:    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		ContentPaddingAddition: "10-100",
		RekeyAfterTime:         "100-120",
		RekeyTimeout:           "3-7",
		RejectAfterTime:        "150-180",
		KeepaliveTimeout:       "5-15",
		MaxHandshakeAttempts:   "15-20",
		RandomTrailers:         true,
		DisableCookies:         true,
		Peers: []option.AwgPeerOptions{
			{
				Address:                     "203.0.113.10",
				Port:                        33622,
				PublicKey:                   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
				PresharedKey:                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
				PersistentKeepaliveInterval: "25-35",
			},
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	for _, expected := range []string{
		"jc=5",
		"jmin=10",
		"jmax=50",
		"s1=139",
		"h1=1",
		"header_protection_key=0000000000000000000000000000000000000000000000000000000000000000",
		"content_padding_addition=10-100",
		"rekey_after_time=100-120",
		"rekey_timeout=3-7",
		"reject_after_time=150-180",
		"keepalive_timeout=5-15",
		"max_handshake_attempts=15-20",
		"random_trailers=true",
		"disable_cookies=true",
		"persistent_keepalive_interval=25-35",
	} {
		if !strings.Contains(ipc, expected) {
			t.Fatalf("missing %q in IPC config:\n%s", expected, ipc)
		}
	}
}

func TestDecodeAwgKeyAcceptsBase64RawBase64AndHex(t *testing.T) {
	for name, key := range map[string]string{
		"base64":     "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"raw base64": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"hex":        "0000000000000000000000000000000000000000000000000000000000000000",
	} {
		t.Run(name, func(t *testing.T) {
			decoded, err := decodeAwgKey(key)
			if err != nil {
				t.Fatal(err)
			}
			if decoded != "0000000000000000000000000000000000000000000000000000000000000000" {
				t.Fatalf("unexpected decoded key: %s", decoded)
			}
		})
	}
}

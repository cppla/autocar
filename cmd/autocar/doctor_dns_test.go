package main

import (
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func TestDoctorDNSName(t *testing.T) {
	longest := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	valid := []struct{ label, input, canonical string }{
		{"relative", "Example.Test", "example.test."},
		{"absolute", "Example.Test.", "example.test."},
		{"single_label", "Example", "example."},
		{"hyphen_and_punycode", "XN--BCHER-KVA.a-b.test", "xn--bcher-kva.a-b.test."},
		{"maximum_wire_name", longest, longest + "."},
	}
	for _, test := range valid {
		t.Run("valid_"+test.label, func(t *testing.T) {
			name, err := doctorDNSName(test.input)
			if err != nil || name.String() != test.canonical {
				t.Error("valid name did not produce the canonical absolute ASCII name")
			}
		})
	}
	invalid := []struct{ label, input string }{
		{"empty", ""}, {"root", "."}, {"empty_label", "example..test"},
		{"two_terminal_dots", "example.test.."}, {"leading_dot", ".example.test"},
		{"leading_hyphen", "-example.test"}, {"trailing_hyphen", "example-.test"},
		{"underscore", "_example.test"}, {"leading_space", " example.test"},
		{"trailing_space", "example.test "}, {"tab", "example\ttest"},
		{"newline", "example.test\n"}, {"unicode", "exámple.test"},
		{"unicode_case_alias", "Key.test"}, {"URL", "https://example.test"},
		{"port", "example.test:53"}, {"wildcard", "*.example.test"},
		{"long_label", strings.Repeat("a", 64) + ".test"},
		{"wire_name_too_long", longest + "d"},
	}
	for _, test := range invalid {
		t.Run("invalid_"+test.label, func(t *testing.T) {
			if _, err := doctorDNSName(test.input); err == nil {
				t.Error("invalid name accepted")
			}
		})
	}
}

func TestDoctorDNSTarget(t *testing.T) {
	valid := []struct{ label, input, canonical string }{
		{"IPv4", "127.0.0.1:53", "127.0.0.1:53"},
		{"IPv6", "[::1]:53", "[::1]:53"},
		{"IPv6_expanded", "[0:0:0:0:0:0:0:1]:53", "[::1]:53"},
		{"mapped_IPv4", "[::ffff:127.0.0.1]:53", "127.0.0.1:53"},
		{"minimum_port", "127.0.0.1:1", "127.0.0.1:1"},
		{"maximum_port", "127.0.0.1:65535", "127.0.0.1:65535"},
	}
	for _, test := range valid {
		t.Run("valid_"+test.label, func(t *testing.T) {
			got, err := doctorDNSTarget(test.input)
			if err != nil || got != netip.MustParseAddrPort(test.canonical) {
				t.Error("valid numeric target did not produce the canonical endpoint")
			}
		})
	}
	invalid := []struct{ label, input string }{
		{"empty", ""}, {"hostname", "resolver.test:53"}, {"missing_port", "127.0.0.1"},
		{"named_port", "127.0.0.1:domain"}, {"zero_port", "127.0.0.1:0"},
		{"large_port", "127.0.0.1:65536"}, {"negative_port", "127.0.0.1:-1"},
		{"unbracketed_IPv6", "::1:53"}, {"zone", "[fe80::1%lo0]:53"},
		{"mapped_zone", "[::ffff:127.0.0.1%lo0]:53"},
		{"unspecified_IPv4", "0.0.0.0:53"}, {"unspecified_IPv6", "[::]:53"},
		{"mapped_unspecified", "[::ffff:0.0.0.0]:53"},
		{"multicast_IPv4", "224.0.0.1:53"}, {"multicast_IPv6", "[ff02::1]:53"},
		{"mapped_multicast", "[::ffff:224.0.0.1]:53"},
		{"leading_space", " 127.0.0.1:53"}, {"trailing_space", "127.0.0.1:53 "},
	}
	for _, test := range invalid {
		t.Run("invalid_"+test.label, func(t *testing.T) {
			if _, err := doctorDNSTarget(test.input); err == nil {
				t.Error("invalid numeric target accepted")
			}
		})
	}
}

func TestDoctorDNSResponse(t *testing.T) {
	name := doctorDNSUnitName(t, "example.test.")
	target := netip.MustParseAddrPort("127.0.0.1:53")
	const id = uint16(0x4712)
	base := func() dnsmessage.Message {
		return dnsmessage.Message{
			Header:    dnsmessage.Header{ID: id, Response: true, RecursionDesired: true, RecursionAvailable: true},
			Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
		}
	}
	check := func(t *testing.T, payload []byte, source string, endpoint netip.AddrPort, want [4]int, valid bool) {
		t.Helper()
		before := string(payload)
		result, err := doctorDNSResponse(payload, source, endpoint, id, name)
		if string(payload) != before {
			t.Error("response validation mutated caller-owned packet bytes")
		}
		if !valid {
			if err == nil || result != nil {
				t.Error("invalid response returned a result instead of nil and an error")
			}
			return
		}
		if err != nil || result == nil {
			t.Error("valid response rejected")
			return
		}
		if [4]int{result.Questions, result.Answers, result.Authorities, result.Additionals} != want || result.RCode != "NOERROR" {
			t.Error("valid response metadata changed")
		}
	}
	resource := func(body dnsmessage.ResourceBody) dnsmessage.Resource {
		return dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: name, Class: dnsmessage.ClassINET, TTL: 60}, Body: body}
	}
	known := []struct {
		label string
		typ   dnsmessage.Type
		body  dnsmessage.ResourceBody
		raw   []byte
	}{
		{"A", dnsmessage.TypeA, &dnsmessage.AResource{A: [4]byte{192, 0, 2, 1}}, []byte{192, 0, 2, 1}},
		{"AAAA", dnsmessage.TypeAAAA, &dnsmessage.AAAAResource{AAAA: [16]byte{0x20, 0x01, 0x0d, 0xb8, 15: 1}}, make([]byte, 16)},
		{"NS", dnsmessage.TypeNS, &dnsmessage.NSResource{NS: name}, []byte{1, 'x', 0}},
		{"CNAME", dnsmessage.TypeCNAME, &dnsmessage.CNAMEResource{CNAME: doctorDNSUnitName(t, "alias.example.test.")}, []byte{1, 'x', 0}},
		{"PTR", dnsmessage.TypePTR, &dnsmessage.PTRResource{PTR: name}, []byte{1, 'x', 0}},
		{"MX", dnsmessage.TypeMX, &dnsmessage.MXResource{Pref: 10, MX: name}, []byte{0, 10, 1, 'x', 0}},
		{"SOA", dnsmessage.TypeSOA, &dnsmessage.SOAResource{NS: name, MBox: name, Serial: 1, Refresh: 2, Retry: 3, Expire: 4, MinTTL: 5}, append([]byte{0xc0, 12, 0xc0, 12}, make([]byte, 20)...)},
		{"TXT", dnsmessage.TypeTXT, &dnsmessage.TXTResource{TXT: []string{"", "opaque"}}, []byte{0, 1, 'x'}},
		{"SRV", dnsmessage.TypeSRV, &dnsmessage.SRVResource{Priority: 1, Weight: 2, Port: 443, Target: name}, []byte{0, 1, 0, 2, 1, 187, 1, 'x', 0}},
		{"SVCB", dnsmessage.TypeSVCB, &dnsmessage.SVCBResource{Priority: 1, Target: doctorDNSUnitName(t, "."), Params: []dnsmessage.SVCParam{{Key: dnsmessage.SVCParamPort, Value: []byte{1, 187}}}}, []byte{0, 1, 0, 0, 3, 0, 2, 1, 187}},
		{"HTTPS", dnsmessage.TypeHTTPS, &dnsmessage.HTTPSResource{SVCBResource: dnsmessage.SVCBResource{Priority: 1, Target: doctorDNSUnitName(t, ".")}}, []byte{0, 1, 0}},
	}
	t.Run("valid_NOERROR_NODATA", func(t *testing.T) {
		check(t, doctorDNSUnitPack(t, base()), target.String(), target, [4]int{1, 0, 0, 0}, true)
	})
	for _, test := range known {
		t.Run("valid_"+test.label, func(t *testing.T) {
			message := base()
			message.Answers = []dnsmessage.Resource{resource(test.body)}
			check(t, doctorDNSUnitPack(t, message), target.String(), target, [4]int{1, 1, 0, 0}, true)
		})
		// A second, well-framed opaque RR supplies bytes after the first body.
		// A typed decoder must not borrow them from an undersized RDLENGTH.
		t.Run("invalid_"+test.label+"_short_body", func(t *testing.T) {
			body := append([]byte(nil), test.raw[:len(test.raw)-1]...)
			check(t, doctorDNSUnitRaw(id, test.typ, body, true), target.String(), target, [4]int{}, false)
		})
		if test.typ != dnsmessage.TypeTXT {
			t.Run("invalid_"+test.label+"_extra_body_octet", func(t *testing.T) {
				body := append(append([]byte(nil), test.raw...), 0)
				check(t, doctorDNSUnitRaw(id, test.typ, body, true), target.String(), target, [4]int{}, false)
			})
		}
	}
	t.Run("valid_all_sections_and_unknown", func(t *testing.T) {
		message := base()
		message.Answers = []dnsmessage.Resource{resource(known[0].body)}
		message.Authorities = []dnsmessage.Resource{resource(known[6].body)}
		message.Additionals = []dnsmessage.Resource{resource(&dnsmessage.UnknownResource{Type: 65280, Data: []byte{0xc0, 0xff, 0x40, 0x80}})}
		check(t, doctorDNSUnitPack(t, message), target.String(), target, [4]int{1, 1, 1, 1}, true)
	})
	t.Run("valid_ASCII_question_case", func(t *testing.T) {
		message := base()
		message.Questions[0].Name = doctorDNSUnitName(t, "EXAMPLE.Test.")
		check(t, doctorDNSUnitPack(t, message), target.String(), target, [4]int{1, 0, 0, 0}, true)
	})
	t.Run("valid_mapped_source", func(t *testing.T) {
		check(t, doctorDNSUnitPack(t, base()), "[::ffff:127.0.0.1]:53", target, [4]int{1, 0, 0, 0}, true)
	})
	t.Run("valid_IPv6_source_spelling", func(t *testing.T) {
		check(t, doctorDNSUnitPack(t, base()), "[0:0:0:0:0:0:0:1]:53", netip.MustParseAddrPort("[::1]:53"), [4]int{1, 0, 0, 0}, true)
	})
	t.Run("valid_Builder_compressed_names", func(t *testing.T) {
		builder := dnsmessage.NewBuilder(nil, base().Header)
		builder.EnableCompression()
		if err := builder.StartQuestions(); err != nil {
			t.Fatal("could not build question section")
		}
		if err := builder.Question(base().Questions[0]); err != nil {
			t.Fatal("could not build question")
		}
		if err := builder.StartAnswers(); err != nil {
			t.Fatal("could not build answer section")
		}
		header := dnsmessage.ResourceHeader{Name: name, Class: dnsmessage.ClassINET, TTL: 60}
		if err := builder.CNAMEResource(header, dnsmessage.CNAMEResource{CNAME: doctorDNSUnitName(t, "alias.example.test.")}); err != nil {
			t.Fatal("could not build compressed CNAME")
		}
		payload, err := builder.Finish()
		if err != nil {
			t.Fatal("could not finish compressed message")
		}
		// Independently witness a compressed owner and label-plus-pointer RDATA.
		answer := 12 + len(doctorDNSUnitQuestionName()) + 4
		body := answer + 2 + 10
		if len(payload) <= body+6 || payload[answer] != 0xc0 || payload[body] != 5 || payload[body+6] != 0xc0 {
			t.Fatal("positive fixture did not actually contain name compression")
		}
		check(t, payload, target.String(), target, [4]int{1, 1, 0, 0}, true)
	})
	t.Run("valid_raw_compressed_CNAME", func(t *testing.T) {
		check(t, doctorDNSUnitRaw(id, dnsmessage.TypeCNAME, []byte{5, 'a', 'l', 'i', 'a', 's', 0xc0, 12}, false), target.String(), target, [4]int{1, 1, 0, 0}, true)
	})
	t.Run("valid_maximum_classic_message", func(t *testing.T) {
		check(t, doctorDNSUnitSized(t, base(), name, 512), target.String(), target, [4]int{1, 1, 0, 0}, true)
	})
	t.Run("invalid_oversized_framed_message", func(t *testing.T) {
		check(t, doctorDNSUnitSized(t, base(), name, 513), target.String(), target, [4]int{}, false)
	})
	mutations := []struct {
		label string
		apply func(*dnsmessage.Message)
	}{
		{"ID", func(m *dnsmessage.Message) { m.ID++ }},
		{"query_not_response", func(m *dnsmessage.Message) { m.Response = false }},
		{"opcode", func(m *dnsmessage.Message) { m.OpCode = 1 }},
		{"truncated", func(m *dnsmessage.Message) { m.Truncated = true }},
		{"no_question", func(m *dnsmessage.Message) { m.Questions = nil }},
		{"two_questions", func(m *dnsmessage.Message) { m.Questions = append(m.Questions, m.Questions[0]) }},
		{"question_name", func(m *dnsmessage.Message) { m.Questions[0].Name = doctorDNSUnitName(t, "other.test.") }},
		{"Unicode_question_case_alias", func(m *dnsmessage.Message) { m.Questions[0].Name = doctorDNSUnitName(t, "example.teſt.") }},
		{"question_type", func(m *dnsmessage.Message) { m.Questions[0].Type = dnsmessage.TypeAAAA }},
		{"question_class", func(m *dnsmessage.Message) { m.Questions[0].Class = dnsmessage.ClassCHAOS }},
	}
	for _, test := range mutations {
		t.Run("invalid_"+test.label, func(t *testing.T) {
			message := base()
			test.apply(&message)
			check(t, doctorDNSUnitPack(t, message), target.String(), target, [4]int{}, false)
		})
	}
	for _, source := range []struct{ label, value string }{
		{"IP", "127.0.0.2:53"}, {"port", "127.0.0.1:54"}, {"hostname", "resolver.test:53"},
		{"empty", ""}, {"malformed", "not-an-endpoint"}, {"zone", "[::1%lo0]:53"},
		{"mapped_zone", "[::ffff:127.0.0.1%lo0]:53"},
	} {
		t.Run("invalid_source_"+source.label, func(t *testing.T) {
			check(t, doctorDNSUnitPack(t, base()), source.value, target, [4]int{}, false)
		})
	}
	for code := dnsmessage.RCode(1); code <= 15; code++ {
		t.Run("invalid_rcode_"+doctorDNSUnitDecimal(uint16(code)), func(t *testing.T) {
			message := base()
			message.RCode = code
			check(t, doctorDNSUnitPack(t, message), target.String(), target, [4]int{}, false)
		})
	}
	for _, section := range []string{"answer", "authority", "additional"} {
		for _, extended := range []bool{false, true} {
			label := section
			if extended {
				label += "_extended_rcode"
			}
			t.Run("invalid_OPT_"+label, func(t *testing.T) {
				message := base()
				ttl := uint32(0)
				if extended {
					ttl = 1 << 24
				}
				opts := []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: doctorDNSUnitName(t, "."), Class: 512, TTL: ttl}, Body: &dnsmessage.OPTResource{}}}
				switch section {
				case "answer":
					message.Answers = opts
				case "authority":
					message.Authorities = opts
				case "additional":
					message.Additionals = opts
				}
				check(t, doctorDNSUnitPack(t, message), target.String(), target, [4]int{}, false)
			})
		}
	}
	malformed := []struct {
		label string
		body  []byte
		typ   dnsmessage.Type
	}{
		{"empty_name_RDATA", nil, dnsmessage.TypeCNAME},
		{"truncated_pointer", []byte{0xc0}, dnsmessage.TypeCNAME},
		{"pointer_outside_packet", []byte{0xff, 0xff}, dnsmessage.TypeCNAME},
		{"reserved_label_01", []byte{0x40, 0}, dnsmessage.TypeCNAME},
		{"reserved_label_10", []byte{0x80, 0}, dnsmessage.TypeCNAME},
		{"unterminated_label", []byte{1, 'x'}, dnsmessage.TypeCNAME},
		{"TXT_string_exceeds_RDATA", []byte{3, 'x'}, dnsmessage.TypeTXT},
		{"SVCB_incomplete_tuple", []byte{0, 1, 0, 0}, dnsmessage.TypeSVCB},
		{"SVCB_tuple_value_exceeds_RDATA", []byte{0, 1, 0, 0, 3, 0, 2, 1}, dnsmessage.TypeSVCB},
		{"SVCB_duplicate_keys", []byte{0, 1, 0, 0, 3, 0, 0, 0, 3, 0, 0}, dnsmessage.TypeSVCB},
		{"HTTPS_decreasing_keys", []byte{0, 1, 0, 0, 4, 0, 0, 0, 3, 0, 0}, dnsmessage.TypeHTTPS},
	}
	for _, test := range malformed {
		t.Run("invalid_"+test.label, func(t *testing.T) {
			check(t, doctorDNSUnitRaw(id, test.typ, test.body, true), target.String(), target, [4]int{}, false)
		})
	}
	t.Run("invalid_compression_self_loop", func(t *testing.T) {
		payload := doctorDNSUnitRaw(id, dnsmessage.TypeCNAME, []byte{0, 0}, false)
		body := 12 + len(doctorDNSUnitQuestionName()) + 4 + 2 + 10
		payload[body], payload[body+1] = byte(0xc0|(body>>8)), byte(body)
		check(t, payload, target.String(), target, [4]int{}, false)
	})
	t.Run("invalid_declared_RDLENGTH_beyond_packet", func(t *testing.T) {
		payload := doctorDNSUnitRaw(id, dnsmessage.TypeA, []byte{1, 2, 3, 4}, false)
		length := 12 + len(doctorDNSUnitQuestionName()) + 4 + 2 + 8
		binary.BigEndian.PutUint16(payload[length:length+2], 65535)
		check(t, payload, target.String(), target, [4]int{}, false)
	})
	t.Run("invalid_trailing_octets", func(t *testing.T) {
		payload := append(doctorDNSUnitPack(t, base()), 0, 0, 0)
		check(t, payload, target.String(), target, [4]int{}, false)
	})
	t.Run("invalid_truncated_message_prefixes", func(t *testing.T) {
		message := base()
		message.Answers = []dnsmessage.Resource{resource(known[0].body)}
		payload := doctorDNSUnitPack(t, message)
		for end := 0; end < len(payload); end++ {
			check(t, append([]byte(nil), payload[:end]...), target.String(), target, [4]int{}, false)
		}
	})
	t.Run("invalid_excess_record_count", func(t *testing.T) {
		payload := doctorDNSUnitPack(t, base())
		binary.BigEndian.PutUint16(payload[6:8], 65535)
		check(t, payload, target.String(), target, [4]int{}, false)
	})
}

func doctorDNSUnitName(t *testing.T, text string) dnsmessage.Name {
	t.Helper()
	name, err := dnsmessage.NewName(text)
	if err != nil {
		t.Fatal("could not prepare a fixture name")
	}
	return name
}

func doctorDNSUnitPack(t *testing.T, message dnsmessage.Message) []byte {
	t.Helper()
	payload, err := message.Pack()
	if err != nil {
		t.Fatal("could not pack a fixture message")
	}
	return payload
}

func doctorDNSUnitSized(t *testing.T, message dnsmessage.Message, name dnsmessage.Name, size int) []byte {
	t.Helper()
	body := &dnsmessage.UnknownResource{Type: 65280}
	message.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: name, Class: dnsmessage.ClassINET}, Body: body}}
	initial := doctorDNSUnitPack(t, message)
	if len(initial) > size {
		t.Fatal("fixture message overhead exceeded requested size")
	}
	body.Data = make([]byte, size-len(initial))
	payload := doctorDNSUnitPack(t, message)
	if len(payload) != size {
		t.Fatal("fixture message did not have the intended byte length")
	}
	return payload
}

func doctorDNSUnitQuestionName() []byte {
	return []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 4, 't', 'e', 's', 't', 0}
}

// doctorDNSUnitRaw is independent of Message.Pack and the production scanner.
// The first RDATA has exactly its declared byte length, even when its type
// requires more or fewer bytes. An optional complete opaque record immediately
// follows it, so a decoder accidentally reading past RDLENGTH can find bytes.
func doctorDNSUnitRaw(id uint16, typ dnsmessage.Type, body []byte, following bool) []byte {
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[:2], id)
	binary.BigEndian.PutUint16(header[2:4], 0x8180)
	binary.BigEndian.PutUint16(header[4:6], 1)
	answers := uint16(1)
	if following {
		answers++
	}
	binary.BigEndian.PutUint16(header[6:8], answers)
	payload := append(header, doctorDNSUnitQuestionName()...)
	payload = append(payload, 0, 1, 0, 1)
	rr := []byte{0xc0, 12, byte(typ >> 8), byte(typ), 0, 1, 0, 0, 0, 60, byte(len(body) >> 8), byte(len(body))}
	payload = append(payload, rr...)
	payload = append(payload, body...)
	if following {
		payload = append(payload, 0xc0, 12, 0xff, 0, 0, 1, 0, 0, 0, 60, 0, 0)
	}
	return payload
}

func doctorDNSUnitDecimal(value uint16) string {
	if value < 10 {
		return string(rune('0' + value))
	}
	return "1" + string(rune('0'+value-10))
}

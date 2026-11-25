package XRay

import (
	"errors"
	"net/netip"
	"testing"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// These write under HKLM, as the real thing does. The rule they install in
// the DNS client's own table names a namespace nothing resolves, so it never
// changes where a lookup on the machine goes.
const (
	testRule      = "VlessCoreTestRule"
	testNamespace = ".vless-core-test.invalid"
	// A table of our own for the cases that need one that is not there yet.
	testTableRoot = `SOFTWARE\VlessCoreTest`
	testTable     = testTableRoot + `\DnsPolicyConfig`
)

var testServers = []netip.Addr{netip.MustParseAddr("198.18.0.2")}

// requireElevated skips unless this process may write under HKLM. Asked of
// the registry rather than of the token: that is the question, and the
// answer the token gives is not the same everywhere the tests run.
func requireElevated(t *testing.T) {
	t.Helper()
	key, _, err := registry.CreateKey(registry.LOCAL_MACHINE, testTableRoot, registry.READ)
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Skip("writing under HKLM needs an elevated process")
	}
	if err != nil {
		t.Fatalf("open HKLM for writing: %v", err)
	}
	key.Close()
	_ = registry.DeleteKey(registry.LOCAL_MACHINE, testTableRoot)
}

func scratchTable(t *testing.T) {
	t.Helper()
	requireElevated(t)
	drop := func() {
		_ = registry.DeleteKey(registry.LOCAL_MACHINE, testTable+`\`+testRule)
		_ = registry.DeleteKey(registry.LOCAL_MACHINE, testTable+`\Sibling`)
		_ = registry.DeleteKey(registry.LOCAL_MACHINE, testTable)
		_ = registry.DeleteKey(registry.LOCAL_MACHINE, testTableRoot)
	}
	drop()
	t.Cleanup(drop)
}

// The registry has no "is this volatile" question. What it does have is a
// rule that a volatile key cannot hold a permanent one.
func isVolatile(t *testing.T, path string) bool {
	t.Helper()
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.CREATE_SUB_KEY)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer key.Close()

	child, _, err := registry.CreateKey(key, "Probe", registry.READ)
	if err == nil {
		child.Close()
		_ = registry.DeleteKey(key, "Probe")
		return false
	}
	if errors.Is(err, windows.ERROR_CHILD_MUST_BE_VOLATILE) {
		return true
	}
	t.Fatalf("probe %s: %v", path, err)
	return false
}

// The point of the change: a rule that is still there after a restart is a
// machine with no DNS and nothing running that knows why.
func TestTheDNSRuleDoesNotOutliveTheBoot(t *testing.T) {
	scratchTable(t)

	if err := writeNRPTRule(testTable, testRule, []string{testNamespace}, testServers); err != nil {
		t.Fatal(err)
	}
	if !isVolatile(t, testTable+`\`+testRule) {
		t.Fatal("the rule was written as a permanent key")
	}
}

// Created along with the rule it would be volatile too, and then no other
// VPN could install a permanent rule in it until the next reboot.
func TestTheTableIsLeftPermanent(t *testing.T) {
	scratchTable(t)

	if err := writeNRPTRule(testTable, testRule, []string{testNamespace}, testServers); err != nil {
		t.Fatal(err)
	}
	if isVolatile(t, testTable) {
		t.Fatal("the table was created volatile")
	}

	sibling, _, err := registry.CreateKey(registry.LOCAL_MACHINE, testTable+`\Sibling`, registry.READ)
	if err != nil {
		t.Fatalf("another rule can no longer be installed next to ours: %v", err)
	}
	sibling.Close()
}

// Creating over a key that exists opens it as it is, so the rule a core
// before this one left behind has to go first.
func TestAPermanentRuleLeftByAnOlderCoreIsReplaced(t *testing.T) {
	scratchTable(t)

	old, _, err := registry.CreateKey(registry.LOCAL_MACHINE, testTable+`\`+testRule, registry.SET_VALUE)
	if err != nil {
		t.Fatal(err)
	}
	if err := old.SetStringValue("GenericDNSServers", "10.9.9.9"); err != nil {
		t.Fatal(err)
	}
	old.Close()

	if err := writeNRPTRule(testTable, testRule, []string{testNamespace}, testServers); err != nil {
		t.Fatal(err)
	}
	if !isVolatile(t, testTable+`\`+testRule) {
		t.Fatal("the old permanent rule was reused")
	}
}

func TestTheDNSRuleSaysWhatTheClientReads(t *testing.T) {
	scratchTable(t)

	servers := []netip.Addr{netip.MustParseAddr("198.18.0.2"), netip.MustParseAddr("198.18.0.3")}
	if err := writeNRPTRule(testTable, testRule, []string{testNamespace}, servers); err != nil {
		t.Fatal(err)
	}

	key, err := registry.OpenKey(registry.LOCAL_MACHINE, testTable+`\`+testRule, registry.QUERY_VALUE)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Close()

	if names, _, err := key.GetStringsValue("Name"); err != nil || len(names) != 1 || names[0] != testNamespace {
		t.Fatalf("Name = %v, %v", names, err)
	}
	if got, _, err := key.GetStringValue("GenericDNSServers"); err != nil || got != "198.18.0.2;198.18.0.3" {
		t.Fatalf("GenericDNSServers = %q, %v", got, err)
	}
	if got, _, err := key.GetIntegerValue("ConfigOptions"); err != nil || got != nrptConfigOptionsDNSServers {
		t.Fatalf("ConfigOptions = %d, %v", got, err)
	}
	if got, _, err := key.GetIntegerValue("Version"); err != nil || got != nrptVersion {
		t.Fatalf("Version = %d, %v", got, err)
	}
}

func TestNoServersMeansNoRule(t *testing.T) {
	scratchTable(t)

	if err := writeNRPTRule(testTable, testRule, []string{testNamespace}, nil); err != nil {
		t.Fatal(err)
	}
	if key, err := registry.OpenKey(registry.LOCAL_MACHINE, testTable+`\`+testRule, registry.READ); err == nil {
		key.Close()
		t.Fatal("a rule naming no servers was installed")
	}
}

// Against the DNS client's own table: the path is right, this process may
// write there, and removal finds what was written.
func TestARuleInTheRealTableIsRemoved(t *testing.T) {
	requireElevated(t)
	path := nrptLocalKeyPath + `\` + testRule
	t.Cleanup(func() { deleteNRPTRule(testRule) })

	if err := writeNRPTRule(nrptLocalKeyPath, testRule, []string{testNamespace}, testServers); err != nil {
		t.Fatal(err)
	}
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.READ)
	if err != nil {
		t.Fatalf("the rule is not where the DNS client looks: %v", err)
	}
	key.Close()

	deleteNRPTRule(testRule)

	if key, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.READ); err == nil {
		key.Close()
		t.Fatal("the rule is still there after removal")
	}
	// And removing what is not there is not an error or a panic.
	deleteNRPTRule(testRule)
}

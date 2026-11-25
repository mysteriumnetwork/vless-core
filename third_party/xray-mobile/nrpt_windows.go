package XRay

import (
	"fmt"
	"net/netip"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Setting DNS on the tunnel adapter is not enough on Windows.
//
// Smart multi-homed name resolution sends a query to the resolvers of every
// interface at once and takes the first answer, so the adapter's metric does
// not decide who sees the name. Worse, the physical adapter's resolver is
// usually the LAN router, reached over an on-link /24 that beats this
// tunnel's /1 halves on longest-prefix match — so that query leaves in the
// clear no matter what the routing table says about the default route.
//
// The Name Resolution Policy Table is the documented way out: a rule for "."
// names the only servers the DNS client may ask, for every namespace and both
// address families, and it takes precedence over per-interface resolvers.
//
// The alternative is a WFP filter blocking port 53 everywhere else, which is
// what wireguard-windows does. That is reachable here through
// firewall.EnableFirewall, but only together with its blockAll rule — a full
// kill switch that also cuts LAN access. It belongs with a deliberate kill
// switch feature rather than with a DNS fix.

const (
	// Two tables exist, and they are not additive: when the Group Policy one
	// is present Windows ignores the local one entirely, so a rule written
	// only here would be silently inert on a managed machine — the kind most
	// likely to care about a leak. Both OpenVPN and Tailscale deal with this
	// by writing to the Group Policy table when it exists, which is what
	// nrptBaseKey picks.
	nrptLocalKeyPath  = `SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig`
	nrptPolicyKeyPath = `SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig`

	// Named rather than a GUID so a rule left behind by a crash is
	// recognisable, both to us at startup and to anyone reading the registry.
	// The plugin removes a leftover by this name too, when the core is in no
	// state to: kCoreDnsRule in vless_dart's windows/dns_policy.cpp has to
	// match.
	nrptRuleName = "MysteriumVlessDns"

	// A single "." matches every namespace.
	nrptAllNamespaces = "."

	// The rule names its own DNS servers.
	nrptConfigOptionsDNSServers = 0x08
	nrptVersion                 = 2
)

// ApplyDNSPolicy points all name resolution at [servers] until
// [UnconfigureTun] runs.
//
// Its own step rather than part of [ConfigureTun], and the last one of a
// start: this rule is the one thing here that does harm when it outlives the
// process, so it goes in only once the tunnel is known to carry traffic.
// Until then lookups go where they went before the connect, which nobody was
// promised otherwise.
func ApplyDNSPolicy(servers []netip.Addr) error {
	netMu.Lock()
	defer netMu.Unlock()
	return writeNRPTRule(nrptBaseKey(), nrptRuleName, []string{nrptAllNamespaces}, servers)
}

// writeNRPTRule installs [rule] under the table at [base].
func writeNRPTRule(base, rule string, namespaces []string, servers []netip.Addr) error {
	if len(servers) == 0 {
		return nil
	}

	addresses := make([]string, 0, len(servers))
	for _, server := range servers {
		addresses = append(addresses, server.String())
	}

	// The table itself is created permanent when it is missing. Left to the
	// call below it would be created volatile along with the rule, and a
	// volatile key cannot hold a permanent one: every other VPN's rule would
	// then fail to install until the next reboot.
	table, _, err := registry.CreateKey(registry.LOCAL_MACHINE, base, registry.CREATE_SUB_KEY)
	if err != nil {
		return fmt.Errorf("open nrpt table: %w", err)
	}
	defer table.Close()

	// Creating over a key that exists opens it as it is, and one left by a
	// core older than this is permanent.
	_ = registry.DeleteKey(table, rule)

	key, err := createVolatileKey(table, rule)
	if err != nil {
		return fmt.Errorf("create nrpt rule: %w", err)
	}
	defer key.Close()

	if err := key.SetDWordValue("Version", nrptVersion); err != nil {
		return fmt.Errorf("nrpt version: %w", err)
	}
	if err := key.SetStringsValue("Name", namespaces); err != nil {
		return fmt.Errorf("nrpt name: %w", err)
	}
	if err := key.SetStringValue("GenericDNSServers", strings.Join(addresses, ";")); err != nil {
		return fmt.Errorf("nrpt servers: %w", err)
	}
	if err := key.SetDWordValue("ConfigOptions", nrptConfigOptionsDNSServers); err != nil {
		return fmt.Errorf("nrpt options: %w", err)
	}
	// Cosmetic, but this rule is visible in Get-DnsClientNrptRule and in the
	// registry, and an unlabelled one is hard to attribute.
	if err := key.SetStringValue("DisplayName", "Mysterium VPN"); err != nil {
		return fmt.Errorf("nrpt display name: %w", err)
	}

	// Answers cached before the rule was installed were resolved by whoever
	// the adapter pointed at, and would keep being served from the cache.
	flushDNSCache()
	return nil
}

const regOptionVolatile = 0x1

var procRegCreateKeyExW = windows.NewLazySystemDLL("advapi32.dll").
	NewProc("RegCreateKeyExW")

// createVolatileKey creates a key that is never written to disk.
//
// Nothing runs on the way out when this process is killed, so the rule is
// made to not outlive the boot it was written in: a restart or a full
// shutdown drops it whoever is or is not there to remove it.
//
// A backstop, not the mechanism. A shutdown with Fast Startup, the default,
// hibernates the kernel rather than ending it, and a key held in its memory
// can be expected to come back with it. Removal is still what the plugin and
// the startup of this process are for.
//
// The registry package has no way to ask for this, hence the direct call.
func createVolatileKey(parent registry.Key, name string) (registry.Key, error) {
	path, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	var handle windows.Handle
	status, _, _ := procRegCreateKeyExW.Call(
		uintptr(parent),
		uintptr(unsafe.Pointer(path)),
		0,
		0,
		regOptionVolatile,
		uintptr(registry.SET_VALUE),
		0,
		uintptr(unsafe.Pointer(&handle)),
		0,
	)
	if status != 0 {
		return 0, windows.Errno(status)
	}
	return registry.Key(handle), nil
}

// ClearStaleDNSPolicy removes a rule left behind by a previous run.
//
// Nothing runs on the way out when the host app dies and the job object kills
// the core, and this rule is the one piece of configuration that both outlives
// the process and does harm on its own: left in place it sends every lookup on
// the machine to a resolver only reachable through a tunnel that is gone.
// Called at startup, before any tunnel exists.
func ClearStaleDNSPolicy() {
	removeNRPT()
}

// nrptBaseKey reports which table to write to: the Group Policy one when it
// exists, since its presence makes Windows ignore the local table, otherwise
// the local one.
func nrptBaseKey() string {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, nrptPolicyKeyPath, registry.READ)
	if err != nil {
		return nrptLocalKeyPath
	}
	key.Close()
	return nrptPolicyKeyPath
}

// removeNRPT drops the rule. Safe to call when none is installed.
func removeNRPT() {
	deleteNRPTRule(nrptRuleName)
}

func deleteNRPTRule(rule string) {
	// From both tables rather than from whichever one nrptBaseKey picks now:
	// the Group Policy table can appear or disappear between applying a rule
	// and dropping it, and the copy left behind would be the one still in
	// force.
	for _, base := range []string{nrptLocalKeyPath, nrptPolicyKeyPath} {
		_ = registry.DeleteKey(registry.LOCAL_MACHINE, base+`\`+rule)
	}
	// Deleting the key is what lifts the policy; the flush drops answers
	// resolved while it was in force.
	flushDNSCache()
}

var procDnsFlushResolverCache = windows.NewLazySystemDLL("dnsapi.dll").
	NewProc("DnsFlushResolverCache")

// flushDNSCache is best effort: it only drops cached answers, and a failure
// costs staleness rather than correctness.
func flushDNSCache() {
	if err := procDnsFlushResolverCache.Find(); err != nil {
		return
	}
	_, _, _ = procDnsFlushResolverCache.Call()
}

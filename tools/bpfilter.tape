# VHS script to generate the demo GIFs
#
# Uses https://github.com/charmbracelet/vhs
# To generate the GIFs:
#  vhs tools/bpfilter_dark.tape
#  vhs tools/bpfilter_light.tape

Require bfcli

Set Shell "bash"
Set FontSize 22
Set Width 1280
Set Height 900

Type "# Can we ping thefacebook.com"
Backspace 15
Type "facebook.com?" Sleep 500ms Enter
Type "ping -n -c 2 -W 1 facebook.com" Sleep 500ms Enter
Sleep 2500ms

Enter
Type "# Can we fetch https://1.1.1.1?" Sleep 500ms Enter
Type "# We expect a 301 return code to redirect the request to the proper location" Sleep 500ms Enter
Type "curl -m 2 -s -o /dev/null -w '%{http_code}\n' https://1.1.1.1" Sleep 500ms Enter
Sleep 2500ms

Enter
Type "# Block ICMP on input, and https://1.1.1.1 on output" Sleep 500ms Enter
Type "sudo bfcli ruleset set --from-str '" Enter
Type "chain my_input_chain BF_HOOK_XDP{ifindex=2} ACCEPT" Enter
Type "  rule" Enter
Type "    ip4.proto icmp" Enter
Type "    counter" Enter
Type "    DROP" Enter
Type "chain my_output_chain BF_HOOK_TC_EGRESS{ifindex=2} ACCEPT" Enter
Type "  rule" Enter
Type "    (ip4.daddr) in {1.1.1.1; 8.8.8.8}" Enter
Type "    tcp.dport eq 443" Enter
Type "    counter" Enter
Type "    log" Enter
Type "    DROP" Enter
Type "'" Sleep 500ms Enter

Enter
Type "# Both should fail now" Sleep 500ms Enter
Type "ping -n -c 2 -W 1 facebook.com" Sleep 500ms Enter
Sleep 3s

Enter
Type "curl -m 2 -sS -o /dev/null -w '%{http_code}\n' https://1.1.1.1" Sleep 500ms Enter
Sleep 3s

Enter
Type "# But HTTP traffic to 1.1.1.1 is not blocked" Sleep 500ms Enter
Type "curl -m 2 -s -o /dev/null -w '%{http_code}\n' http://1.1.1.1" Sleep 500ms Enter
Sleep 3s

Enter
Type "# Per-rule counters confirm both rules fired" Sleep 500ms Enter
Type "sudo bfcli ruleset get" Sleep 500ms Enter
Sleep 8s

Enter
Type "# Show logged traffic to https://1.1.1.1" Sleep 500ms Enter
Type "timeout 2 sudo bfcli chain logs --name my_output_chain" Sleep 500ms Enter
Sleep 8s

Hide
Ctrl+C

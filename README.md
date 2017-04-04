# IDS rule parse for the Go language

The package provides a parser for Suricata and Snort style IDS rules.

## Usage

    line := "alert tcp $TELNET_SERVERS 23 -> $EXTERNAL_NET any (msg:"GPL TELNET TELNET login failed"; flow:from_server,established; content:"Login failed"; nocase; classtype:bad-unknown; sid:2100492; rev:10;)"
    rule, err := idsrules.Parse(line)
    if err != nil {
        log.Fatal(err)
    }
    log.Printf("Rule [%s] is enable: %v", rule.Msg, rule.Enabled)

## License

MIT.

# fwloki

fwloki is a simple daemon to watch a log file (typically /var/log/messages)
for iptables logs, parse them and write them back out to [loki][] in a few
short microseconds. Optionally, you can also add some GeoIP metadata to the
logs at the expense of a bit more extra processing time.

Once in loki, you're free to do what you like with the logs, stick them in a
table in Grafana? Sure. Show the data in a world map to see who's targeting
your network? Of course. Inspect and drop traffic from repeat offenders? If
that's what you're into.

The world's your clam, really.

[loki]: https://github.com/grafana/loki

#### Config

```toml
log-file = "/var/log/messages"

# [geoip]
# asn-db = "./db/GeoLite2-ASN.mmdb"
# city-db = "./db/GeoLite2-City.mmdb"
# country-db = "./db/GeoLite2-Country.mmdb"

[firewall]
rules = [
    "OUTSIDE-LOCAL-default-D",
    "OUTSIDE-LOCAL-V6-default-D",
    "OUTSIDE-IN-default-D",
    "OUTSIDE-IN-V6-default-D"
]

[loki]
push-url = "http://10.0.0.28:3100/loki/api/v1/push"
```

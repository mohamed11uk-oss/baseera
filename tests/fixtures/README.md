SYNTHETIC test fixtures (invented domains, shaped like the real source formats). Not real feed data.

- `whois_ae_sample.txt`: shaped like the aeDA (whois.aeda.net.ae) legacy layout (padded "Label:   value" lines,
  contact IDs, Name Server lines) with NO date fields. Not captured live: port 43 returned no data from the build box.
- `whois_ae_sample_dated.txt`: ICANN-style layout with a `Creation Date:` line, in case the .ae output includes one.
- `rdap_sample.json`: RFC 9083 domain object (events/entities/nameservers) for an invented domain.

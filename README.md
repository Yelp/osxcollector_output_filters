# OSXCollector Output Filters [![Build Status: master](https://travis-ci.org/Yelp/osxcollector_output_filters.svg?branch=master)](https://travis-ci.org/Yelp/osxcollector_output_filters)  [![PyPI](https://img.shields.io/pypi/v/osxcollector_output_filters.svg)](https://pypi.python.org/pypi/osxcollector_output_filters)
The `osxcollector.output_filters` package contains filters that process and transform the output of [OSXCollector](https://github.com/Yelp/osxcollector). The goal of filters is to make it easy to analyze OSXCollector output.

Each filter has a single purpose. They do one thing and they do it right.

## Running Filters in a VirtualEnv
Unlike `osxcollector.py` filters have dependencies that aren't already installed on a new Mac. The best solution for ensure dependencies can be found is to use virtualenv.

To setup a virtualenv for the first time use:
```shell
$ sudo pip install tox virtualenv
$ make venv
$ source virtualenv_run/bin/activate  # Not necessary if you use aactivator
```

## Filter Configuration
Many filters require configuration, like API keys or details on a blacklist. The configuration for filters is done in a YAML file. The file is named `osxcollector.yaml`. The filter will look for the configuration file in:
- The current directory.
- The user's home directory.
- The path pointed to by the environment variable `OSXCOLLECTOR_CONF`.

A sample config is included. Make a copy and then modify if for yourself:
```shell
$ cp osxcollector.yaml.example osxcollector.yaml
$ emacs osxcollector.yaml
```

## Basic Filters
Using combinations of these basic filters, an analyst can figure out a lot of what happened without expensive tools, without threat feeds or fancy APIs.

### FindDomainsFilter
`osxcollector.output_filters.find_domains.FindDomainsFilter` attempts to find domain names in OSXCollector output. The domains are added to the line with the key `osxcollector_domains`.

FindDomainsFilter isn't too useful on it's own but it's super powerful when chained with filters like `FindBlacklistedFilter` and or `osxcollector.output_filters.virustotal.lookup_domains.LookupDomainsFilter`.

To run and see lines where domains have been added try:
```shell
$ python -m osxcollector.output_filters.find_domains -i RomeoCredible.json | \
    jq 'select(has("osxcollector_domains"))'
```

Usage:
```shell
$ python -m osxcollector.output_filters.find_domains -h
usage: find_domains.py [-h] [--input-file INPUT_FILE]

optional arguments:
  -h, --help            show this help message and exit
  --input-file INPUT_FILE
                        [OPTIONAL] Path to OSXCollector output to read.
                        Defaults to stdin otherwise.
```

### FindBlacklistedFilter
`osxcollector.output_filters.find_blacklisted.FindBlacklistedFilter` reads a set of blacklists from the `osxcollector.yaml` and marks any lines with values on the blacklist. The BlacklistFilter is flexible and allows you to compare the OSXCollector output against multiple blacklists.

You _really should_ create blacklists for domains, file hashes, file names, and any known hinky stuff.

Configuration Keys:
* `blacklist_name`: [REQUIRED] the name of the blacklist.
* `blacklist_keys`: [REQUIRED] get the value of these keys and compare against the blacklist. These can be of the form `a.b` to look at `b` in `{"a": {"b": "foo"}}`
* `blacklist_file_path`: [REQUIRED] path to a file with the actual values to blacklist
* `blacklist_is_regex`: [REQUIRED] should the values in the blacklist file be treated as regex
* `blacklist_is_domains`: [OPTIONAL] interpret values as domains and do some smart regex and subdomain stuff with them.

If you want to find blacklisted domains, you will have to use the find_domains filter to pull the domains out first. To see lines matching a specific blacklist named `domains` try:
```shell
$ python -m osxcollector.output_filters.find_domains -i RiddlerBelize.json | \
    python -m osxcollector.output_filters.find_blacklisted | \
    jq 'select(has("osxcollector_blacklist")) | \
        select(.osxcollector_blacklist | keys[] | contains("domains"))'
```

Usage:
```shell
$ python -m osxcollector.output_filters.find_blacklisted -h
usage: find_blacklisted.py [-h] [--input-file INPUT_FILE]

optional arguments:
  -h, --help            show this help message and exit
  --input-file INPUT_FILE
                        [OPTIONAL] Path to OSXCollector output to read.
                        Defaults to stdin otherwise.
```

### RelatedFilesFilter
`osxcollector.output_filters.related_files.RelatedFilesFilter` takes an initial set of file paths, names, or terms. It breaks this input into individual file and directory names and then searches for these terms across the entire OSXCollector output. The filter is smart and ignores common terms like `bin` or `Library` as well as ignoring user names.

This filter is great for figuring out how `evil_invoice.pdf` landed up on a machine. It'll find browser history, quarantines, email messages, etc. related to a file.

To run and see related lines try:
```shell
$ python -m osxcollector.output_filters.related_files -i CanisAsp.json -f '/foo/bar/baz' -f 'dingle' | \
    jq 'select(has("osxcollector_related")) | \
        select(.osxcollector_related | keys[] | contains("files"))'
```

Usage:
```shell
$ python -m osxcollector.output_filters.related_files -h
usage: related_files.py [-h] [-f FILE_TERMS] [--input-file INPUT_FILE]

optional arguments:
  -h, --help            show this help message and exit
  --input-file INPUT_FILE
                        [OPTIONAL] Path to OSXCollector output to read.
                        Defaults to stdin otherwise.

RelatedFilesFilter:
  -f FILE_TERMS, --file-term FILE_TERMS
                        [OPTIONAL] Suspicious terms to use in pivoting through
                        file names. May be specified more than once.
```

### ChromeHistoryFilter
`osxcollector.output_filters.chrome.sort_history.SortHistoryFilter` builds a really nice Chrome browser history sorted in descending time order. This output is comparable to looking at the history tab in the browser but actually contains _more_ info. The `core_transition` and `page_transition` keys explain whether the user got to the page by clicking a link, through a redirect, a hidden iframe, etc.

To run and see Chrome browser history:
```shell
$ python -m osxcollector.output_filters.chrome.sort_history -i SirCray.json | \
    jq 'select(.osxcollector_browser_history=="chrome")'
```

This is great mixed with a grep in a certain time window, like maybe the 5 minutes before that hinky download happened.
```shell
$ python -m osxcollector.output_filters.chrome.sort_history -i SirCray.json | \
    jq -c 'select(.osxcollector_browser_history=="chrome")' | \
    egrep '2015-02-02 20:3[2-6]'
```

Usage:
```shell
$ python -m osxcollector.output_filters.chrome.sort_history -h
usage: sort_history.py [-h] [--input-file INPUT_FILE]

optional arguments:
  -h, --help            show this help message and exit
  --input-file INPUT_FILE
                        [OPTIONAL] Path to OSXCollector output to read.
                        Defaults to stdin otherwise.
```

### FirefoxHistoryFilter
`osxcollector.output_filters.firefox.sort_history.SortHistoryFilter` builds a really nice Firefox browser history sorted in descending time order. It's a lot like the `ChromeHistoryFilter`.

To run and see Firefox browser history:
```shell
$ python -m osxcollector.output_filters.firefox.sort_history -i CousingLobe.json | \
    jq 'select(.osxcollector_browser_history=="firefox")'
```

Usage:
```shell
$ python -m osxcollector.output_filters.firefox.sort_history -h
usage: sort_history.py [-h] [--input-file INPUT_FILE]

optional arguments:
  -h, --help            show this help message and exit
  --input-file INPUT_FILE
                        [OPTIONAL] Path to OSXCollector output to read.
                        Defaults to stdin otherwise.
```

### ChromeExtensionsFilter
`osxcollector.output_filters.chrome.find_extensions.FindExtensionsFilter` looks for extensions in the Chrome JSON files.

To run and see Chrome extensions:
```shell
$ python -m osxcollector.output_filters.chrome.find_extensions -i MotherlyWolf.json | \
    jq 'select(.osxcollector_section=="chrome" and
               .osxcollector_subsection=="extensions")'
```

Usage:
```shell
$ python -m osxcollector.output_filters.chrome.find_extensions -h
usage: find_extensions.py [-h] [--input-file INPUT_FILE]

optional arguments:
  -h, --help            show this help message and exit
  --input-file INPUT_FILE
                        [OPTIONAL] Path to OSXCollector output to read.
                        Defaults to stdin otherwise.
```

### FirefoxExtensionsFilter
`osxcollector.output_filters.firefox.find_extensions.FindExtensionsFilter` looks for extensions in the Firefox JSON files.

To run and see Firefox extensions:
```shell
$ python -m osxcollector.output_filters.firefox.find_extensions -i FlawlessPelican.json | \
    jq 'select(.osxcollector_section=="firefox" and
               .osxcollector_subsection=="extensions")'
```

Usage:
```shell
$ python -m osxcollector.output_filters.firefox.find_extensions -h
usage: find_extensions.py [-h] [--input-file INPUT_FILE]

optional arguments:
  -h, --help            show this help message and exit
  --input-file INPUT_FILE
                        [OPTIONAL] Path to OSXCollector output to read.
                        Defaults to stdin otherwise.
```

## Threat API Filters
By taking the output of OSXCollector and looking up further info with OpenDNS and VirusTotal APIs, Yelp enhances the output with useful info. Some of these APIs aren't free but they are useful.

Using these filters as examples, it would be possible to integrate with additional free or premium threat APIs. `osxcollector.output_filters.base_filters.threat_feed.ThreatFeedFilter` has most of the plumbing for hooking up to arbitrary APIs.

### OpenDNS RelatedDomainsFilter
`osxcollector.output_filters.opendns.related_domains.RelatedDomainsFilter` takes an initial set of domains and IPs and then looks up domains related to them with the OpenDNS Umbrella API.

Often an initial alert contains a domain or IP your analysts don't know anything about. However, by gathering the 2nd generation related domains, familiar _friends_ might appear. When you're lucky, those related domains land up being the download source for some downloads you might have overlooked.

The filter will ignore domains if they are in the blacklist named `domain_whitelist`. This helps to reduce churn and false positives.

Run it as and see what it found:
```shell
$ python -m osxcollector.output_filters.find_domains -i NotchCherry.json | \
    python -m osxcollector.output_filters.opendns.related_domains \
           -d dismalhedgehog.com -d fantasticrabbit.org \
           -i 128.128.128.28 | \
    jq 'select(has("osxcollector_related")) |
        select(.osxcollector_related | keys[] | contains("domains"))'
```

The results will look something like:
```
{
   'osxcollector_related': {
       'domains': {
           'domain_in_line.com': ['dismalhedgehog.com'],
           'another.com': ['128.128.128.28']
       }
    }
}
```

Usage:
```shell
$ python -m osxcollector.output_filters.opendns.related_domains -h
usage: related_domains.py [-h] [-d INITIAL_DOMAINS] [-i INITIAL_IPS]
                          [--related-domains-generations GENERATIONS]
                          [--input-file INPUT_FILE]

optional arguments:
  -h, --help            show this help message and exit
  --input-file INPUT_FILE
                        [OPTIONAL] Path to OSXCollector output to read.
                        Defaults to stdin otherwise.

opendns.RelatedDomainsFilter:
  -d INITIAL_DOMAINS, --domain INITIAL_DOMAINS
                        [OPTIONAL] Suspicious domains to use in pivoting. May
                        be specified more than once.
  -i INITIAL_IPS, --ip INITIAL_IPS
                        [OPTIONAL] Suspicious IP to use in pivoting. May be
                        specified more than once.
  --related-domains-generations GENERATIONS
                        [OPTIONAL] How many generations of related domains to
                        lookup with OpenDNS
```

### OpenDNS LookupDomainsFilter
`osxcollector.output_filters.opendns.lookup_domains.LookupDomainsFilter` lookups domain reputation and threat information with the OpenDNS Umbrella API. It adds information about _suspicious_ domains to the output lines.

The filter uses a heuristic to determine what is _suspicious_. It can create false positives but usually a download from a domain marked as _suspicious_ is a good lead.

Run it and see what was found:
```shell
$ python -m osxcollector.output_filters.find_domains -i GladElegant.json | \
    python -m osxcollector.output_filters.opendns.lookup_domains | \
    jq 'select(has("osxcollector_opendns"))'
```

Usage:
```shell
$ python -m osxcollector.output_filters.opendns.lookup_domains -h
usage: lookup_domains.py [-h] [--input-file INPUT_FILE]

optional arguments:
  -h, --help            show this help message and exit
  --input-file INPUT_FILE
                        [OPTIONAL] Path to OSXCollector output to read.
                        Defaults to stdin otherwise.
```

### VirusTotal LookupDomainsFilter
`osxcollector.output_filters.virustotal.lookup_domains.LookupDomainsFilter` lookups domain reputation and threat information with the VirusTotal API. It adds information about _suspicious_ domains to the output lines. It's a lot like the OpenDNS filter of the same name.

The filter uses a heuristic to determine what is _suspicious_. It can create a lot of false positives but also provides good leads.

Run it and see what was found:
```shell
$ python -m osxcollector.output_filters.find_domains -i PippinNightstar.json | \
    python -m osxcollector.output_filters.virustotal.lookup_domains | \
    jq 'select(has("osxcollector_vtdomain"))'
```

Usage:
```shell
$ python -m osxcollector.output_filters.virustotal.lookup_domains -h
usage: lookup_domains.py [-h] [--input-file INPUT_FILE]

optional arguments:
  -h, --help            show this help message and exit
  --input-file INPUT_FILE
                        [OPTIONAL] Path to OSXCollector output to read.
                        Defaults to stdin otherwise.
```

### VirusTotal LookupHashesFilter
`osxcollector.output_filters.virustotal.lookup_hashes.LookupHashesFilter` lookups hashes with the VirusTotal API. This basically finds anything VirusTotal knows about which is a huge time saver. There's pretty much no false positives here, but there's also no chance of detecting unknown stuff.

Run it and see what was found:
```shell
$ python -m osxcollector.output_filters.virustotal.lookup_hashes -i FungalBuritto.json | \
    jq 'select(has("osxcollector_vthash"))'
```

Usage:
```shell
$ python -m osxcollector.output_filters.virustotal.lookup_hashes -h
usage: lookup_hashes.py [-h] [--input-file INPUT_FILE]

optional arguments:
  -h, --help            show this help message and exit
  --input-file INPUT_FILE
                        [OPTIONAL] Path to OSXCollector output to read.
                        Defaults to stdin otherwise.
```

### VirusTotal LookupURLsFilter
`osxcollector.output_filters.virustotal.lookup_hashes.LookupURLsFilter` lookups URLs with the VirusTotal API. As this only looks up the reports, it may not find the reports for some unknown URLs.

Run it and see what was found:
```shell
$ python -m osxcollector.output_filters.virustotal.lookup_urls -i WutheringLows.json | \
    jq 'select(has("osxcollector_vturl"))'
```

Usage
```shell
$ python -m osxcollector.output_filters.virustotal.lookup_urls -h
usage: lookup_urls.py [-h] [--input-file INPUT_FILE]

optional arguments:
  -h, --help            show this help message and exit
  --input-file INPUT_FILE
                        [OPTIONAL] Path to OSXCollector output to read.
                        Defaults to stdin otherwise.
```

#### Maximum resources per request
Both VirusTotal LookupHashesFilter and LookupURLsFilter can save time by including in a single API request the reports for the multiple resources (hashes or URLs).
As the number of the maximum resources in a request depends on whether you are using a Public or Private API key it is configurable in `osxcollector.yaml` file in `virustotal` section:
```yaml
resources_per_req: 4
```

### ShadowServer LookupHashesFilter
`osxcollector.output_filters.shadowserver.lookup_hashes.LookupHashesFilter`
lookups hashes with the ShadowServer bin-test API. This is sort of the opposite of a VirusTotal lookup and returns results when it sees the hashes of known good files. This helps raise confidence that a file is not malicious.

Run it and see what was found:
```shell
$ python -m osxcollector.output_filters.shadowserver.lookup_hashes -i ArkashKobiashi.json | \
    jq 'select(has("osxcollector_shadowserver"))'
```

Usage:
```shell
$ python -m osxcollector.output_filters.shadowserver.lookup_hashes -h
usage: lookup_hashes.py [-h] [--input-file INPUT_FILE]

optional arguments:
  -h, --help            show this help message and exit
  --input-file INPUT_FILE
                        [OPTIONAL] Path to OSXCollector output to read.
                        Defaults to stdin otherwise.
```

## AnalyzeFilter - The One Filter to Rule Them All
`osxcollector.output_filters.analyze.AnalyzeFilter` is Yelp's _one filter to rule them all_. It chains all the previous filters into one monster analysis. The results, enhanced with blacklist info, threat APIs, related files and domains, and even pretty browser history is written to a new output file.

Then _Very Readable Output Bot_ takes over and prints out an easy-to-digest, human-readable, nearly-English summary of what it found. It's basically equivalent to running:
```shell
$ python -m osxcollector.output_filters.chrome.find_extensions.FindExtensionsFilter -i SlickApocalypse.json | \
    python -m osxcollector.output_filters.firefox.find_extensions.FindExtensionsFilter | \
    python -m osxcollector.output_filters.find_domains | \
    python -m osxcollector.output_filters.shadowserver.lookup_hashes | \
    python -m osxcollector.output_filters.virustotal.lookup_hashes | \
    python -m osxcollector.output_filters.find_blacklisted | \
    python -m osxcollector.output_filters.related_files | \
    python -m osxcollector.output_filters.opendns.related_domains | \
    python -m osxcollector.output_filters.opendns.lookup_domains | \
    python -m osxcollector.output_filters.virustotal.lookup_domains | \
    python -m osxcollector.output_filters.chrome_history | \
    python -m osxcollector.output_filters.firefox_history | \
    tee analyze_SlickApocalypse.json | \
    jq 'select(false == has("osxcollector_shadowserver")) |
        select(has("osxcollector_vthash") or
               has("osxcollector_vtdomain") or
               has("osxcollector_opendns") or
               has("osxcollector_blacklist") or
               has("osxcollector_related"))'
```
and then letting a wise-cracking analyst explain the results to you. The _Very Readable Output Bot_ even suggests hashes and domains to add to blacklists.

This thing is the real deal and our analysts don't even look at OSXCollector output until after they've run the `AnalyzeFilter`.

Run it as:
```shell
$ python -m osxcollector.output_filters.analyze -i FullMonty.json
```

Usage:
```shell
$ python -m osxcollector.output_filters.analyze -h
usage: analyze.py [-f FILE_TERMS] [-d INITIAL_DOMAINS] [-i INITIAL_IPS]
                  [--related-domains-generations GENERATIONS] [-h] [--readout]
                  [--no-opendns] [--no-virustotal] [--no-shadowserver] [-M]
                  [--show-signature-chain] [--show-browser-ext]
                  [--input-file INPUT_FILE]

optional arguments:
  -h, --help            show this help message and exit
  --input-file INPUT_FILE
                        [OPTIONAL] Path to OSXCollector output to read.
                        Defaults to stdin otherwise.

RelatedFilesFilter:
  -f FILE_TERMS, --file-term FILE_TERMS
                        [OPTIONAL] Suspicious terms to use in pivoting through
                        file names. May be specified more than once.

opendns.RelatedDomainsFilter:
  -d INITIAL_DOMAINS, --domain INITIAL_DOMAINS
                        [OPTIONAL] Suspicious domains to use in pivoting. May
                        be specified more than once.
  -i INITIAL_IPS, --ip INITIAL_IPS
                        [OPTIONAL] Suspicious IP to use in pivoting. May be
                        specified more than once.
  --related-domains-generations GENERATIONS
                        [OPTIONAL] How many generations of related domains to
                        lookup with OpenDNS

AnalyzeFilter:
  --readout             [OPTIONAL] Skip the analysis and just output really
                        readable analysis
  --no-opendns          [OPTIONAL] Don't run OpenDNS filters
  --no-virustotal       [OPTIONAL] Don't run VirusTotal filters
  --no-shadowserver     [OPTIONAL] Don't run ShadowServer filters
  -M, --monochrome      [OPTIONAL] Output monochrome analysis
  --show-signature-chain
                        [OPTIONAL] Output unsigned startup items and kexts.
  --show-browser-ext    [OPTIONAL] Output the list of installed browser
                        extensions.
```

## Contributing to OSXCollector Output Filters
We encourage you to extend the functionality of OSXCollector to suit your needs.

### Testing OSXCollector Output Filters
A collection of tests for OSXCollector Output Filters is provided under the `tests` directory. In order to run these tests you must install [tox](https://pypi.python.org/pypi/tox):
```shell
$ sudo pip install tox
```

To run this suit of tests, `cd` into `osxcollector` and enter:
```shell
$ make test
```

### Development Tips
Ensure that all of the OSXCollector Output Filters tests pass before editing the source code. You can run the tests using: `make test`

After making changes to the source code, run `make test` again to verify that your changes did not break any of the tests.

## License
This work is licensed under the GNU General Public License.

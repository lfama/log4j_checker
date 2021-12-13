# Log4j_checker.py (CVE-2021-44228)
![poc_log4j](https://user-images.githubusercontent.com/14056990/145903643-9f46cbb1-cbe4-488a-8e64-7c4f7b1c39c7.PNG)

## Description

This Python3 script tries to look for servers vulnerable to [CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228), also known as [Log4Shell](https://www.lunasec.io/docs/blog/log4j-zero-day/), a very critical vulnerability found in Log4j2 Java logging library. 

It doesn't rely on external DNS log servers to verify and validate the vulnerable targets: when started, a new thread listening on all interfaces and port 55555 (can be changed using .env file or environment variables) is created: it will wait for callback connections from the vulnerable machines and it will notify the main thread through a Python Queue. Keep in mind that you might need to add firewall rules (and/or port forwarding rules) to allow incoming connection to the listening IP:port pair.

In order to increase chances to trigger the vulnerability, the tool takes a URL as argument (or a list of URLs) and it looks for any form included in the URL(s) provided. Then it tries to exploit the vulnerability using each parameter for each form found (GET and POST requests). This is the default behaviour but it can be disabled using the ```--skip-forms``` option (in this case ony 1 request will be performed and the payload will be placed within few header fields).

Also, the following predefined headers are used to test if the targets are vulnerable:
- User-Agent
- X-Fowarded-For
- Referer

Custom headers can be added via command line option.

For a complete usage description see below section.

## Usage

```
python3 log4j_checker.py -h
usage: log4j_checker.py [-h] [--url URL] [--headers HEADERS [HEADERS ...]] [--urls URLS] [--skip-forms]

optional arguments:
  -h, --help            show this help message and exit
  --url URL             Single url you want to test (valid url is http(s)://host:[port]/[path])
  --headers HEADERS [HEADERS ...]
                        Custom headers you want to try (space separated)
  --urls URLS           A file containing 1 url per line
  --skip-forms          Skip forms check (only perform 1 request)
```

## Disclaimer

This tool is meant to be used for testing your own systems.
 

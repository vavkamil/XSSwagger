#!/usr/bin/python3.6

import re
import bs4
import argparse
import requests
import urllib.parse
import concurrent.futures

# from tqdm import tqdm
from termcolor import coloredrsion
from packaging import version
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# https://snyk.io/vuln/npm:swagger-ui


def banner():
    print(
        """    ) (   (                                    
 ( /( )\ ))\ )                                 
 )\()|()/(()/((  (      ) (  ( (  (    (  (    
((_)\ /(_))(_))\))(  ( /( )\))()\))(  ))\ )(   
__((_|_))(_))((_)()\ )(_)|(_))((_))\ /((_|()\  
\ \/ / __/ __|(()((_|(_)_ (()(_|()(_|_))  ((_) 
 >  <\__ \__ \ V  V / _` / _` / _` |/ -_)| '_| 
/_/\_\___/___/\_/\_/\__,_\__, \__, |\___||_|   
                         |___/|___/\n"""
    )


def parse_args():
    parser = argparse.ArgumentParser(
        description="XSSwagger",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", dest="domain", help="Wordlist of IPs or ranges to use")
    group.add_argument(
        "-D",
        dest="domains",
        help="Wordlist of IPs or ranges to use",
        type=argparse.FileType("r"),
    )
    parser.add_argument(
        "-w",
        dest="wordlist",
        help="Wordlist of IPs or ranges to use",
        default="swagger.lst",
        type=argparse.FileType("r"),
    )
    # parser.add_argument(
    #     "-o",
    #     dest="output",
    #     help="save output to a file (csv separated by semicolon)",
    #     type=argparse.FileType("w"),
    # )
    parser.add_argument(
        "-t",
        dest="threads",
        help="number of threads (default: 5)",
        default="5",
        type=int,
    )
    return parser.parse_args()


def load_domains(location):
    domains = []
    with location as domainlist:
        for domain in domainlist:
            if domain.strip() != "":
                domains.append(domain.strip())
    if not domains:
        print("Error no domains were found in the file")
    return domains


def load_domains2(location):
    domains = []
    with location as domainlist:
        for domain in domainlist:
            if domain.strip() != "":
                domains.append(domain.strip())
    if not domains:
        print("Error no domains were found in the file")
    return domains


def check_if_vulnerable(detected_version):
    vulnerabilities_details = [
        {
            "version": "2.0.24",
            "severity": "Medium",
            "published": "16 Jun, 2019",
            "vulnerable": ">=2.0.3 <2.0.24",
            "vulnerability": "Cross-site Scripting (XSS)",
            "detail": "https://snyk.io/vuln/SNYK-JS-SWAGGERUI-449942",
        },
        {
            "version": "2.1.0",
            "severity": "High",
            "published": "15 Aug, 2016",
            "vulnerable": "<2.1.0",
            "vulnerability": "Cross-site Scripting (XSS)",
            "detail": "https://snyk.io/vuln/npm:swagger-ui:20160815",
        },
        {
            "version": "2.2.1",
            "severity": "High",
            "published": "25 Jul, 2016",
            "vulnerable": "<2.2.1",
            "vulnerability": "Cross-site Scripting (XSS)",
            "detail": "https://snyk.io/vuln/npm:swagger-ui:20160725",
        },
        {
            "version": "2.2.3",
            "severity": "Medium",
            "published": "13 Mar, 2017",
            "vulnerable": "<2.2.3",
            "vulnerability": "Cross-site Scripting (XSS)",
            "detail": "https://snyk.io/vuln/npm:swagger-ui:20160901",
        },
        {
            "version": "3.0.13",
            "severity": "Medium",
            "published": "16 Jun, 2019",
            "vulnerable": ">=3.0.0 <3.0.13",
            "vulnerability": "Cross-site Scripting (XSS)",
            "detail": "https://snyk.io/vuln/SNYK-JS-SWAGGERUI-449941",
        },
        {
            "version": "3.4.2",
            "severity": "Medium",
            "published": "25 Dec, 2017",
            "vulnerable": "<3.4.2",
            "vulnerability": "Cross-site Scripting (XSS)",
            "detail": "https://snyk.io/vuln/npm:swagger-ui:20171031",
        },
        {
            "version": "3.18.0",
            "severity": "Medium",
            "published": "13 Jun, 2019",
            "vulnerable": "<3.18.0",
            "vulnerability": "Reverse Tabnabbing",
            "detail": "https://snyk.io/vuln/SNYK-JS-SWAGGERUI-449808",
        },
        {
            "version": "3.20.9",
            "severity": "Medium",
            "published": "14 Jun, 2019",
            "vulnerable": "<3.20.9",
            "vulnerability": "Cross-site Scripting (XSS)",
            "detail": "https://snyk.io/vuln/SNYK-JS-SWAGGERUI-449921",
        },
    ]

    vulnerabilities_versions = [
        "2.0.24",
        "2.1.0",
        "2.2.1",
        "2.2.3",
        "3.0.13",
        "3.4.2",
        "3.18.0",
        "3.20.9",
    ]

    vulnerable = [
        i
        for i in vulnerabilities_versions
        if version.parse(i) > version.parse(detected_version)
    ]  # https://stackoverflow.com/questions/4587915/return-list-of-items-in-list-greater-than-some-value

    if vulnerable:
        print("\n[ Vulnerable ] version", detected_version, "detected!")
        for vuln in vulnerable:
            my_item = next(
                (item for item in vulnerabilities_details if item["version"] == vuln),
                None,
            )
            print(10 * "----------")
            print("[ Severity ]", my_item["severity"])
            print("[ Vulnerable ]", my_item["vulnerable"])
            print("[ Published ]", my_item["published"])
            print("[ Vulnerability ]", my_item["vulnerability"])
            print("[ Detail ]", my_item["detail"])


def check_version(url, html):
    if re.search("(?<='|\")(.*?)swagger-ui.js(?='|\")", html):
        pr1 = re.search("(?<='|\")(.*?)swagger-ui.js(?='|\")", html)
        swagger_js_path = pr1.group()
        # swagger_js_path = re.sub('^.', '', swagger_js_path)
        url = re.sub("index.html", "", url)
        # print(swagger_js_path)
        swagger_ui_js = urllib.parse.urljoin(url + "/", swagger_js_path)
        # print(swagger_ui_js)
        response = requests.get(url=swagger_ui_js)
        pr1 = re.findall(
            "@version\sv(.*?)$", response.content.decode("utf-8"), re.MULTILINE
        )
        version_detected = pr1[0]
    elif re.search("(?<='|\")(.*?)swagger-ui-bundle.js(?='|\")", html):
        pr2 = re.search("(?<='|\")(.*?)swagger-ui-bundle.js(?='|\")", html)
        swagger_bundle_path = pr2.group(0)
        # swagger_bundle_path = re.sub('^.', '', swagger_bundle_path)
        # print("1", swagger_bundle_path)
        swagger_bundle_js = urllib.parse.urljoin(url + "/", swagger_bundle_path)
        # print("2", swagger_bundle_js)
        response2 = requests.get(url=swagger_bundle_js)
        pr2 = re.search(
            'd=!0,h="(.*?)",v="(.*?)",m="(.*?)",(g|y)="(.*?)";',
            response2.content.decode("utf-8"),
        )
        version_detected = pr2[2]
    else:
        version_detected = "error"

    return version_detected


def check_swagger(domain, path):
    url = "https://" + domain + "/" + path
    response = requests.get(url=url)

    html = bs4.BeautifulSoup(response.content, features="lxml")
    if (
        html.title
        and bool(re.search("Swagger|API", html.title.text))
        and response.status_code == 200
    ):
        return (
            1,
            response.status_code,
            html.title.text,
            url,
            response.content.decode("utf-8"),
        )
    else:
        return (0, 0, 0, 0, 0)


def check_domain(domain):
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        is_swagger = {
            executor.submit(check_swagger, domain, path): path
            for path in swagger_wordlist
        }
        for swagger in concurrent.futures.as_completed(is_swagger):
            (check, status_code, title, url, response) = swagger.result()
            if check == 1:
                print("\n" + 10 * "**********")
                print(10 * "**********" + "\n")
                print("[", status_code, "]", "[", title, "]", url)
                version_detected = check_version(url, response)
                if version_detected != "error":
                    print("[ Version ]", version_detected, "detected!")
                    check_if_vulnerable(version_detected)
                else:
                    print("[ Version ] Idk, please check manually!")


if __name__ == "__main__":
    banner()
    args = parse_args()

    if args.domain:
        domain = args.domain
        print("[i] Scanning a single domain:", domain, "\n")

        swagger_wordlist = load_domains(args.wordlist)

        check_domain(domain)

    if args.domains:
        domains = load_domains(args.domains)
        print("[i] Scanning multiple domains:", args.domains.name)
        print("[i] Domains in a list:", str(len(domains)))
        swagger_wordlist = load_domains2(args.wordlist)
        for domain in domains:

            for path in swagger_wordlist:
                url = "https://" + domain + "/" + path

                try:
                    response = requests.get(url=url, verify=False, timeout=5)
                except Exception:
                    pass

                html = bs4.BeautifulSoup(response.content, features="lxml")
                if (
                    html.title
                    and bool(re.search("Swagger|API", html.title.text))
                    and response.status_code == 200
                ):
                    print("\n" + 10 * "**********")
                    print(10 * "**********" + "\n")
                    if response.url != url:
                        print("[ Redirect ]", url, "->", response.url)
                    url = response.url
                    print(
                        "[", response.status_code, "]", "[", html.title.text, "]", url
                    )
                    version_detected = check_version(
                        url, response.content.decode("utf-8")
                    )
                    if version_detected != "error":
                        print("[ Version ]", version_detected, "detected!")
                        check_if_vulnerable(version_detected)
                    else:
                        print("[ Version ] Idk, please check manually!")

                else:
                    continue

    print("\n[ Done ] Don't be evil!\n")

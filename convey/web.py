import logging
import re

from bs4 import BeautifulSoup
import requests
from urllib.parse import urljoin
import urllib3

from .utils import print_atomic
from .config import Config

logger = logging.getLogger(__name__)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  # seen due to web module requests.get(verify=False)


class Web:
    """
    :return: self.get = [http status | error, shortened text, original html, redirects, x-frame-options, csp, form_names]
    """
    cache = {}
    store_html = True
    store_text = True
    headers = {}

    @classmethod
    def init(cls, store_text=True, store_html=True):
        cls.store_text = store_text
        cls.store_html = store_html
        if Config.get("user_agent", "FIELDS"):
            cls.headers = {"User-Agent": Config.get("user_agent", "FIELDS")}

    def __init__(self, url):
        if url in self.cache:
            self.get = self.cache[url]
            return
        redirects = []
        current_url = url
        while True:
            try:
                logger.debug(f"Scrapping connection to {current_url}")
                response = requests.get(current_url, timeout=Config.get("web_timeout", "FIELDS", get=int),
                                        headers=self.headers,
                                        allow_redirects=False, verify=False)
            except IOError as e:
                if isinstance(e, requests.exceptions.HTTPError):
                    s = 0
                elif isinstance(e, requests.exceptions.ConnectionError):
                    s = -1
                elif isinstance(e, requests.exceptions.RequestException):
                    s = -2
                elif isinstance(e, requests.exceptions.Timeout):
                    s = -3
                else:
                    s = e
                self.cache[url] = self.get = str(s), None, None, redirects, None, None, None
                print_atomic(f"Scrapping {url} failed: {e}")
                break
            if response.headers.get("Location") and len(redirects) < 10:
                current_url = urljoin(current_url, response.headers.get("Location"))
                redirects.append(current_url)
                continue
            else:
                response.encoding = response.apparent_encoding  # https://stackoverflow.com/a/52615216/2036148
                if self.store_text:
                    soup = BeautifulSoup(response.text, features="html.parser")
                    # check redirect
                    res = soup.select("meta[http-equiv=refresh i]")
                    if res:
                        wait, txt = res[0].attrs["content"].split(";")
                        m = re.search(r"http[^\"'\s]*", txt)
                        if m and len(redirects) < 10:
                            current_url = m.group(0)
                            redirects.append(current_url)
                            continue
                    # prepare content to be shortened
                    [s.extract() for s in
                     soup(["style", "script", "head"])]  # remove tags with low probability of content
                    text = re.sub(r'\n\s*\n', '\n', soup.text)  # reduce multiple new lines to singles
                    text = re.sub(r'[^\S\r\n][^\S\r\n]*[^\S\r\n]', ' ',
                                  text)  # reduce multiple spaces (not new lines) to singles

                    # if the form tag like <input> or <select> has no attribute "name", print out its tag name and value or options
                    def get_info(el):
                        """ This element has no "name" attribute """
                        n = el.name
                        r = [n]
                        if n == "select":
                            for opt in el.find_all("option"):
                                r.append(opt.attrs.get("value", "") + ":" + opt.text)
                        else:
                            r.append(el.attrs.get("value", ""))
                        return " ".join(r)

                    form_names = [s.attrs.get("name", get_info(s)) for s in soup(("input", "select", "textarea"))]
                else:
                    form_names = None
                    text = ""
                # for res in response.history[1:]:
                #     redirects += f"REDIRECT {res.status_code} → {res.url}\n" + text
                #     redirects.append(res.url)

                print_atomic(f"Scrapped {url} ({len(response.text)} bytes)")
                self.cache[
                    url] = self.get = response.status_code, text.strip(), response.text if self.store_html else None, \
                    redirects, \
                    response.headers.get('X-Frame-Options', None), \
                    response.headers.get('Content-Security-Policy', None), \
                    form_names
                break
                # if current_url == url:
                #     break
                # url = current_url

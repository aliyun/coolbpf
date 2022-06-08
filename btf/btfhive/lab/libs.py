# -*- coding: utf-8 -*-
# cython:language_level=3
"""
-------------------------------------------------
   File Name：     libs
   Description :
   Author :       liaozhaoyan
   date：          2022/1/14
-------------------------------------------------
   Change Activity:
                   2022/1/14:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'
import requests
from bs4 import BeautifulSoup

sKernel = "linux-image-unsigned-5.4.0-42-generic-dbgsym_5.4.0-42.46_arm64.ddeb"

ubuntuUrl = "http://ddebs.ubuntu.com/pool/main/l/linux/"

def filter(href):
    if href.startswith("linux-image") and "dbgsym" in href and href.endswith("arm64.ddeb"):
        print(href)

def start():
    html = requests.get(ubuntuUrl)
    bs = BeautifulSoup(html.text, 'lxml')
    table = bs.find('table')
    for a in table.find_all('a'):
        if a.has_attr("href"):
            href = a["href"]
            filter(href)

if __name__ == "__main__":
    start()
    pass

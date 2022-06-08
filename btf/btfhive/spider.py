# -*- coding: utf-8 -*-
# cython:language_level=2
"""
-------------------------------------------------
   File Name：     spider
   Description :
   Author :       liaozhaoyan
   date：          2021/12/1
-------------------------------------------------
   Change Activity:
                   2021/12/1:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import time

from bs4 import BeautifulSoup
import requests
from getVmlinux import CgetVmlinux
import traceback
from vers import versD


class Cspider(object):
    def __init__(self):
        self._oDict = {
            "alios": self.getAliosUrl,
            "alinux": self.getAlinux,
            "centos": self.getCentos,
            "ubuntu": self.getUbuntu,
            "anolis": self.getAlinux
        }
        self._vm = CgetVmlinux()

    def _proc(self, url, href, release, arch):
        self._vm.proc(url, href, release, arch)

    def getAliosUrl(self, url, rel, arch):
        html = requests.get(url)
        bs = BeautifulSoup(html.text, 'lxml')
        uls = bs.find('ul')
        for li in uls.find_all('li'):
            href = li.a['href']
            if href.endswith(".rpm"):
                # print("%s%s" % (url, href))
                dstUrl = "%s%s" % (url, href)
                self._proc(dstUrl, href, rel, arch)

    def getCentos(self, url, rel, arch):
        html = requests.get(url)
        bs = BeautifulSoup(html.text, 'lxml')
        table = bs.find('table', attrs={'id': "indexlist"})
        for td in table.find_all('td', attrs={'class': 'indexcolname'}):
            href = td.a['href']
            if href.startswith('kernel-debuginfo') and not href.startswith('kernel-debuginfo-common'):
                # print("%s%s" % (url, href))
                dstUrl = "%s%s" % (url, href)
                self._proc(dstUrl, href, rel, arch)

    def getAlinux(self, url, rel, arch):
        html = requests.get(url)
        bs = BeautifulSoup(html.text, 'lxml')
        links = bs.findAll('a')
        for link in links:
            href = link['href']
            if href.startswith('kernel-debuginfo') and not href.startswith('kernel-debuginfo-common'):
                dstUrl = "%s%s" % (url, href)
                self._proc(dstUrl, href, rel, arch)
        # table = bs.find('table', attrs={'class': "table"})
        # for td in table.find_all('td', attrs={'class': 'link'}):
        #     href = td.a['href']
        #     if href.startswith('kernel-debuginfo') and not href.startswith('kernel-debuginfo-common'):
        #         dstUrl = "%s%s" % (url, href)
        #         self._vm.proc(dstUrl, href, rel)

    def getUbuntu(self, url, rel, arch):
        html = requests.get(url)
        bs = BeautifulSoup(html.text, 'lxml')
        table = bs.find('table')
        endDeb = {'x86_64': "amd64.ddeb", 'aarch64': "arm64.ddeb"}
        ends = endDeb[arch]
        for a in table.find_all('a'):
            if a.has_attr("href"):
                href = a["href"]
                if href.startswith("linux-image") and "dbgsym" in href and href.endswith(ends):
                    # print("%s%s" % (url, href))
                    dstUrl = "%s%s" % (url, href)
                    self._proc(dstUrl, href, rel, arch)

    def work(self):
        for arch, relD in versD.items():
            for release in relD.keys():
                urls = relD[release]
                for url in urls:
                    try:
                        self._oDict[release](url, release, arch)
                    except Exception as e:
                        print(f"except msg: {e}")
                        traceback.print_exc()
                        continue

        #
        # for k in allD.keys():
        #     urls = allD[k]
        #     for url in urls:
        #         try:
        #             self._oDict[k](url, k)
        #         except Exception as e:
        #             print(f"except msg: {e}")
        #             traceback.print_exc()
        #             continue


if __name__ == "__main__":
    s = Cspider()
    # s.work()
    while True:
        s.work()
        time.sleep(10 * 60)
    pass

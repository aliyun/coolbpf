# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     udpHook
   Description :
   Author :       liaozhaoyan
   date：          2021/8/26
-------------------------------------------------
   Change Activity:
                   2021/8/26:
-------------------------------------------------
"""
from socket import *
import json


def udpPut(udpHost, dRecv):
    s = json.dumps(dRecv)
    udpSocket = socket(AF_INET, SOCK_DGRAM)
    sendAddress = (udpHost, 8080)
    try:
        udpSocket.sendto(s.encode(), sendAddress)
    except OSError as e:
        print(f"udp put failed, {e.strerror}")
    udpSocket.close()


if __name__ == "__main__":
    dst = "172.24.90.162"
    udpPut(dst, {"k": "v"})
    pass

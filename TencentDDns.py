#!/usr/bin/env python3
 
# -- coding:utf-8 --

"""
@author: XinRoom
"""

import requests, urllib
import json
import time
import os,sys
import random

import hashlib
import hmac
import base64

import socket
import re

def set_headers(ref):
    """针对获得公网api的headers"""
    headers = {
        "Dnt": "1",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.122 Safari/537.36",
        "Referer": ref
    }
    return headers

class DDNS:
    """腾讯云APIV2版本的ddns修改域名a记录解析工具 （请先随便添加相应的域名解析记录！）"""
    ## api doc https://cloud.tencent.com/document/api/302/4032
    def __init__(self, SecretId:str, SecretKey:str):
        self.SecretId = SecretId
        self.SecretKey = SecretKey
        self.headers = {"User-Agent" : "DDNS"}
        api_domain = "cns.api.qcloud.com"  # 解析记录相关api域
        self.api_url = "%s/v2/index.php" % (api_domain)

    @staticmethod
    def get_now_ip(domain:str):
        myaddr = socket.getaddrinfo(domain, 'http')
        return myaddr[0][4][0]

    @staticmethod
    def get_new_ip():
        """获得公网IP"""
        apis = [
            "https://ifconfig.co/ip",
            "https://www.taobao.com/help/getip.php",
            "https://ipinfo.io/ip",
            "http://ifconfig.me/ip",
            "http://ip.360.cn/IPShare/info",
            "https://myip.com.tw",
            "http://ip.xianhua.com.cn",
            "https://www.ip.cn"
        ]

        for api in apis:
            trueIp = None
            try:
                ip = requests.get(api,timeout=(3,5),headers=set_headers(api)).text
                trueIp =re.search(r'((25[0-5]|2[0-4]\d|[01]{0,1}\d{0,1}\d)\.){3}(25[0-5]|2[0-4]\d|[01]{0,1}\d{0,1}\d)',ip)
            except:
                continue
            if trueIp is not None:
                DDNS.__log("info", "get_new_ip succeed in %s" % api )
                break
        if trueIp is None:
            DDNS.__log("error", "get_new_ip error" )
            return ""
        return trueIp.group(0)
        

    def __get_record_ID(self, domain:str, subdomain:str):
        """获得解析列表"""

        req_param = {
            "Action" : "RecordList",
            # "offset" : "0",
            "length" : "99",
            "recordType" : "A",
            "domain" : domain,
            "subDomain" : subdomain
        }
        r = self.__send_data(req_param)
        if "records" not in r or len(r["records"]) == 0:
            return -1
        return r["records"][0]["id"]


    def update_record(self, domain:str, subdomain:str):
        """修改解析记录"""

        if "*" in subdomain:
            now_ip = self.get_now_ip( subdomain.replace('*','a') + "." + domain)        # 泛域名解析
        else:
            now_ip = self.get_now_ip( subdomain + "." + domain)
        new_ip = self.get_new_ip()

        if now_ip == new_ip:
            self.__log("info", "update_record %s.%s no renew ip" % (subdomain, domain) )
            return 0
        if new_ip == '':
            return 0


        r = self.__get_record_ID(domain, subdomain)
        if r == -1:
            return r

        req_param = {
            "Action" : "RecordModify",
            "domain" : domain,
            "recordId" : r,
            "subDomain" : subdomain,
            "recordType" : "A",
            "recordLine" : "默认",
            "value" : new_ip
        }
        self.__send_data(req_param)


    def __Signature(self, param:dict):
        """签名"""
        param = dict(sorted(param.items()))  # 按key升序排序
        srcStr = "GET" + self.api_url + "?"
        srcStr += urllib.parse.urlencode(param)
        srcStr = urllib.parse.unquote(srcStr)
        param["Signature"] = str(base64.b64encode(hmac.new(bytes(self.SecretKey, 'utf-8'),
                                    bytes(srcStr, 'utf-8'), hashlib.sha1).digest()),
                            'utf-8')
        return param


    @staticmethod
    def __log(tag:str, msg:str):
        """log"""
        print("%s [%s] %s" % (time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()), tag, msg) )


    def __send_data(self, data:dict):
        """发送数据"""

        # 公共参数
        basic_param = {
            "Nonce" : random.randint(1000,109990),
            #"Region" : "ap-guangzhou",
            "SecretId" : self.SecretId,
            # "SignatureMethod" : "HmacSHA1",
            "Timestamp" : str(round(time.time()))
        }
        param = self.__Signature(dict(**basic_param, **data))
        try:
            r = json.loads(requests.get(url="https://" + self.api_url,params=param,headers=self.headers,timeout=(3,5)).text)
            if ("code" in r) and (r["code"] == 0):
                self.__log("success", "__send_data success")
                if "data" in r:
                    return r["data"]
            else:
                self.__log("error", "__send_data error %s" % (r["codeDesc"]) )
                return -1
        except:
            self.__log("error", "__send_data requests error" )
            return -1

        return 1



if __name__ == "__main__":
    SecretId = "*********************"  # SecretId
    SecretKey = "******************" # SecretKey
    Domain = "*****" #域名

    try:
        d = DDNS(SecretId, SecretKey)
        d.update_record(Domain, "a")
        # d.update_record(Domain, "*.a")
    except Exception as msg:
        print("%s [%s] %s" % (time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()), 'error', 'run error:'+str(msg)) )
        sys.exit(1)
    sys.exit(0)

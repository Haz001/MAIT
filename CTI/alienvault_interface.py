import IndicatorTypes
from OTXv2 import OTXv2
import hashlib
import pprint
import time
import configparser
import py2neo
import json

class alienvault_intelligence:

    def __init__(self):
        config = configparser.ConfigParser()
        config.read('./config.txt')
        API_KEY = config['AlienVault']['API_KEY']
        OTX_SERVER = config['AlienVault']['OTX_SERVER']
        self.otx = OTXv2(API_KEY, server=OTX_SERVER)


    def query_hash(self, hash):
        result, alerts =  self.file( hash)
        return (result, alerts)


    def query_url(self, url):
        result, alerts =  self.url(url)
        if len(alerts) > 0:
            print('Identified as potentially malicious')
        else:
            print('Unknown or not identified as malicious')
        return (result, alerts)

    def query_domain(self, domain):
        result, alerts =  self.domain(domain)
        if len(alerts) > 0:
            print('Identified as potentially malicious')
        else:
            print('Unknown or not identified as malicious')
        return (result, alerts)

    def query_ip(self, ip, type):
        result, alerts =  self.ip(ip, type)
        if len(alerts) > 0:
            print('Identified as potentially malicious')
        else:
            print('Unknown or not identified as malicious')
        return (result, alerts)

    def insert_neo4j(self, neoGraph,savelst, hash256):
        neoSelector = py2neo. NodeMatcher(neoGraph)
        prevnode = ''
        if neoSelector.match("SAMPLE", sha1=hash256).first():
            print(f"Graph for sample {hash256} already exists in Neo4j instance!")
        else:
            node = py2neo.Node('SAMPLE', hash = hash256 )
            neoGraph.create(node)
            prevnode = node
        for i in savelst:    
            node1 = py2neo.Node(i[1], indicator = i[0], date = i[2] )
            neoGraph.create(node1)
            timerel = py2neo.Relationship(prevnode, 'next', node1)
            neoGraph.create(timerel)
            rootrel = py2neo.Relationship(node, i[1], node1)
            neoGraph.create(rootrel)
            prevnode = node1

    def get_hash_pulses(self, hash256):
        results, alerts = self.query_hash(hash256)
        return results['general']['pulse_info']['pulses']

    def get_url_pulses(self, mal_url):
        results, alerts = self.query_url(mal_url)
        return results['general']['pulse_info']['pulses']

    def get_domain_pulses(self, mal_domain): 
        results, alerts = self.query_domain(mal_domain)
        return results['general']['pulse_info']['pulses']

    def get_ip_pulses(self, mal_ip, type): 
        results, alerts = self.query_ip(mal_ip, type)
        return results['pulse_info']['pulses']

    def getValue(self, results, keys):
        if type(keys) is not list or len(keys) <= 0:
            return results
        if type(results) is not dict:
            return (
                self.getValue(results[0], keys)
                if type(results) is list and len(results) > 0
                else results
            )
        key = keys.pop(0)
        return self.getValue(results[key], keys) if key in results else None

    def hostname(self,hostname):
        alerts = []
        result = self.otx.get_indicator_details_by_section(IndicatorTypes.HOSTNAME, hostname, 'general')

        # Return nothing if it's in the whitelist
        validation = self.getValue(result, ['validation'])
        if not validation:
            if pulses := self.getValue(result, ['pulse_info', 'pulses']):
                alerts.extend(
                    'In pulse: ' + pulse['name']
                    for pulse in pulses
                    if 'name' in pulse
                )
        result = self.otx.get_indicator_details_by_section(IndicatorTypes.DOMAIN, hostname, 'general')
        # Return nothing if it's in the whitelist
        validation = self.getValue(result, ['validation'])
        if not validation:
            if pulses := self.getValue(result, ['pulse_info', 'pulses']):
                alerts.extend(
                    'In pulse: ' + pulse['name']
                    for pulse in pulses
                    if 'name' in pulse
                )
        return (result, alerts)

    def ip(self, ip, type):
        alerts = []
        if type == 'IPv4': 
            result = self.otx.get_indicator_details_by_section(IndicatorTypes.IPv4, ip, 'general')
        else: 
            result = self.otx.get_indicator_details_by_section(IndicatorTypes.IPv6, ip, 'general')
        # Return nothing if it's in the whitelist
        validation = self.getValue(result, ['validation'])
        if not validation:
            if pulses := self.getValue(result, ['pulse_info', 'pulses']):
                alerts.extend(
                    'In pulse: ' + pulse['name']
                    for pulse in pulses
                    if 'name' in pulse
                )
        return (result, alerts)

    def domain(self, domain):
        alerts = []
        result = self.otx.get_indicator_details_full(IndicatorTypes.DOMAIN, domain)

        google = self.getValue( result, ['url_list', 'url_list', 'result', 'safebrowsing'])
        if google and 'response_code' in str(google):
            alerts.append({'google_safebrowsing': 'malicious'})


        if clamav := self.getValue(
            result,
            ['url_list', 'url_list', 'result', 'multiav', 'matches', 'clamav'],
        ):
            alerts.append({'clamav': clamav})

        if avast := self.getValue(
            result,
            ['url_list', 'url_list', 'result', 'multiav', 'matches', 'avast'],
        ):
            alerts.append({'avast': avast})

        if has_analysis := self.getValue(
            result,
            ['url_list', 'url_list', 'result', 'urlworker', 'has_file_analysis'],
        ):
            file_hash = self.getValue( result,  ['url_list','url_list', 'result', 'urlworker', 'sha256'])
            if file_alerts := self.file(file_hash):
                alerts.extend(iter(file_alerts))
        return (result, alerts)

    def url(self, url):
        alerts = []
        result = self.otx.get_indicator_details_full(IndicatorTypes.URL, url)

        google = self.getValue( result, ['url_list', 'url_list', 'result', 'safebrowsing'])
        if google and 'response_code' in str(google):
            alerts.append({'google_safebrowsing': 'malicious'})


        if clamav := self.getValue(
            result,
            ['url_list', 'url_list', 'result', 'multiav', 'matches', 'clamav'],
        ):
            alerts.append({'clamav': clamav})

        if avast := self.getValue(
            result,
            ['url_list', 'url_list', 'result', 'multiav', 'matches', 'avast'],
        ):
            alerts.append({'avast': avast})

        if has_analysis := self.getValue(
            result,
            ['url_list', 'url_list', 'result', 'urlworker', 'has_file_analysis'],
        ):
            file_hash = self.getValue( result,  ['url_list','url_list', 'result', 'urlworker', 'sha256'])
            if file_alerts := self.file(file_hash):
                alerts.extend(iter(file_alerts))
        # Todo: Check file page

        return (result, alerts)

    def file(self, hash):
        alerts = []
        hash_type = IndicatorTypes.FILE_HASH_MD5
        if len(hash) == 64:
            hash_type = IndicatorTypes.FILE_HASH_SHA256
        if len(hash) == 40:
            hash_type = IndicatorTypes.FILE_HASH_SHA1

        result = self.otx.get_indicator_details_full(hash_type, hash)
        if avg := self.getValue(
            result,
            ['analysis', 'analysis', 'plugins', 'avg', 'results', 'detection'],
        ):
            alerts.append({'avg': avg})

        if clamav := self.getValue(
            result,
            ['analysis', 'analysis', 'plugins', 'clamav', 'results', 'detection'],
        ):
            alerts.append({'clamav': clamav})

        if avast := self.getValue(
            result,
            ['analysis', 'analysis', 'plugins', 'avast', 'results', 'detection'],
        ):
            alerts.append({'avast': avast})

        if microsoft := self.getValue(
            result,
            [
                'analysis',
                'analysis',
                'plugins',
                'cuckoo',
                'result',
                'virustotal',
                'scans',
                'Microsoft',
                'result',
            ],
        ):
            alerts.append({'microsoft': microsoft})

        if symantec := self.getValue(
            result,
            [
                'analysis',
                'analysis',
                'plugins',
                'cuckoo',
                'result',
                'virustotal',
                'scans',
                'Symantec',
                'result',
            ],
        ):
            alerts.append({'symantec': symantec})

        if kaspersky := self.getValue(
            result,
            [
                'analysis',
                'analysis',
                'plugins',
                'cuckoo',
                'result',
                'virustotal',
                'scans',
                'Kaspersky',
                'result',
            ],
        ):
            alerts.append({'kaspersky': kaspersky})

        suricata = self.getValue( result, ['analysis','analysis','plugins','cuckoo','result','suricata','rules','name'])
        if suricata and 'trojan' in str(suricata).lower():
            alerts.append({'suricata': suricata})

        return (result, alerts)

    def get_related_pulse_report(self, indicator, type): 
        if type == 'URL': 
            pulse_report = self.get_url_pulses(indicator)
        elif type == 'domain': 
            pulse_report = self.get_domain_pulses(indicator)
        elif type == 'IPv4': 
            pulse_report = self.get_ip_pulses(indicator, 'IPv4')
        elif type == 'IPv6': 
            pulse_report = self.get_ip_pulses(indicator, 'IPv6')
        elif type == 'FileHash-SHA256': 
            pulse_report = self.get_hash_pulses(indicator)
        else: 
            return "Invalid indicator type"

        return pulse_report

    def get_related_pulse_indicators(self, indicator, type): 
        indicators = []
        pulse_report = self.get_related_pulse_report(indicator, type)

        for i in pulse_report: 
            pulse_indicators = self.otx.get_pulse_indicators(i['id'],limit = 300)

            indicators.extend(j for j in pulse_indicators if j['type'] == type)
        indicators.sort(key = lambda x:x['created'])
        return indicators
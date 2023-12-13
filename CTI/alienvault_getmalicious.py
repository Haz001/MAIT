#!/usr/bin/env python

import IndicatorTypes

# Get a nested key from a dict, without having to do loads of ifs
def get_value(results, keys):
    if type(keys) is not list or len(keys) <= 0:
        return results
    if type(results) is not dict:
        return (
            get_value(results[0], keys)
            if type(results) is list and len(results) > 0
            else results
        )
    key = keys.pop(0)
    return get_value(results[key], keys) if key in results else None

def hostname(otx, hostname):
    alerts = []
    result = otx.get_indicator_details_by_section(IndicatorTypes.HOSTNAME, hostname, 'general')

    # Return nothing if it's in the whitelist
    validation = get_value(result, ['validation'])
    if not validation:
        if pulses := get_value(result, ['pulse_info', 'pulses']):
            alerts.extend(
                'In pulse: ' + pulse['name']
                for pulse in pulses
                if 'name' in pulse
            )
    result = otx.get_indicator_details_by_section(IndicatorTypes.DOMAIN, hostname, 'general')
    # Return nothing if it's in the whitelist
    validation = get_value(result, ['validation'])
    if not validation:
        if pulses := get_value(result, ['pulse_info', 'pulses']):
            alerts.extend(
                'In pulse: ' + pulse['name']
                for pulse in pulses
                if 'name' in pulse
            )
    return (result, alerts)


def ip(otx, ip):
    alerts = []
    result = otx.get_indicator_details_by_section(IndicatorTypes.IPv4, ip, 'general')
    # Return nothing if it's in the whitelist
    validation = get_value(result, ['validation'])
    if not validation:
        if pulses := get_value(result, ['pulse_info', 'pulses']):
            alerts.extend(
                'In pulse: ' + pulse['name']
                for pulse in pulses
                if 'name' in pulse
            )
    return (result, alerts)



def url(otx, url):
    alerts = []
    result = otx.get_indicator_details_full(IndicatorTypes.URL, url)

    google = get_value( result, ['url_list', 'url_list', 'result', 'safebrowsing'])
    if google and 'response_code' in str(google):
        alerts.append({'google_safebrowsing': 'malicious'})


    if clamav := get_value(
        result,
        ['url_list', 'url_list', 'result', 'multiav', 'matches', 'clamav'],
    ):
        alerts.append({'clamav': clamav})

    if avast := get_value(
        result,
        ['url_list', 'url_list', 'result', 'multiav', 'matches', 'avast'],
    ):
        alerts.append({'avast': avast})

    if has_analysis := get_value(
        result,
        ['url_list', 'url_list', 'result', 'urlworker', 'has_file_analysis'],
    ):
        file_hash = get_value( result,  ['url_list','url_list', 'result', 'urlworker', 'sha256'])
        if file_alerts := file(otx, file_hash):
            alerts.extend(iter(file_alerts))
    # Todo: Check file page

    return (result, alerts)

def file(otx, hash):
    alerts = []
    hash_type = IndicatorTypes.FILE_HASH_MD5
    if len(hash) == 64:
        hash_type = IndicatorTypes.FILE_HASH_SHA256
    if len(hash) == 40:
        hash_type = IndicatorTypes.FILE_HASH_SHA1

    result = otx.get_indicator_details_full(hash_type, hash)
    if avg := get_value(
        result,
        ['analysis', 'analysis', 'plugins', 'avg', 'results', 'detection'],
    ):
        alerts.append({'avg': avg})

    if clamav := get_value(
        result,
        ['analysis', 'analysis', 'plugins', 'clamav', 'results', 'detection'],
    ):
        alerts.append({'clamav': clamav})

    if avast := get_value(
        result,
        ['analysis', 'analysis', 'plugins', 'avast', 'results', 'detection'],
    ):
        alerts.append({'avast': avast})

    if microsoft := get_value(
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

    if symantec := get_value(
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

    if kaspersky := get_value(
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

    suricata = get_value( result, ['analysis','analysis','plugins','cuckoo','result','suricata','rules','name'])
    if suricata and 'trojan' in str(suricata).lower():
        alerts.append({'suricata': suricata})

    return (result, alerts)

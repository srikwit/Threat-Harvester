import json
import requests
import urllib3
import time
import datetime

from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
urllib3.disable_warnings()

headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.2; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.0.1667.0 Safari/537.36'}

protect = True
EndUserMessage = True
NetworkAdminMessage = False

def cymon_ip_verdict(ip):
    response = requests.get("https://cymon.io/api/nexus/v1/ip/"+ip+"/",headers=headers,verify=False)
    result = {}
    if response.status_code == 200:
        result = response.json()
        result['sources'] = ';'.join(result['sources'])
    result['status'] = response.status_code
    result['date'] = datetime.datetime.today().strftime('%d-%m-%Y')
    result['inspect'] = ip
    return result

def cymon_domain_verdict(domain):
    response = requests.get("https://cymon.io/api/nexus/v1/domain/"+domain+"/",headers=headers,verify=False)
    result = {}
    if response.status_code == 200:
        result = response.json()
        result['sources'] = ';'.join(result['sources'])
    result['status'] = response.status_code
    result['date'] = datetime.datetime.today().strftime('%d-%m-%Y')
    result['inspect'] = domain
    return result

def make_mail_text(aggregated_verdict,blockable_element):
    
    blockable_elements = set()
    sources = set()    
    for data in aggregated_verdict:
        if data['status'] == 200:
            blockable_elements.add(data['inspect'])
            sources.update(data['sources'].split(";"))
        else:
            
            break    
    if len(sources) > 0:
        print("Dear Team,\n")
        print("Kindly block the following "+blockable_element+"s as we have observed traffic towards it.")
        for element in blockable_elements:
            print(element)
        print()
        print("We are relying on the following sources for the same.")
        for source in sources:
            print(source)
    return

data_sources = {"IP":"ip_list.txt","Domain":"domain_list.txt"}

for i in data_sources:
    aggregated_verdict = []
    try:
        with open(data_sources[i],"r") as ip_file:
            unsanitized_elements = ip_file.readlines()
            for element in unsanitized_elements:
                aggregated_verdict.append(cymon_ip_verdict(element.rstrip("\r\n")))
            sorted(aggregated_verdict,key=lambda verdict: verdict['status'])
            make_mail_text(aggregated_verdict,i)
            print()
    except Exception as e:
        print("Could not query for "+i+"s as the source data file "+data_sources[i]+" was not found")

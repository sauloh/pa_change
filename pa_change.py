#!/bin/sh

"""
    Script to rename Palo Alto Firewall objects and Rules using the PAN API
    by sauloh.
"""

import requests
import xmltodict
import getpass
from re import findall

requests.packages.urllib3.disable_warnings()

def get_token(base_url):
    """
        Generate a token
    """
    print("[+] Getting Token\n")

    r = requests.get(base_url, verify=False)

    response_dict = xmltodict.parse(r.text)

    token = response_dict['response']['result']['key']

    return token

def rename_rules(IP, token):
    """
        Retrieve and Rename Palo Alto Rules
    """
    xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security"

    print("[+] Retriving Rules")
    r = requests.get("https://{0}/api/?type=config&action=show&key={1}&xpath={2}".format(IP, token, xpath),verify=False)
    
    rules = findall("""<entry name="(.*)">""", r.text)

    for rule in rules:
        new_name = "JB_"+rule # New rule name

        rename_url = "https://{0}/api/?type=config&action=rename&key={1}&xpath={2}/rules/entry[@name='{3}']&newname={4}".format(IP, token,xpath, rule, new_name) # URL to change name

        print("\t[+] Renaming Rule: {0} to {1}".format(rule, new_name))

        r = requests.get(rename_url, verify=False) # Do API request

        if "command succeeded" in r.text: # Print 
            print("\t\t[OK] Rule: {0} renamed to {1}\n".format(rule, new_name))
        else:
            print("\t\tFailed changing name")
            print("\t\tERROR: ", r.text," <<<<\n")

def rename_address(IP, token):
    """
        Retrieve and Rename Addresses
    """    

    xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address"

    print("[+] Retriving Address")
    r = requests.get("https://{0}/api/?type=config&action=show&key={1}&xpath={2}".format(ip, token, xpath),verify=False)

    addresses = findall("""<entry name="(.*)">""", r.text)

    for address in addresses:
        new_name = "JB_"+address # new address
        
        rename_url = "https://{0}/api/?type=config&action=rename&key={1}&xpath={2}/entry[@name='{3}']&newname={4}".format(ip, token,xpath, address, new_name) # URL to change name

        print("\t[+] Renaming Address: {0} to {1}".format(address, new_name))

        r = requests.get(rename_url, verify=False) # Do API request

        if "command succeeded" in r.text: # Print 
            print("\t\t[OK] Address: {0} renamed to {1}\n".format(address, new_name))
        else:
            print("\t\tFailed changing name")
            print("\t\tERROR: ", r.text," <<<<\n")

def rename_group_address(IP, token):
    """
        Retrieve and Rename Group-Address
    """

    xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address-group"

    print("[+] Retriving Group Address")
    r = requests.get("https://{0}/api/?type=config&action=show&key={1}&xpath={2}".format(ip, token, xpath),verify=False)
    
    group_addresses = findall("""<entry name="(.*)">""", r.text)

    for group in group_addresses:
        new_name = "JB_"+group # new group-address
        
        rename_url = "https://{0}/api/?type=config&action=rename&key={1}&xpath={2}/entry[@name='{3}']&newname={4}".format(ip, token,xpath, group, new_name) # URL to change name

        print("\t[+] Renaming Group Address: {0} to {1}".format(group, new_name))

        r = requests.get(rename_url, verify=False) # Do API request

        if "command succeeded" in r.text: # Print 
            print("\t\t[OK] Group Address: {0} renamed to {1}".format(group, new_name))
        else:
            print("\t\tFailed changing name")
            print("\t\t>>>>", r.text," <<<<\n")

def rename_services(IP, token):
    """
        Retrieve and Rename Services
    """

    xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/service"

    print("[+] Retriving Services")
    r = requests.get("https://{0}/api/?type=config&action=show&key={1}&xpath={2}".format(ip, token, xpath),verify=False)
    
    services = findall("""<entry name="(.*)">""", r.text)

    for service in services:
        new_name = "JB_"+service # new service name
    
        rename_url = "https://{0}/api/?type=config&action=rename&key={1}&xpath={2}/entry[@name='{3}']&newname={4}".format(ip, token, xpath, service, new_name) # URL to change name

        print("\t[+] Renaming Service: {0} to {1}".format(service, new_name))

        r = requests.get(rename_url, verify=False) # Do API request

        if "command succeeded" in r.text: # Print 
            print("\t\t[OK] Service: {0} renamed to {1}\n".format(service, new_name))
        else:
            print("\t\tFailed changing name")
            print("\t\t>>>>", r.text," <<<<\n")
        
def rename_group_services(ip, token):
    """
        Retrieve and Rename Group-Services
    """

    xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/service-group"

    print("[+] Retriving Group Services")
    r = requests.get("https://{0}/api/?type=config&action=show&key={1}&xpath={2}".format(ip, token, xpath),verify=False)
    
    group_services = findall("""<entry name="(.*)">""", r.text)

    for group in group_services:
        new_name = "JB_"+group # new service name
    
        rename_url = "https://{0}/api/?type=config&action=rename&key={1}&xpath={2}/entry[@name='{3}']&newname={4}".format(ip, token,xpath, group, new_name) # URL to change name

        print("\t[+] Renaming Group Service: {0} to {1}".format(group, new_name))

        r = requests.get(rename_url, verify=False) # Do API request

        if "command succeeded" in r.text: # Print 
            print("\t\t[OK] Group Service: {0} renamed to {1}\n".format(group, new_name))
        else:
            print("\t\tFailed changing name")
            print("\t\t>>>>", r.text," <<<<")

def read_credentials():
    """
        Read credentials and return them.
    """
    host = input("IP Address: ")
    username = input("Username: ")
    passwd = getpass.getpass("Password: ")
    
    return host, username, passwd

if __name__ == "__main__":
    # Get Variables - IP - Username and Password
    ip, username, passwd = read_credentials() 

    # Build URL to get token
    get_token_url = "https://{0}/api/?type=keygen&user={1}&password={2}".format(ip, username, passwd)

    # Get Token
    token = get_token(get_token_url)

    rename_rules(ip, token) 
    rename_address(ip, token)
    rename_group_address(ip, token)
    rename_services(ip, token)
    rename_group_services(ip, token)

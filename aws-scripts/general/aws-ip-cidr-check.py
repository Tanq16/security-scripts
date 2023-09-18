# Check AWS IP
# ------------
# This script takes in IP addresses of CIDR ranges
# as either arguments while calling or as new lines
# when no argument is given. It will accept CIDR
# values or IP addresses till it encounters "done"
# as an entry. The results are Amazon services that
# the address/range belongs to as a list and the
# associated region for each, grouped by region.

import requests
import sys
import ipaddress

def is_ip_or_cidr(input_str):
    try:
        retval = ipaddress.ip_address(input_str)
        return 'ip_address', retval.version, retval
    except ValueError:
        try:
            retval = ipaddress.ip_network(input_str)
            return 'cidr_range', retval.version, retval
        except ValueError:
            return 'invalid_input', 0, None

def check_asset(inp, ip_ranges):
    inp_type, version, val = is_ip_or_cidr(inp)
    combos = []
    if inp_type == 'invalid_input' or version == 0:
        pass
    if inp_type == 'cidr_range':
        prefix_list = ip_ranges['prefixes'] if version == 4 else ip_ranges['ipv6_prefixes']
        prefix_to_check = 'ip_prefix' if version == 4 else 'ipv6_prefix'
        for cidr in prefix_list:
            if val.subnet_of(ipaddress.ip_network(cidr[prefix_to_check])):
                combos.append((cidr['service'], cidr['region']))
    if inp_type == 'ip_address':
        prefix_list = ip_ranges['prefixes'] if version == 4 else ip_ranges['ipv6_prefixes']
        prefix_to_check = 'ip_prefix' if version == 4 else 'ipv6_prefix'
        for cidr in prefix_list:
            if val in ipaddress.ip_network(cidr[prefix_to_check]):
                combos.append((cidr['service'], cidr['region']))
    return combos

def main(data):
    ip_ranges = requests.get('https://ip-ranges.amazonaws.com/ip-ranges.json', headers={'Accept': 'application/json'}).json()
    for inp in data:
        combos = check_asset(inp, ip_ranges)
        if len(combos) == 0:
            print(inp + ' not found in AWS ranges.')
        else:
            print('========\n' + inp)
            result = {}
            for service, region in combos:
                if region in result:
                    result[region].append(service)
                else:
                    result[region] = [service]
            for region, services in result.items():
                print(f'{services} in {region}')
            
if __name__ == '__main__':
    input_data = []
    if len(sys.argv) > 1:
        input_data = sys.argv[1:]
    else:
        while True:
            inp = input()
            if inp == "done":
                break
            input_data.append(inp)
    main(input_data)

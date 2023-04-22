# Burp Header Extracter
# ---------------------
# This script takes in the XML dump of the exported requests
# from Burpsuite. Using that, it cycles through them to find
# all headers and their unique values. The resultant data is
# stored in a JSON file for easy querying with jq.

import re
import sys
import json
import base64
import xmltodict

def main(filename):    
    with open(filename) as f:
        xml_string = f.read()

    json_string = xmltodict.parse(xml_string)
    burpitems = json_string['items']['item']
    headers_dict = {}

    for i in burpitems:
        request = base64.b64decode(i['request']['#text']).decode('utf-8')
        headers = re.findall(r'(.*?):\s(.*?)\n', request)
        for header in headers:
            header_name = header[0]
            header_value = header[1]
            if header_name not in headers_dict:
                headers_dict[header_name] = set()
            headers_dict[header_name].add(header_value)

    for header_name, header_values in headers_dict.items():
        headers_dict[header_name] = list(header_values)

    with open('headers_dump.json', 'w') as f:
        f.write(json.dumps(headers_dict))

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: python3 burp-header-extractor.py <BURP_EXPORT_XML>')
        sys.exit(1)
    filename = sys.argv[1]
    main(filename)

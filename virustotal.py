import json
import hashlib
import argparse
from virus_total_apis import PublicApi as VirusTotalPublicApi

ap = argparse.ArgumentParser()
ap.add_argument("-hh", "--hash", required=True,
	help="the hash to be search")
args = vars(ap.parse_args())

API_KEY = 'd5b33fd32a1bd5d2ee706f24a96599579b317dd6251d3a6e550d242d14c57854'

FILE_HASH = args["hash"]


vt = VirusTotalPublicApi(API_KEY)

response = vt.get_file_report(FILE_HASH)
# print(json.dumps(response, sort_keys=True, indent=4))
with open('data.json', 'w') as outfile:
    json.dump(response, outfile, sort_keys=True, indent=4)

def pp_json(json_thing, sort=True, indents=4):
    if type(json_thing) is str:
        print(json.dumps(json.loads(json_thing), sort_keys=sort, indent=indents))
    else:
        print(json.dumps(json_thing, sort_keys=sort, indent=indents))
        return None

# open file
with open('data.json', 'r') as json_data:
    f = json.load(json_data)

    # search in JSON object @keys results scans
    output = []
    for k, v in f["results"]["scans"].items():
        for x, i in v.items():
            if i == True:
                detected_tup = (k, v)
                output.append(detected_tup)
    pretty_json = pp_json(output)
    print(pretty_json)
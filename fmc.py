import requests
from requests.auth import HTTPBasicAuth
import json
import csv
import re
from time import sleep
import os.path
import getpass


def basic_auth():
    url = f'https://{fmc_address}/api/fmc_platform/v1/auth/generatetoken'
    response = requests.request("POST", url, auth=HTTPBasicAuth(
        f'{username}', f'{password}'), data={}, verify=False)
    print(response.request.url)
    print(response.request.headers)
    print(response.request.body)
    print(response.status_code)
    print(response.headers)
    domainUUID = response.headers['DOMAIN_UUID']
    XAuthAccessToken = response.headers['X-auth-access-token']
    return domainUUID, XAuthAccessToken


def create_security_zones():
    domainUUID, XAuthAccessToken = basic_auth()
    with open('seczones.csv') as csv_file:
        csv_reader = csv.DictReader(csv_file, delimiter=',')
        line_count = 0
        for row in csv_reader:
            firewall = row['fwName']
            print(f'Firewall is mapped too: {firewall}')
            seczone = row['securityzoneName']
            print(f'Security Zone is mapped too: {seczone}')
            mode = row['interfaceMode']
            print(f'Mode is mapped too: {mode}')

            dataDict = {
                "type": "SecurityZone",
                "name": seczone,
                "interfaceMode": mode,
                "interfaces": []
            }

            jsonData = json.dumps(dataDict)

            url = f'https://{fmc_address}/api/fmc_config/v1/domain/{domainUUID}/object/securityzones'

            newHeaders = {'Content-type': 'application/json',
                          'Accept': 'text/plain', 'X-auth-access-token': XAuthAccessToken}

            response = requests.post(
                url, headers=newHeaders, data=jsonData, verify=False)

            print(response.request.url)
            print(response.request.headers)
            print(response.request.body)
            print(response.status_code)
            print(response.headers)


def create_access_policy():
    domainUUID, XAuthAccessToken = basic_auth()
    with open('acspol.csv') as csv_file:
        csv_reader = csv.DictReader(csv_file, delimiter=',')
        line_count = 0
        for row in csv_reader:
            firewall = row['fwName']
            print(f'Firewall is mapped too: {firewall}')

            dataDict = {
                "type": "AccessPolicy",
                "name": firewall + "-AccessPolicy",
                "defaultAction": {
                    "action": "BLOCK"
                }
            }

            jsonData = json.dumps(dataDict)

            url = f'https://{fmc_address}/api/fmc_config/v1/domain/{domainUUID}/policy/accesspolicies'

            newHeaders = {'Content-type': 'application/json',
                          'Accept': 'text/plain', 'X-auth-access-token': XAuthAccessToken}

            response = requests.post(
                url, headers=newHeaders, data=jsonData, verify=False)

            print(response.request.url)
            print(response.request.headers)
            print(response.request.body)
            print(response.status_code)
            print(response.headers)


def create_network_objects():
    domainUUID, XAuthAccessToken = basic_auth()
    with open('network_objects.csv') as csv_file:
        csv_reader = csv.DictReader(csv_file, delimiter=',')
        line_count = 0
        for row in csv_reader:
            objectType = row['objectType']
            print(f'objectType is mapped too: {objectType}')

            objectName = row['objectName']
            print(f'objectName is mapped too: {objectName}')

            objectValue = row['objectValue']
            print(f'objectValue is mapped too: {objectValue}')

            objectDescription = row['objectDescription']
            print(f'objectDescription is mapped too: {objectDescription}')

            dataDict = {
                "name": objectName,
                "type": objectType,
                "value": objectValue,
                "description": objectDescription
            }

            jsonData = json.dumps(dataDict)

            if objectType == "Network":

                url = f'https://{fmc_address}/api/fmc_config/v1/domain/{domainUUID}/object/networks'

                newHeaders = {'Content-type': 'application/json',
                              'Accept': 'text/plain', 'X-auth-access-token': XAuthAccessToken}

                response = requests.post(
                    url, headers=newHeaders, data=jsonData, verify=False)
                sleep(2)

                print(response.request.url)
                print(response.request.headers)
                print(response.request.body)
                print(response.status_code)
                print(response.content)

                url = f'https://{fmc_address}/api/fmc_config/v1/domain/{domainUUID}/object/networks?filter=nameOrValue%3A{objectName}'

                newHeaders = {'Content-type': 'application/json',
                              'Accept': 'text/plain', 'X-auth-access-token': XAuthAccessToken}

                response = requests.get(url, headers=newHeaders, verify=False)

                print(response.request.url)
                print(response.request.headers)
                print(response.request.body)
                print(response.status_code)
                print(response.content)

                response_json = response.json()
                print(response_json)

                networkUUID = response_json["items"][0]["id"]
                print(f'networkUUID is mapped too {networkUUID}')

                objectGroup = row['objectGroup']
                print(f'objectGroup is mapped too: {objectGroup}')

                firewallName = row['firewallName']
                print(f'firewallName is mapped too: {firewallName}')

                if not os.path.exists(firewallName + "-" + objectGroup + "_objectgroup.json"):

                    filename = firewallName + "-" + objectGroup + "_objectgroup.json"

                    with open(filename, mode='w') as f:
                        start = {"name": f"{firewallName}" + "-" +
                                 f"{objectGroup}", "objects": [], "type": "NetworkGroup"}
                        json.dump(start, f)

                    with open(filename, "r") as file:
                        data = json.load(file)
                        temp = data["objects"]
                        entry = {"type": f"{objectType}",
                                 "name": f"{objectName}", "id": f"{networkUUID}"}
                        print(entry)
                        temp.append(entry)

                        with open(filename, "w") as file:
                            json.dump(data, file)

                else:

                    filename = firewallName + "-" + objectGroup + "_objectgroup.json"

                    with open(filename, "r") as file:
                        data = json.load(file)
                        temp = data["objects"]
                        entry = {"type": f"{objectType}",
                                 "name": f"{objectName}", "id": f"{networkUUID}"}
                        print(entry)
                        temp.append(entry)

                        with open(filename, "w") as file:
                            json.dump(data, file)

            elif objectType == "Host":

                url = f'https://{fmc_address}/api/fmc_config/v1/domain/{domainUUID}/object/hosts'

                newHeaders = {'Content-type': 'application/json',
                              'Accept': 'text/plain', 'X-auth-access-token': XAuthAccessToken}

                response = requests.post(
                    url, headers=newHeaders, data=jsonData, verify=False)
                sleep(2)

                print(response.request.url)
                print(response.request.headers)
                print(response.request.body)
                print(response.status_code)
                print(response.content)

                url = f'https://{fmc_address}/api/fmc_config/v1/domain/{domainUUID}/object/hosts?filter=nameOrValue%3A{objectName}'

                newHeaders = {'Content-type': 'application/json',
                              'Accept': 'text/plain', 'X-auth-access-token': XAuthAccessToken}

                response = requests.get(url, headers=newHeaders, verify=False)

                print(response.request.url)
                print(response.request.headers)
                print(response.request.body)
                print(response.status_code)
                print(response.content)

                response_json = response.json()
                print(response_json)

                hostUUID = response_json["items"][0]["id"]
                print(f'hostUUID is mapped too {hostUUID}')

                objectGroup = row['objectGroup']
                print(f'objectGroup is mapped too: {objectGroup}')

                firewallName = row['firewallName']
                print(f'firewallName is mapped too: {firewallName}')

                if not os.path.exists(firewallName + "-" + objectGroup + "_objectgroup.json"):

                    filename = firewallName + "-" + objectGroup + "_objectgroup.json"

                    with open(filename, mode='w') as f:
                        start = {"name": f"{objectGroup}",
                                 "objects": [], "type": "NetworkGroup"}
                        json.dump(start, f)

                    with open(filename, "r") as file:
                        data = json.load(file)
                        temp = data["objects"]
                        entry = {"type": f"{objectType}",
                                 "name": f"{objectName}", "id": f"{hostUUID}"}
                        print(entry)
                        temp.append(entry)

                        with open(filename, "w") as file:
                            json.dump(data, file)
                else:

                    filename = firewallName + "-" + objectGroup + "_objectgroup.json"

                    with open(filename, "r") as file:
                        data = json.load(file)
                        temp = data["objects"]
                        entry = {"type": f"{objectType}",
                                 "name": f"{objectName}", "id": f"{hostUUID}"}
                        print(entry)
                        temp.append(entry)

                        with open(filename, "w") as file:
                            json.dump(data, file)

            else:
                print(
                    f'The object type, {objectType}, does not match the script logic. Please double check your inputs.')

    with open('network_objects.csv') as csv_file:

        csv_reader = csv.DictReader(csv_file, delimiter=',')
        line_count = 0

        for row in csv_reader:

            objectGroup = row['objectGroup']
            print(f'objectGroup is mapped too: {objectGroup}')

            firewallName = row['firewallName']
            print(f'firewallName is mapped too: {firewallName}')

            filename = firewallName + "-" + objectGroup + "_objectgroup.json"

            url = f'https://{fmc_address}/api/fmc_config/v1/domain/{domainUUID}/object/networkgroups?bulk=true'

            newHeaders = {'Content-type': 'application/json',
                          'Accept': 'text/plain', 'X-auth-access-token': XAuthAccessToken}

            response = requests.post(url, data=open(
                filename, 'rb'), headers=newHeaders, verify=False)

            print(response.request.url)
            print(response.request.headers)
            print(response.request.body)
            print(response.status_code)
            print(response.content)


def create_port_objects():

    domainUUID, XAuthAccessToken = basic_auth()

    with open('port_objects.csv') as csv_file:
        csv_reader = csv.DictReader(csv_file, delimiter=',')
        line_count = 0
        for row in csv_reader:

            firewallName = row['firewallName']
            print(f'firewallName is mapped too: {firewallName}')

            objectGroup = row['objectGroup']
            print(f'objectGroup is mapped too: {objectGroup}')

            objectName = row['objectName']
            print(f'objectName is mapped too: {objectName}')

            protocol = row['protocol']
            print(f'protocol is mapped too: {protocol}')

            port = row['port']
            print(f'port is mapped too: {port}')

            dataDict = {
                "name": objectName,
                "protocol": protocol,
                "port": port,
                "type": "ProtocolPortObject"
            }

            jsonData = json.dumps(dataDict)

            url = f'https://{fmc_address}/api/fmc_config/v1/domain/{domainUUID}/object/protocolportobjects'

            newHeaders = {'Content-type': 'application/json',
                          'Accept': 'text/plain', 'X-auth-access-token': XAuthAccessToken}

            response = requests.post(
                url, headers=newHeaders, data=jsonData, verify=False)
            sleep(2)

            print(response.request.url)
            print(response.request.headers)
            print(response.request.body)
            print(response.status_code)
            print(response.content)

            url = f'https://{fmc_address}/api/fmc_config/v1/domain/{domainUUID}/object/protocolportobjects?filter=nameOrValue%3A{objectName}'

            newHeaders = {'Content-type': 'application/json',
                          'Accept': 'text/plain', 'X-auth-access-token': XAuthAccessToken}

            response = requests.get(url, headers=newHeaders, verify=False)

            print(response.request.url)
            print(response.request.headers)
            print(response.request.body)
            print(response.status_code)
            print(response.content)

            response_json = response.json()
            items_list = response_json["items"]
            item_count = 0
            for item in items_list:
                if (items_list[item_count]['name'] == objectName):
                    print(item)
                    print("-------------------")
                    portUUID = items_list[item_count]['id']
                    print(f'portUUID is mapped too {portUUID}')
                else:
                    print(
                        f'Could not locate a protocol port object called, {objectName}')
                item_count += 1

            if not os.path.exists(firewallName + "-" + objectGroup + "_objectgroup.json"):

                filename = firewallName + "-" + objectGroup + "_objectgroup.json"

                with open(filename, mode='w') as f:
                    start = {"name": f"{objectGroup}",
                             "objects": [], "type": "PortObjectGroup"}
                    json.dump(start, f)

                with open(filename, "r") as file:
                    data = json.load(file)
                    temp = data["objects"]
                    entry = {"id": f"{portUUID}", "type": "ProtocolPortObject"}
                    print(entry)
                    temp.append(entry)

                    with open(filename, "w") as file:
                        json.dump(data, file)

            else:

                filename = firewallName + "-" + objectGroup + "_objectgroup.json"

                with open(filename, "r") as file:
                    data = json.load(file)
                    temp = data["objects"]
                    entry = {"id": f"{portUUID}", "type": "ProtocolPortObject"}
                    print(entry)
                    temp.append(entry)

                    with open(filename, "w") as file:
                        json.dump(data, file)

    with open('port_objects.csv') as csv_file:

        csv_reader = csv.DictReader(csv_file, delimiter=',')
        line_count = 0

        for row in csv_reader:

            objectGroup = row['objectGroup']
            print(f'objectGroup is mapped too: {objectGroup}')

            firewallName = row['firewallName']
            print(f'firewallName is mapped too: {firewallName}')

            filename = firewallName + "-" + objectGroup + "_objectgroup.json"

            url = f'https://{fmc_address}/api/fmc_config/v1/domain/{domainUUID}/object/portobjectgroups?bulk=true'

            newHeaders = {'Content-type': 'application/json',
                          'Accept': 'text/plain', 'X-auth-access-token': XAuthAccessToken}

            response = requests.post(url, data=open(
                filename, 'rb'), headers=newHeaders, verify=False)

            print(response.request.url)
            print(response.request.headers)
            print(response.request.body)
            print(response.status_code)
            print(response.content)


def create_security_rules():
    domainUUID, XAuthAccessToken = basic_auth()
    with open('secrules.csv') as csv_file:
        csv_reader = csv.DictReader(csv_file, delimiter=',')
        line_count = 0
        for row in csv_reader:
            accesspolicy = row['accesspolicyName']
            print(f'Access Policy is mapped too: {accesspolicy}')

            url = f'https://{fmc_address}/api/fmc_config/v1/domain/{domainUUID}/policy/accesspolicies?name={accesspolicy}'

            newHeaders = {'Content-type': 'application/json',
                          'Accept': 'text/plain', 'X-auth-access-token': XAuthAccessToken}

            response = requests.get(url, headers=newHeaders, verify=False)

            print(response.request.url)
            print(response.request.headers)
            print(response.status_code)
            print(response.content)

            response_json = response.json()

            items_list = response_json["items"]
            item_count = 0
            for item in items_list:
                if (items_list[item_count]['name'] == accesspolicy):
                    print(item)
                    print("-------------------")
                    containerUUID = items_list[item_count]['id']
                    print(
                        f'Access Policy, {accesspolicy}, UUID is {containerUUID}')

                item_count += 1

            category = row['categoryName']
            print(f'Category is mapped too: {category}')

            dataDict = {
                "type": "Category",
                "name": category
            }

            jsonData = json.dumps(dataDict)

            url = f'https://{fmc_address}/api/fmc_config/v1/domain/{domainUUID}/policy/accesspolicies/{containerUUID}/categories'

            newHeaders = {'Content-type': 'application/json',
                          'Accept': 'text/plain', 'X-auth-access-token': XAuthAccessToken}

            response = requests.post(
                url, headers=newHeaders, data=jsonData, verify=False)

            print(response.request.url)
            print(response.request.headers)
            print(response.request.body)
            print(response.status_code)
            print(response.headers)

            firewallName = row['firewallName']
            print(f'ruleName is mapped too: {firewallName}')

            ruleName = row['ruleName']
            print(f'ruleName is mapped too: {ruleName}')

            filename = firewallName + "-" + ruleName + "_accessrule.json"

            if not os.path.exists(filename):

                with open(filename, mode='w') as f:
                    start = {"action": "ALLOW", "enabled": True, "type": "AccessRule", "name": f"{ruleName}", "sendEventsToFMC": True, "logFiles": False, "logBegin": False, "logEnd": True, "vlanTags": {}, "sourceZones": {"objects": []}, "destinationZones": {"objects": [
                    ]}, "sourceNetworks": {"objects": []}, "destinationNetworks": {"objects": []}, "destinationPorts": {"objects": []}, "sourceDynamicObjects": {}, "destinationDynamicObjects": {}, "newComments": ["ASA Configuration migrated by PRESIDIO GOVERNMENT SOLUTIONS"]}
                    json.dump(start, f)
                    sleep(1)

                with open(filename, "r") as file:

                    srcZone = row['srcZone']
                    print(f'srcZone is mapped too: {srcZone}')

                    if srcZone != "any":

                        url = f'https://{fmc_address}/api/fmc_config/v1/domain/{domainUUID}/object/securityzones'

                        newHeaders = {'Content-type': 'application/json',
                                      'Accept': 'text/plain', 'X-auth-access-token': XAuthAccessToken}

                        response = requests.get(
                            url, headers=newHeaders, verify=False)

                        print(response.request.url)
                        print(response.request.headers)
                        print(response.status_code)
                        print(response.content)

                        response_json = response.json()
                        items_list = response_json["items"]
                        item_count = 0
                        for item in items_list:
                            if (items_list[item_count]['name'] == srcZone):
                                print(item)
                                print("-------------------")
                                srcZoneUUID = items_list[item_count]['id']
                                print(f'Source Zone UUID is {srcZoneUUID}')

                            item_count += 1

                        data = json.load(file)
                        temp = data["sourceZones"]["objects"]
                        entry = {"name": f"{srcZone}",
                                 "id": f"{srcZoneUUID}", "type": "SecurityZone"}
                        print(entry)
                        temp.append(entry)

                        with open(filename, "w") as file:
                            json.dump(data, file)

                with open(filename, "r") as file:

                    destZone = row['destZone']
                    print(f'destZone is mapped too: {destZone}')

                    if destZone != "any":

                        url = f'https://{fmc_address}/api/fmc_config/v1/domain/{domainUUID}/object/securityzones'

                        newHeaders = {'Content-type': 'application/json',
                                      'Accept': 'text/plain', 'X-auth-access-token': XAuthAccessToken}

                        response = requests.get(
                            url, headers=newHeaders, verify=False)

                        print(response.request.url)
                        print(response.request.headers)
                        print(response.status_code)
                        print(response.content)

                        response_json = response.json()
                        items_list = response_json["items"]
                        item_count = 0
                        for item in items_list:
                            if (items_list[item_count]['name'] == destZone):
                                print(item)
                                print("-------------------")
                                destZoneUUID = items_list[item_count]['id']
                                print(
                                    f'Destination Zone UUID is {destZoneUUID}')

                            item_count += 1

                        data = json.load(file)
                        temp = data["destinationZones"]["objects"]
                        entry = {"name": f"{destZone}",
                                 "id": f"{destZoneUUID}", "type": "SecurityZone"}
                        print(entry)
                        temp.append(entry)

                        with open(filename, "w") as file:
                            json.dump(data, file)

                with open(filename, "r") as file:

                    srcNetGrp = row['srcNetworkGroup']
                    print(f'srcNetGrp is mapped too: {srcNetGrp}')

                    if srcNetGrp != "any":

                        url = f'https://{fmc_address}/api/fmc_config/v1/domain/{domainUUID}/object/networkgroups?filter=nameOrValue%3A{srcNetGrp}'

                        newHeaders = {'Content-type': 'application/json',
                                      'Accept': 'text/plain', 'X-auth-access-token': XAuthAccessToken}

                        response = requests.get(
                            url, headers=newHeaders, verify=False)

                        print(response.request.url)
                        print(response.request.headers)
                        print(response.status_code)
                        print(response.content)

                        response_json = response.json()

                        srcNetGrpUUID = response_json['items'][0]['id']
                        print(f'Source Network Group UUID is {srcNetGrpUUID}')

                        data = json.load(file)
                        temp = data["sourceNetworks"]["objects"]
                        entry = {"type": "NetworkGroup", "overridable": False,
                                 "id": f"{srcNetGrpUUID}", "name": f"{srcNetGrp}"}
                        print(entry)
                        temp.append(entry)

                        with open(filename, "w") as file:
                            json.dump(data, file)

                with open(filename, "r") as file:

                    destNetGrp = row['destNetworkGroup']
                    print(f'destNetGrp is mapped too: {destNetGrp}')

                    if destNetGrp != "any":

                        url = f'https://{fmc_address}/api/fmc_config/v1/domain/{domainUUID}/object/networkgroups?filter=nameOrValue%3A{destNetGrp}'

                        newHeaders = {'Content-type': 'application/json',
                                      'Accept': 'text/plain', 'X-auth-access-token': XAuthAccessToken}

                        response = requests.get(
                            url, headers=newHeaders, verify=False)

                        print(response.request.url)
                        print(response.request.headers)
                        print(response.status_code)
                        print(response.content)

                        response_json = response.json()

                        destNetGrpUUID = response_json['items'][0]['id']
                        print(
                            f'Destination Network Group UUID is {destNetGrpUUID}')

                        data = json.load(file)
                        temp = data["destinationNetworks"]["objects"]
                        entry = {"type": "NetworkGroup", "overridable": False,
                                 "id": f"{destNetGrpUUID}", "name": f"{destNetGrp}"}
                        print(entry)
                        temp.append(entry)

                        with open(filename, "w") as file:
                            json.dump(data, file)

                with open(filename, "r") as file:

                    destPortGrp = row['destPortGroup']
                    print(f'destPortGrp is mapped too: {destPortGrp}')

                    if destPortGrp != "any":

                        url = f'https://{fmc_address}/api/fmc_config/v1/domain/{domainUUID}/object/portobjectgroups?filter=nameOrValue%3A{destPortGrp}'

                        newHeaders = {'Content-type': 'application/json',
                                      'Accept': 'text/plain', 'X-auth-access-token': XAuthAccessToken}

                        response = requests.get(
                            url, headers=newHeaders, verify=False)

                        print(response.request.url)
                        print(response.request.headers)
                        print(response.status_code)
                        print(response.content)

                        response_json = response.json()
                        destPortGrpUUID = response_json['items'][0]['id']
                        print(
                            f'Destination Port Group UUID is {destPortGrpUUID}')

                        data = json.load(file)
                        temp = data["destinationPorts"]["objects"]
                        entry = {"type": "PortObjectGroup", "overridable": False,
                                 "id": f"{destPortGrpUUID}", "name": f"{destPortGrp}"}
                        print(entry)
                        temp.append(entry)

                        with open(filename, "w") as file:
                            json.dump(data, file)

                        with open(filename, "r") as file:

                            srcZone = row['srcZone']
                            print(f'srcZone is mapped too: {srcZone}')

                            if srcZone != "any":

                                url = f'https://{fmc_address}/api/fmc_config/v1/domain/{domainUUID}/object/securityzones'

                                newHeaders = {'Content-type': 'application/json',
                                              'Accept': 'text/plain', 'X-auth-access-token': XAuthAccessToken}

                                response = requests.get(
                                    url, headers=newHeaders, verify=False)

                                print(response.request.url)
                                print(response.request.headers)
                                print(response.status_code)
                                print(response.content)

                                response_json = response.json()
                                items_list = response_json["items"]
                                item_count = 0
                                for item in items_list:
                                    if (items_list[item_count]['name'] == srcZone):
                                        print(item)
                                        print("-------------------")
                                        srcZoneUUID = items_list[item_count]['id']
                                        print(
                                            f'Source Zone UUID is {srcZoneUUID}')

                                    item_count += 1

                                data = json.load(file)
                                temp = data["sourceZones"]["objects"]
                                entry = {
                                    "name": f"{srcZone}", "id": f"{srcZoneUUID}", "type": "SecurityZone"}
                                print(entry)
                                temp.append(entry)

                                with open(filename, "w") as file:
                                    json.dump(data, file)

                        with open(filename, "r") as file:

                            destZone = row['destZone']
                            print(f'destZone is mapped too: {destZone}')

                            if destZone != "any":

                                url = f'https://{fmc_address}/api/fmc_config/v1/domain/{domainUUID}/object/securityzones'

                                newHeaders = {'Content-type': 'application/json',
                                              'Accept': 'text/plain', 'X-auth-access-token': XAuthAccessToken}

                                response = requests.get(
                                    url, headers=newHeaders, verify=False)

                                print(response.request.url)
                                print(response.request.headers)
                                print(response.status_code)
                                print(response.content)

                                response_json = response.json()
                                items_list = response_json["items"]
                                item_count = 0
                                for item in items_list:
                                    if (items_list[item_count]['name'] == destZone):
                                        print(item)
                                        print("-------------------")
                                        destZoneUUID = items_list[item_count]['id']
                                        print(
                                            f'Destination Zone UUID is {destZoneUUID}')

                                    item_count += 1

                                data = json.load(file)
                                temp = data["destinationZones"]["objects"]
                                entry = {
                                    "name": f"{destZone}", "id": f"{destZoneUUID}", "type": "SecurityZone"}
                                print(entry)
                                temp.append(entry)

                                with open(filename, "w") as file:
                                    json.dump(data, file)

                        with open(filename, "r") as file:

                            srcNetGrp = row['srcNetworkGroup']
                            print(f'srcNetGrp is mapped too: {srcNetGrp}')

                            if srcNetGrp != "any":

                                url = f'https://{fmc_address}/api/fmc_config/v1/domain/{domainUUID}/object/networkgroups?filter=nameOrValue%3A{srcNetGrp}'

                                newHeaders = {'Content-type': 'application/json',
                                              'Accept': 'text/plain', 'X-auth-access-token': XAuthAccessToken}

                                response = requests.get(
                                    url, headers=newHeaders, verify=False)

                                print(response.request.url)
                                print(response.request.headers)
                                print(response.status_code)
                                print(response.content)

                                response_json = response.json()

                                srcNetGrpUUID = response_json['items'][0]['id']
                                print(
                                    f'Source Network Group UUID is {srcNetGrpUUID}')

                                data = json.load(file)
                                temp = data["sourceNetworks"]["objects"]
                                entry = {"type": "NetworkGroup", "overridable": False,
                                         "id": f"{srcNetGrpUUID}", "name": f"{srcNetGrp}"}
                                print(entry)
                                temp.append(entry)

                                with open(filename, "w") as file:
                                    json.dump(data, file)

                        with open(filename, "r") as file:

                            destNetGrp = row['destNetworkGroup']
                            print(f'destNetGrp is mapped too: {destNetGrp}')

                            if destNetGrp != "any":

                                url = f'https://{fmc_address}/api/fmc_config/v1/domain/{domainUUID}/object/networkgroups?filter=nameOrValue%3A{destNetGrp}'

                                newHeaders = {'Content-type': 'application/json',
                                              'Accept': 'text/plain', 'X-auth-access-token': XAuthAccessToken}

                                response = requests.get(
                                    url, headers=newHeaders, verify=False)

                                print(response.request.url)
                                print(response.request.headers)
                                print(response.status_code)
                                print(response.content)

                                response_json = response.json()

                                destNetGrpUUID = response_json['items'][0]['id']
                                print(
                                    f'Destination Network Group UUID is {destNetGrpUUID}')

                                data = json.load(file)
                                temp = data["destinationNetworks"]["objects"]
                                entry = {"type": "NetworkGroup", "overridable": False,
                                         "id": f"{destNetGrpUUID}", "name": f"{destNetGrp}"}
                                print(entry)
                                temp.append(entry)

                                with open(filename, "w") as file:
                                    json.dump(data, file)

                        with open(filename, "r") as file:

                            destPortGrp = row['destPortGroup']
                            print(f'destPortGrp is mapped too: {destPortGrp}')

                            if destPortGrp != "any":

                                url = f'https://{fmc_address}/api/fmc_config/v1/domain/{domainUUID}/object/portobjectgroups?filter=nameOrValue%3A{destPortGrp}'

                                newHeaders = {'Content-type': 'application/json',
                                              'Accept': 'text/plain', 'X-auth-access-token': XAuthAccessToken}

                                response = requests.get(
                                    url, headers=newHeaders, verify=False)

                                print(response.request.url)
                                print(response.request.headers)
                                print(response.status_code)
                                print(response.content)

                                response_json = response.json()
                                destPortGrpUUID = response_json['items'][0]['id']
                                print(
                                    f'Destination Port Group UUID is {destPortGrpUUID}')

                                data = json.load(file)
                                temp = data["destinationPorts"]["objects"]
                                entry = {"type": "PortObjectGroup", "overridable": False,
                                         "id": f"{destPortGrpUUID}", "name": f"{destPortGrp}"}
                                print(entry)
                                temp.append(entry)

                                with open(filename, "w") as file:
                                    json.dump(data, file)

    with open('secrules.csv') as csv_file:

        csv_reader = csv.DictReader(csv_file, delimiter=',')
        line_count = 0

        for row in csv_reader:

            firewallName = row['firewallName']
            print(f'ruleName is mapped too: {firewallName}')

            ruleName = row['ruleName']
            print(f'ruleName is mapped too: {ruleName}')

            accesspolicy = row['accesspolicyName']
            print(f'Access Policy is mapped too: {accesspolicy}')

            category = row['categoryName']
            print(f'Category is mapped too: {category}')

            url = f'https://{fmc_address}/api/fmc_config/v1/domain/{domainUUID}/policy/accesspolicies?name={accesspolicy}'

            newHeaders = {'Content-type': 'application/json',
                          'Accept': 'text/plain', 'X-auth-access-token': XAuthAccessToken}

            response = requests.get(url, headers=newHeaders, verify=False)

            print(response.request.url)
            print(response.request.headers)
            print(response.status_code)
            print(response.content)

            response_json = response.json()
            items_list = response_json["items"]
            item_count = 0
            for item in items_list:
                if (items_list[item_count]['name'] == accesspolicy):
                    print(item)
                    print("-------------------")
                    containerUUID = items_list[item_count]['id']
                    print(
                        f'Access Policy, {accesspolicy}, UUID is {containerUUID}')

                item_count += 1

            filename = firewallName + "-" + ruleName + "_accessrule.json"

            url = f'https://{fmc_address}/api/fmc_config/v1/domain/{domainUUID}/policy/accesspolicies/{containerUUID}/accessrules?category={category}'

            newHeaders = {'Content-type': 'application/json',
                          'Accept': 'text/plain', 'X-auth-access-token': XAuthAccessToken}

            response = requests.post(url, data=open(
                filename, 'rb'), headers=newHeaders, verify=False)

            print(response.request.url)
            print(response.request.headers)
            print(response.request.body)
            print(response.status_code)
            print(response.content)


while True:
    print('Author: Trevor Patch')
    print('Release Date: 5/27/2022')
    print('FMC Tested Version: 7.0.1-84')
    print('\n')
    print('--------------------------------')
    print('\n')

    fmc_address = input("Please provide the FMC Target Address: ")
    username = input("Enter Username: ")
    password = getpass.getpass('Enter Password:')

    while True:
        print('Menu: ')
        print('0. Quit')
        print('1. Create SecurityZone without Interface')
        print('2. Create AccessPolicy for firewall pair')
        print('3. Create Network Objects')
        print('4. Create Port Objects')
        print('5. Create Security Policy for firewall pair')

        selection = input("Please select a menu number: ")

        if selection == "0":
            break

        elif selection == "1":
            create_security_zones()

        elif selection == "2":
            create_access_policy()

        elif selection == "3":
            create_network_objects()

        elif selection == "4":
            create_port_objects()

        elif selection == "5":
            create_security_rules()

        else:
            print('Invalid Menu Selection. Please input the menu number only.')

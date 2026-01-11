import requests
import json
import zipfile
import time
import xml.etree.ElementTree as ET
from auth2 import Auth2Token
from request import RestRequest
class ExtracterApigeeResources():
    def __init__(self,domain="apigee.googleapis.com", 
                 organization="gcp101027-apigeex"):
        self.request = RestRequest()
        self.domain = domain
        self.main_url = f"https://{self.domain}/v1/organizations/"
        self.organization = organization
    def get_last_number_deployed_revision_proxy(self, name_proxy):
        response = self.request.get(f"{self.main_url}{self.organization}/apis/{name_proxy}/deployments")
        if (len(json.loads(response.text)) > 0):
            revisions = json.loads(response.text)["deployments"] # get all deployed revisions
            list_revisions = []
            for revision in revisions:
                list_revisions.append(int(revision['revision']))
            final_revision = max(list_revisions)
            return final_revision
        else:
            return -1
    def get_deployed_revisions_proxy(self, name_proxy):
        response = self.request.get(f"{self.main_url}{self.organization}/apis/{name_proxy}/deployments")
        if (len(json.loads(response.text)) > 0):
            revisions = json.loads(response.text)["deployments"] # get all deployed revisions
            list_revisions = []
            for revision in revisions:
                record = {}
                record["revision"] = int(revision['revision'])
                record["environment"] = revision["environment"]
                list_revisions.append(record)
            return list_revisions
        else:
            return -1
    def download_file(self,url):
        # NOTE the stream=True parameter below
        with self.request.get(url,stream=True) as r:
            r.raise_for_status()
            with open("temprorary.zip", 'wb') as f:
                for chunk in r.iter_content(chunk_size=8192): 
                    # If you have chunk encoded response uncomment if
                    # and set chunk_size parameter to None.
                    #if chunk: 
                    f.write(chunk)
    def get_sharedflows(self,url):
        sharedflows = []
        policy_list = []
        self.download_file(url)
        with zipfile.ZipFile("temprorary.zip") as arhive:
            list_names = [object for object in arhive.namelist() if "apiproxy/policies/" in str(object)]
            if len(list_names) > 0:
                if "apiproxy/policies/" in list_names:
                    list_names.remove("apiproxy/policies/")
                    policy_list = [str(object).removeprefix("apiproxy/policies/") for object in list_names]
                    flowcallout_list = self.filterpolicyBySharedflow(policy_list)
                    if len(flowcallout_list) > 0:
                        for flowcallout in flowcallout_list:
                            with arhive.open("apiproxy/policies/"+flowcallout) as myfile:
                                root_element = ET.fromstring(myfile.read())
                                for sharedflow in root_element.findall('SharedFlowBundle'): 
                                    sharedflows.append(sharedflow.text)
        return (sharedflows,policy_list)
    def filterpolicyBySharedflow(self, policies):
        acronyms = ["AC-","AM-","AE-",
                    "BA-","CRL-","EV-",
                    "JS-","JC-", "JTP-", 
                    "J2X-", "JtoX-", "KVM-",
                    "LDAP-","ML-","PC-",
                    "LC-","IC-", "SA-", 
                    "QZ-", "VC-", "RC-",
                    "OAuthv1-", "OAuthv2-","Python-", 
                    "Q-", "RQ-", "RF-",
                    "RE-", "MV-", "SAML-",
                    "EC-", "JWT-", "JWS-",
                    "SC-", "SA-","Stats-",
                    "VAK-", "XMLTP-", "X2J-",
                    "XSL-"] # filtering all known convient names of policy expect FC and others unknown))
        sharedflows = []
        for policy in policies:
            structure_policy = str(policy).split("-")
            if f"{structure_policy[0]}-" not in acronyms:
                sharedflows.append(policy)
        return sharedflows
    def filterpolicyByKVM(self, policies):
        acronyms = ["AC-","AM-","AE-",
                    "BA-","CRL-","EV-",
                    "JS-","JC-", "JTP-", 
                    "J2X-", "JtoX-","LDAP-",
                    "ML-","PC-","LC-",
                    "IC-", "SA-", 
                    "QZ-", "VC-", "RC-",
                    "OAuthv1-", "OAuthv2-","Python-", 
                    "Q-", "RQ-", "RF-",
                    "RE-", "MV-", "SAML-",
                    "EC-", "JWT-", "JWS-",
                    "SC-", "SA-","Stats-",
                    "VAK-", "XMLTP-", "X2J-",
                    "XSL-", "FC-"] # filtering all known convient names of policy expect FC and others unknown))
        sharedflows = []
        for policy in policies:
            structure_policy = str(policy).split("-")
            if f"{structure_policy[0]}-" not in acronyms:
                sharedflows.append(policy)
        return sharedflows
    def get_kvm_dependency(self,policy_list):
        kvm = []
        if len(policy_list) > 0: 
            with zipfile.ZipFile("temprorary.zip") as archive:
                flowcallout_list = self.filterpolicyByKVM(policy_list)
                if len(flowcallout_list) > 0:
                    for flowcallout in flowcallout_list:
                            with archive.open("apiproxy/policies/"+flowcallout) as myfile:
                                root_element = ET.fromstring(myfile.read())
                                name_kvm = root_element.get("mapIdentifier")
                                if name_kvm is not None and name_kvm not in kvm:
                                    kvm.append(name_kvm)
        return kvm
    def get_kvm_dependency_without_policy(self):
        kvm = [] 
        with zipfile.ZipFile("temprorary.zip") as archive:
                print(archive.namelist())
                list_names = [object for object in archive.namelist() if "sharedflowbundle/policies/" in str(object)]
                if len(list_names) > 0:
                    if "sharedflowbundle/policies" in list_names:
                        list_names.remove("sharedflowbundle/")
                        list_names.remove("sharedflowbundle/policies/")
                    policy_list = [str(object).removeprefix("sharedflowbundle/policies/") for object in list_names]
                    if len(policy_list) > 0:
                            flowcallout_list = self.filterpolicyByKVM(policy_list)
                            if len(flowcallout_list) > 0:
                                print(flowcallout_list)
                                for flowcallout in flowcallout_list:
                                        with archive.open("sharedflowbundle/policies/"+flowcallout) as myfile:
                                            content = myfile.read()
                                            if len(content) > 0:
                                                root_element = ET.fromstring(content.decode('utf-8'))
                                                name_kvm = root_element.get("mapIdentifier")
                                                if name_kvm is not None and name_kvm not in kvm:
                                                    kvm.append(name_kvm)
        return kvm
    def get_proxies(self,includeRevisions=False,includeMetaData=False):
        response = []
        list_all_names_proxy = json.loads(self.request.get(f"{self.main_url}{self.organization}/apis?includeRevisions={includeRevisions}&includeMetaData={includeMetaData}").text)["proxies"] 
        for proxy in list_all_names_proxy:
            record = {}
            record["type"] = "proxy"
            record["name"] = proxy["name"]
            record["revisions"] = {}
            revisions = self.get_deployed_revisions_proxy(proxy["name"])
            if revisions == -1:
                revision_dependency = {}
                resp = json.loads(self.request.get(f"{self.main_url}{self.organization}/apis/{proxy["name"]}",).text)
                revision_dependency["enviroment"] = ""
                record["revisions"][f"{resp["latestRevisionId"]}"] = revision_dependency
            else:
                for revision in revisions:
                    revision_dependency = {}
                    url = f"{self.main_url}{self.organization}/apis/{proxy["name"]}/revisions/{revision["revision"]}?format=bundle"
                    (list_sharedflow, policy) = self.get_sharedflows(url)
                    list_kvms_dependency = self.get_kvm_dependency(policy)
                    revision_dependency["kvms_dependency"] = list_kvms_dependency
                    revision_dependency["sharedflow"] = list_sharedflow
                    revision_dependency["enviroment"] = revision["environment"]
                    record["revisions"][f"{revision["revision"]}"] = revision_dependency
            record["kvms_proxy_scope"] = self.get_kvms_proxy(proxy["name"])
            response.append(record)
        print(f"Total proxy extracted: {len(response)}")
        print("proxy was done")
        return response
    def get_organization(self):
        response = self.request.get(f"{self.main_url}{self.organization}")
        return response.json()
    def get_kvms_organization(self):
        kvms = []
        response = self.request.get(f"{self.main_url}{self.organization}/keyvaluemaps")
        for kvm in response.json():
            record = {"name": kvm, "proxies": [], "sharedflow": []}
            kvms.append(record)
        return kvms
    def get_kvms_environment(self, environment):
        kvms = []
        response = self.request.get(f"{self.main_url}{self.organization}/environments/{environment}/keyvaluemaps")
        for kvm in response.json():
            record = {"name": kvm, "proxies": [], "sharedflow": []}
            kvms.append(record)
        return kvms
    def get_kvms_proxy(self, proxy):
        response = self.request.get(f"{self.main_url}{self.organization}/apis/{proxy}/keyvaluemaps")
        return response.json()
    def get_sharedflows_list(self):
        sharedflows = []
        response = self.request.get(f"{self.main_url}{self.organization}/sharedflows")
        for sharedflow in response.json()['sharedFlows']:
            record = {}
            record["name"] = sharedflow["name"]
            record["revisions"] = {}
            record["proxy"] = []
            revisions = self.get_sharedflow_deployments(sharedflow["name"])
            for revision in revisions:
                numberRevision = revision["revision"]
                record["revisions"][f"{numberRevision}"] = {}
                record["revisions"][f"{numberRevision}"]["kvm"] = self.get_sharedflow_kvm(sharedflow["name"],numberRevision)
                record["revisions"][f"{numberRevision}"]["environment"] = revision["environment"]
                record["revisions"][f"{numberRevision}"]["proxy"] = [] 
            sharedflows.append(record)
        print(f"Total sharedflow extracted: {len(sharedflows)}")
        print("sharedflow was done")
        return sharedflows
    def get_sharedflow_kvm(self, sharedflow, revision):
        url = f"{self.main_url}{self.organization}/sharedflows/{sharedflow}/revisions/{revision}?format=bundle"
        self.download_file(url)
        return self.get_kvm_dependency_without_policy()
    def get_sharedflow_deployments(self, sharedflowName):
        response = self.request.get(f"{self.main_url}{self.organization}/sharedflows/{sharedflowName}/deployments")
        if 'deployments' in response.json():
            return response.json()['deployments']
        else:
            return []
    def get_apiproducts(self):
        apiproducts = []
        response = self.request.get(f"{self.main_url}{self.organization}/apiproducts")
        apiproducts = response.json()['apiProduct']
        for apiproduct in apiproducts:
            apiproduct["proxy"] = [] 
            details_apiproduct = self.request.get(f"{self.main_url}{self.organization}/apiproducts/{apiproduct["name"]}").json()
            if "operationGroup" in details_apiproduct:
                if "operationConfigs" in details_apiproduct["operationGroup"]:
                    details = details_apiproduct["operationGroup"]["operationConfigs"]
                    proxy = []
                    for detail in details:
                        proxy.append(detail['apiSource'])
                    apiproduct["proxy"] = proxy
            if "proxies" in details_apiproduct:
                apiproduct["proxy"] = details_apiproduct["proxies"]
        print(f"Total apiproducts extracted: {len(apiproducts)}")
        print("apiproduct was done")
        return apiproducts
    def get_apps(self):
        response = self.request.get(f"{self.main_url}{self.organization}/apps?expand=true")
        apps = response.json()['app']
        new_format_apps = []
        for app in apps:
            record = {}
            record["name"] = app["name"]
            apiproducts = []
            if 'apiProducts' in app["credentials"][0]:
                for apiproduct in app["credentials"][0]['apiProducts']:
                    apiproducts.append(apiproduct['apiproduct'])
            record["apiproduct"] = apiproducts
            new_format_apps.append(record)
        print(f"Total apps extracted: {len(new_format_apps)}")
        print("apps was done")
        return new_format_apps
    def get_developers(self):
        response = self.request.get(f"{self.main_url}{self.organization}/developers?expand=true")
        developers = response.json()["developer"]
        new_format_developers = []
        for developer in developers:
            record = {}
            record["email"] = developer["email"]
            apps = []
            if 'apps' in developer:
                for app in developer["apps"]:
                    apps.append(app)
            record["app"] = apps
            new_format_developers.append(record)
        print(f"Total developers extracted: {len(new_format_developers)}")
        print("Developers was done")
        return new_format_developers
    def get_flowhooks(self, env):
        response = self.request.get(f"{self.main_url}{self.organization}/environments/{env}/flowhooks").json()
        flowhooks = []
        for flowhook in response:
            fh = {}
            response_flowhook = self.request.get(f"{self.main_url}{self.organization}/environments/{env}/flowhooks/{flowhook}").json()
            fh["name"] = flowhook
            fh["sharedflow"] = ""
            if "sharedflow" in response_flowhook:
                fh["sharedflow"] = response_flowhook["sharedFlow"] 
            flowhooks.append(fh)
        return flowhooks
    def get_keystores(self, env):
        response = self.request.get(f"{self.main_url}{self.organization}/environments/{env}/keystores").json()
        return response
    def get_caches(self,env):
        response = self.request.get(f"{self.main_url}{self.organization}/environments/{env}/caches").json()
        return response
    def build_hierarchy(self, file):
        structure = {}
        organization = self.get_organization()
        structure["organization_name"] = organization["name"]
        structure["organization_kvm"] = self.get_kvms_organization()
        structure["environments"] = [{"name": env, "kvm": self.get_kvms_environment(env),
                                      "keystore": self.get_keystores(env), "cache": self.get_caches(env),
                                      "flowhook": self.get_flowhooks(env), "proxy": [], "sharedflow": []} 
                                     for env in organization["environments"]]
        structure["sharedflow"] = self.get_sharedflows_list()
        structure["proxy"] = self.get_proxies()
        structure["apiproduct"] = self.get_apiproducts()
        structure["app"] = self.get_apps()
        structure["developers"] = self.get_developers()
        print("Start collecting dependencies...")
        for kvm in structure["organization_kvm"]: # find dependency between kvms organization and sharedflow
            for sharedflow in structure["sharedflow"]:
                for key,value in sharedflow["revisions"].items():
                    if "kvm" in value:
                        for KVM in value["kvm"]:
                            if kvm["name"] == KVM:
                                if sharedflow["name"] not in kvm["sharedflow"]:
                                    kvm["sharedflow"].append(sharedflow["name"])
        for record in structure["environments"]: # find dependency between kvms environment scope and sharedflow
            for kvm in record["kvm"]:
                for sharedflow in structure["sharedflow"]:
                    for key,value in sharedflow["revisions"].items():
                        if "kvm" in value:
                            for KVM in value["kvm"]:
                                if kvm["name"] == KVM:
                                    if sharedflow["name"] not in kvm["proxies"]:
                                        kvm["sharedflow"].append(sharedflow["name"])
        for kvm in structure["organization_kvm"]: # find dependency between kvms organization and proxy
            for proxy in structure["proxy"]:
                for key,value in proxy["revisions"].items():
                    if "kvms_dependency" in value:
                        for KVM in value["kvms_dependency"]:
                            if kvm["name"] == KVM:
                                if proxy["name"] not in kvm["proxies"]:
                                    kvm["proxies"].append(proxy["name"])
        for record in structure["environments"]: # find dependency between kvms environment scope and proxy
            for kvm in record["kvm"]:
                for proxy in structure["proxy"]:
                    for key,value in proxy["revisions"].items():
                        if "kvms_dependency" in value:
                            for KVM in value["kvms_dependency"]:
                                if kvm["name"] == KVM:
                                    if proxy["name"] not in kvm["proxies"]:
                                        kvm["proxies"].append(proxy["name"])
        for environment in structure["environments"]: # find dependency between environment and proxy
            for proxy in structure["proxy"]:
                for key,value in proxy["revisions"].items():
                    if environment["name"] == value["enviroment"]:
                        environment["proxy"].append(proxy["name"])
        for environment in structure["environments"]: # find dependency between environment and sharedflow
            for sharedflow in structure["sharedflow"]:
                if len(sharedflow["revisions"]) > 0:
                    for key,value in sharedflow["revisions"].items():
                            if environment["name"] == value["environment"]:
                                environment["sharedflow"].append(sharedflow["name"])
        for proxy in structure["proxy"]: # find dependency between proxy and sharedflow
            for key, value in proxy["revisions"].items():
                if "sharedflow" in value:
                    for sharedfl in value["sharedflow"]:
                        for sharedflow in structure["sharedflow"]:
                            if sharedfl == sharedflow["name"]:
                                sharedflow["proxy"].append(proxy["name"])
        for apiproduct in structure["apiproduct"]: # find dependency between apiproduct and proxy
            for proxy in apiproduct["proxy"]:
                for prox in structure["proxy"]:
                    if prox["name"] == proxy:
                       prox["apiproduct"] = apiproduct["name"]
        for app in structure["app"]: # find dependency between app and apiproduct
            for apiproduct in app['apiproduct']:
                for apiprod in structure["apiproduct"]:
                    if apiprod["name"] == apiproduct:
                       apiprod["app"] = app["name"]
        print("Almost done, are you still there?")
        for developer in structure["developers"]: # find dependency between developers and app
            for app in developer['app']:
                for App in structure["app"]:
                    if App["name"] == app:
                       App["developer"] = developer["email"]
        with open(file, "w", encoding="utf-8") as hierarchy:
            json.dump(structure, hierarchy, ensure_ascii=False, indent=4)
        print(f"hierarchy saved in file: {file}")
        return structure 
if __name__ == "__main__":
   start = time.time()
   extracter = ExtracterApigeeResources()
   data1 = extracter.build_hierarchy("hierarchy.json")
   end = time.time()
   print("Time to complete: %d", end-start)


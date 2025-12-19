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
                list_revisions.append(int(revision['revision']))
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
        self.download_file(url)
        with zipfile.ZipFile("temprorary.zip") as arhive:
            list_names = [object for object in arhive.namelist() if "apiproxy/policies/" in str(object)]
            if len(list_names) > 0:
                if "apiproxy/policies/" in list_names:
                    list_names.remove("apiproxy/policies/")
                    policy_list = [str(object).removeprefix("apiproxy/policies/") for object in list_names]
                    flowcallout_list = [policy for policy in policy_list if "FC-" in policy]
                    if len(flowcallout_list) > 0:
                        for flowcallout in flowcallout_list:
                            with arhive.open("apiproxy/policies/"+flowcallout) as myfile:
                                root_element = ET.fromstring(myfile.read())
                                for sharedflow in root_element.findall('SharedFlowBundle'): 
                                    sharedflows.append(sharedflow.text)
        return sharedflows
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
                resp = json.loads(self.request.get(f"{self.main_url}{self.organization}/apis/{proxy["name"]}",).text)
                revisions = [resp["latestRevisionId"]]
            for revision in revisions:
                revision_dependency = {}
                url = f"{self.main_url}{self.organization}/apis/{proxy["name"]}/revisions/{revision}?format=bundle"
                list_sharedflow = self.get_sharedflows(url)
                revision_dependency["sharedflow"] = list_sharedflow
                record["revisions"][f"{revision}"] = revision_dependency
            response.append(record)
        print(f"Total proxy extracted: {len(response)}")
        with open("proxy.json", "w", encoding="utf-8") as proxyfile:
            json.dump(response, proxyfile, ensure_ascii=False, indent=4)
        print("proxy was done")
        return response
    def get_organization(self):
        response = self.request.get(f"{self.main_url}{self.organization}")
        return response.json()
    def get_kvms_organization(self):
        response = self.request.get(f"{self.main_url}{self.organization}/keyvaluemaps")
        return response.json()
    def get_kvms_environment(self, environment):
        response = self.request.get(f"{self.main_url}{self.organization}/environments/{environment}/keyvaluemaps")
        return response.json()
    def get_kvms_proxy(self, proxy):
        response = self.request.get(f"{self.main_url}{self.organization}/apis/{proxy}/keyvaluemaps")
        return response.json()
    def get_sharedflows_list(self):
        sharedflows = []
        response = self.request.get(f"{self.main_url}{self.organization}/sharedflows")
        for sharedflow in response.json()['sharedFlows']:
            sharedflows.append(sharedflow["name"])
        return sharedflows
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
        return new_format_developers
    def build_hierarchy(self):
        structure = {}
        organization = self.get_organization()
        structure["organization_name"] = organization["name"]
        structure["organization_kvm"] = self.get_kvms_organization()
        structure["environments"] = [{"name": env, "kvm": self.get_kvms_environment(env)} 
                                     for env in organization["environments"]]
        structure["sharedflow"] = [{"name": sharedflow, "proxy": []} for sharedflow in self.get_sharedflows_list()]
        structure["proxy"] = self.get_proxies()
        structure["apiproduct"] = self.get_apiproducts()
        structure["app"] = self.get_apps()
        structure["developers"] = self.get_developers()
        for apiproduct in structure["apiproduct"]: # find depedency between apiproduct and proxy
            for proxy in apiproduct["proxy"]:
                for prox in structure["proxy"]:
                    if prox["name"] == proxy:
                       prox["apiproduct"] = apiproduct["name"]
        for app in structure["app"]: # find depedency between app and apiproduct
            for apiproduct in app['apiproduct']:
                for apiprod in structure["apiproduct"]:
                    if apiprod["name"] == apiproduct:
                       apiprod["app"] = app["name"]
        for developer in structure["developers"]: # find depedency between developers and app
            for app in developer['app']:
                for App in structure["apps"]:
                    if App["name"] == app:
                       App["developer"] = developer["email"]
        with open("hierarchy.json", "w", encoding="utf-8") as hierarchy:
            json.dump(structure, hierarchy, ensure_ascii=False, indent=4)
        return structure
    def get_proxy(self,name,includeRevisions=False,includeMetaData=False):
        response = self.request.get(f"{self.main_url}{self.organization}/apis/{name}")
        proxies_json = json.loads(response.text)
        return proxies_json
if __name__ == "__main__":
   start = time.time()
   extracter = ExtracterApigeeResources()
   data1 = extracter.get_developers()
   end = time.time()
   print(data1)
   print(f"Length: {len(data1)}")
   print("Time: %d", end-start)
#    with open("result.json", "w") as f:
#         f.write(json.dumps(data1))


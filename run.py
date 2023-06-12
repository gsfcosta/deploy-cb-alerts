#!/usr/bin/python3
from time import timezone
import time
import requests,json,sys,os
from dateutil import parser
from datetime import datetime, timedelta
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#Proxy Bypass
os.environ['http_proxy'] = 'http://127.0.0.1:3128'
os.environ['https_proxy'] = 'http://127.0.0.1:3128'
#Carrega Variaveis
cb_api_id           = os.environ["API_ID"]
cb_api_secret_key   = os.environ["API_SECRET_KEY"]
cb_url              = "https://defense-prod05.conferdeploy.net/appservices/v6/orgs/<token>"
#Verifica alertas
data = datetime.now() - timedelta(minutes=60)
datan = datetime.now() + timedelta(hours=3)
dataold = f"{data.isoformat()[:-3]}Z"
datanow = f"{datan.isoformat()[:-3]}Z"
print("data inicio: " + dataold  + " / data fim: " + datanow)
headers = {
    'content-type': "application/json",
    'X-AUTH-TOKEN': cb_api_secret_key + "/" + cb_api_id,
}
criteria = {
    "criteria": {
        "workflow": ["OPEN"],
        "create_time": {
            "end": datanow,
            "start": dataold
        }
    },
    "sort": [
    {
        "field": "create_time",
        "order": "ASC"
    }
    ]}
x = requests.post(cb_url + "/alerts/_search", headers=headers, json=criteria, verify=False)
response = json.loads(x.content)
found = (response['num_found'])
response = (response['results'])
i = int(found)
if i > 0:
    log = str(datetime.now()) + "  INFO : " + str(i) + " incidentes encontrados"
    print(log)
    z = 0
    for alert in response:
        try:
            device_name = alert["device_name"]
            splited = device_name.split("\\")
            device = splited[1]
        except:
            device = alert["device_name"]
        alert_reason = (alert["reason"])
        smax_alert_title = "CB - " + device + " - " + alert_reason
        ####################
        
        # <GET IF INCIDENT EXISTS> #
        count = 0
        ####################  
        policy = int(alert["policy_id"])   
        if count == 0 and policy != 295031:
            try:
                # Abrir incidente
                alert_severity = int(alert["severity"])
                dt1 = parser.parse(alert["create_time"])
                dt = dt1 + timedelta(hours=3)
                data = str(dt.date())
                tempo = str(dt.time().strftime("%H:%M:%S"))
                device_id = str(alert["device_id"])
                severity = str(alert["severity"])
                alert_id = str(alert["id"])
                note = {"note": "Incident: "}
                requests.post(cb_url + "/alerts/" + alert["id"] + "/notes", headers=headers, json=note)
                z = z + 1
            except BaseException as e:
                log = str(datetime.now()) + "  ERROR : Erro ao abrir incidente - " + str(e)
                print(log)
        else:
            continue
    log = str(datetime.now()) + "  INFO : " + str(z) + " incidentes abertos"
    print(log)
else:
    log = str(datetime.now()) + "  INFO : Nenhum incidente encontrado nos ultimos 15 minutos\n"
    print(log)

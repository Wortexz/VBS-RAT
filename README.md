# VBS-RAT

## About the malware
Friday malware day! Interesting malware analysis.    
Malware developers are not chilling on Friday and sending targeted RAT/Spyware worldwide including specific Lithuanian organizations.    

![Screenshot 2024-06-07 204317](https://github.com/Wortexz/VBS-RAT/assets/26935578/6cf45c5c-cdad-4eb0-acb9-dc45b1135950)    

- Distributed via e-mail attachment.
- Seen in Lithuania: Jun 7, 2024, ~14:00:00 EEST.
- Malware Family: RemcosRAT using GuLoader.
- Reads all saved Browser credentials & Email software credentials (Microsoft Outlook).    

- VirusTotal - not many detections (1h after uploading to VirusTotal):

![Screenshot 2024-06-07 170141](https://github.com/Wortexz/VBS-RAT/assets/26935578/00d17ab5-02fa-450b-bcce-090f4c72e25a)

__VirusTotal:__    
First Submission: 2024-06-07 10:40:48 UTC     
Last Analysis: 2024-06-07 17:50:53 UTC    

![Screenshot 2024-06-07 205228](https://github.com/Wortexz/VBS-RAT/assets/26935578/f8d81eb2-012b-4b77-adba-078ee0f6d4a1)    

## What's interesting about this sample?
- A lot of AV vendors for a few hours seem to be struggling to detect this malware with Signature/Heuristic detections.
- Malware behavior is also quite a show.
- Many anti-analysis techniques.
- This malware can be Fileless if launched right.
- Few organizations were attacked and other malware tricks are interesting.

## Malware analysis:
__Type:__ VBScript    

![Screenshot 2024-06-07 170904](https://github.com/Wortexz/VBS-RAT/assets/26935578/94582cde-0358-478b-bd3e-3ca85db74242)    
  
![image](https://github.com/Wortexz/VBS-RAT/assets/26935578/99962d5b-fe69-4138-bf34-b76f659a0fca)

__Malicious Indicators:__    

- __Behavior indicates:__ Remote Access Trojan (RAT) 
- __Sample drops modified:__ NirSoft MailPassView & NirSoft WebBrowserPassView
- __Script file shows a combination of malicious behavior__
- __HTTP requests contain Base64 strings__
- __XOR operators (encryption/decryption)__
- Writes data to a remote process
- Spawns a lot of processes
- Executes powershell with commandline
- GETs files from a webserver
- Sends traffic on typical HTTP outbound port, but without HTTP header
- Uses a browser-related user-agent without launching browser
- Modifies Software Policy Settings
- Writes registry keys
- Unusual Characteristics

__Anti-Reverse Engineering:__    
- __Creates guarded memory regions (anti-debugging trick to avoid memory dumping).__
- __Looks up country code configured in the registry, likely geofence.__
- Environment Awareness.
- Executes WMI queries known to be used for VM detection.
- Many API calls to hide itself.

__MITRE ATT&CK:__

![image](https://github.com/Wortexz/VBS-RAT/assets/26935578/eec4c54b-9a56-4e73-8bfb-fc3e04b81ba1)    

## IOCs    
ESET Detections: 
- __(.VBS):__ VBS/Agent.RZX
- Win32/PSWTool.WebBrowserPassView.I    
- Win32/PSWTool.MailPassView.E    

__SHA-256 (.VBS):__ 1d6d36ec589cbecea839e3b4a5156a35f48436847043f2e1f307f6579e7893e2    
__SHA-256 (WebBrowserPassView):__ D44A5B7B5773BF33674B804C30FC6D25BFFEC3BA594BD317B56651B908612514    
__SHA-256 (MailPassView):__ 5E8BA5A33D8D8CE16CF017E489CE29F911587D72A430ACC6AA14FD5E2F1032E9    

__Network connections:__    
- 178.215.236.110:3051 (jjhfksjh249ved.duckdns[.]org)    
- 178.237.33.50:80 (geoplugin[.]net)    
- 194.59.31.187:80    
- 217.172.98.87:80 (karoonpc[.]com)    

__URL connections:__    
- hxxp://194.59.31.187/tilskrendes[.]toc    
- hxxp://geoplugin.net/json[.]gp    
- hxxp://karoonpc.com/qzntlmtgvccbhmgfidhrwp21[.]bin    
- ssl://178.215.236.110:3051

__Connections are to the compromised servers/websites:__    

![Screenshot 2024-06-07 170727](https://github.com/Wortexz/VBS-RAT/assets/26935578/5be5db0f-d7a2-45b3-bc56-07f263790b88)    
![Screenshot 2024-06-07 170808](https://github.com/Wortexz/VBS-RAT/assets/26935578/d19dcb6a-fcb7-473e-8294-7ceecfc8a9e5)    
![Screenshot 2024-06-07 194102](https://github.com/Wortexz/VBS-RAT/assets/26935578/8dd9d117-665b-4878-a75f-b2acc83ce330)    


__Compromised Vulnerable servers used by attackers__    

![Screenshot 2024-06-07 174246](https://github.com/Wortexz/VBS-RAT/assets/26935578/f4c7d461-91f9-480a-ad46-54237b0087ca)    
![Screenshot 2024-06-07 174340](https://github.com/Wortexz/VBS-RAT/assets/26935578/67d30faf-882e-4b98-8a88-1fdd03bf8582)    

__Process Tree__    
![Screenshot 2024-06-07 202539](https://github.com/Wortexz/VBS-RAT/assets/26935578/a2d0a933-7d79-4fd1-8491-932a15cc8e54)    
![Screenshot 2024-06-07 202558](https://github.com/Wortexz/VBS-RAT/assets/26935578/37c52847-e5f3-469c-b4d4-5a721e912890)    
![Screenshot 2024-06-07 202730](https://github.com/Wortexz/VBS-RAT/assets/26935578/778a332f-da80-4a2b-ac28-d4318f444b5f)    
![Screenshot 2024-06-07 202820](https://github.com/Wortexz/VBS-RAT/assets/26935578/d4165bf2-7cf6-4606-8444-58b1335d1836)    
![Screenshot 2024-06-07 202847](https://github.com/Wortexz/VBS-RAT/assets/26935578/91df77d9-dc39-4f9d-a643-67e81d3abc7f)    





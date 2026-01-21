<img width="1280" height="853" alt="image" src="https://github.com/user-attachments/assets/57b570eb-3759-456c-ad30-5a13cd8bd5ac" />



mindOSINT – Advanced OSINT framework for comprehensive cybersecurity intelligence. Performs secure password exposure checks (Pwned Passwords), IP reputation analysis (Shodan, AbuseIPDB), and malware/hash investigations (VirusTotal). Generates structured reports in PDF, TXT, JSON, and CSV for analysis, auditing, and threat intelligence.
Creator: "Geovane Baptista - AngelMind Security"


* Download / Baixar via git clone:*
  *No terminal : 
  git clone https://github.com/ANGELMIND-SECURITYLABS/mindOSINT.git


  cd mindOSINT
  python3 mindOSINT.py --ip 1.1.1


#Na primeira execução: 

  <img width="447" height="192" alt="image" src="https://github.com/user-attachments/assets/670ff7ab-9c82-4709-bc85-6882129d35a8" />


#Passar as API´s / Enter API´s: virustotal, AbuseIPDB, Shodan
  
  <img width="533" height="243" alt="image" src="https://github.com/user-attachments/assets/876b4134-0f8a-4d8f-89c3-579b1e772182" />




*Uso / Usage*
# Ajuda / Help
python3 mindOSINT.py --help

<img width="792" height="324" alt="image" src="https://github.com/user-attachments/assets/a9c3d8cd-5229-409f-84f9-cc44e188c6bc" />


# Required:
requirements.txt:
requests
shodan
reportlab


<img width="195" height="99" alt="image" src="https://github.com/user-attachments/assets/21d0d2be-4ec9-412d-b652-101ea5334bf0" />




# Verificar senha vazada

  python3 mindOSINT.py --password "Senha@123"

# Consultar IP / IP Analysis

  python3 mindOSINT.py --ip 8.8.8.8
  <img width="805" height="862" alt="image" src="https://github.com/user-attachments/assets/8458fdca-2038-4228-982b-70c487455e36" />




# Consultar hash / Hash reputation
  python3 mindOSINT.py --hash <md5, sha1,sha256>
  python3 mindOSINT.py --hash 5bef35496fcbdbe841c82f4d1ab8b7c2
  <img width="821" height="608" alt="image" src="https://github.com/user-attachments/assets/18edadbe-c2ba-42d8-aef0-e1d45b8063a5" />


#Gerar relatório / Generate Report

  python3 mindOSINT.py --ip 8.8.8.8 --report pdf
  python3 mindOSINT.py --ip 8.8.8.8 --report csv
  python3 mindOSINT.py --ip 8.8.8.8 --report jsom
  python3 mindOSINT.py --ip 8.8.8.8 --report txt
  python3 mindOSINT.py --ip 8.8.8.8 --report all
  <img width="442" height="251" alt="image" src="https://github.com/user-attachments/assets/51aeb39d-582f-4fda-8381-875198c2be26" />

  

#Relatórios / results reports

  Os relatórios são salvos automaticamente em: // Reports are automatically saved to:

reports/

  #Opcional 
  Install dependencies

  After downloading, the user can install the dependencies with:

  pip install -r requirements.txt

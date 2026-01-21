mindOSINT – Advanced OSINT framework for comprehensive cybersecurity intelligence. Performs secure password exposure checks (Pwned Passwords), IP reputation analysis (Shodan, AbuseIPDB), and malware/hash investigations (VirusTotal). Generates structured reports in PDF, TXT, JSON, and CSV for analysis, auditing, and threat intelligence.
Creator: "Geovane Baptista - AngelMind Security"




*Uso / Usage*
# Ajuda / Help
python3 mindOSINT.py --help

<img width="792" height="324" alt="image" src="https://github.com/user-attachments/assets/a9c3d8cd-5229-409f-84f9-cc44e188c6bc" />


Required:
requirements.txt



# Verificar senha vazada
python3 mindOSINT.py --password "Senha@123"

# Consultar IP / IP Analysis
python3 mindOSINT.py --ip 8.8.8.8

# Consultar hash / Hash reputation
python3 mindOSINT.py --hash <SHA256>

#Gerar relatório / Generate Report
python3 mindOSINT.py --ip 8.8.8.8 --report pdf
python3 mindOSINT.py --ip 8.8.8.8 --report csv
python3 mindOSINT.py --ip 8.8.8.8 --report jsom
python3 mindOSINT.py --ip 8.8.8.8 --report txt
python3 mindOSINT.py --ip 8.8.8.8 --report all

#Relatórios / results reports

Os relatórios são salvos automaticamente em: // Reports are automatically saved to:

reports/

#Opcional 
Install dependencies

After downloading, the user can install the dependencies with:

pip install -r requirements.txt

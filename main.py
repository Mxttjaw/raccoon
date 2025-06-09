import sys
import whois
import dns.resolver
import requests
from bs4 import BeautifulSoup
from datetime import datetime
import re
import os
import json
import time
import argparse
from dotenv import load_dotenv, find_dotenv # Modificato: import os e find_dotenv
import google.generativeai as genai 

# Importa le classi necessarie da rich
from rich.console import Console
from rich.theme import Theme
from rich.table import Table
from rich.panel import Panel
from rich import print as rprint # Alias per print di rich, useremo console.print direttamente

# Definisci il tema personalizzato
custom_theme = Theme({
    "info": "dim cyan",
    "warning": "magenta",
    "error": "bold red",
    "success": "bold green",
    "heading": "bold blue",
    "sub_heading": "bold yellow",
    "item": "green",
    "data": "cyan",
    "highlight": "bold magenta",
})

# Inizializza la console di fallback/default per l'output a schermo
# Questa non sarà mai sovrascritta, ma la variabile 'console' nella main sì.
default_console = Console(theme=custom_theme)

# --- Gestione Variabili d'Ambiente (.env) ---
# Trova il .env file, cercando anche nelle directory superiori, e caricalo
dotenv_path = find_dotenv()
if dotenv_path:
    load_dotenv(dotenv_path)
else:
    default_console.print("[warning]Attenzione: File .env non trovato. Le API keys potrebbero non essere caricate.[/warning]")

# Ora puoi accedere alle tue variabili d'ambiente direttamente tramite os.getenv()
# Non hai più bisogno di 'config = dotenv_values(".env")' o di 'config.get("...")'
# Usa direttamente os.getenv("NOME_VARIABILE")

# --- Funzioni di Raccolta Dati OSINT ---

def get_whois_info(domain, console_instance):
    try:
        w = whois.whois(domain)

        info = {
            'registrant': None,
            'emails': [],
            'creation_date': None,
            'expiration_date': None
        }

        if w.name:
            info['registrant'] = ", ".join(w.name) if isinstance(w.name, list) else w.name
        elif w.org:
            info['registrant'] = ", ".join(w.org) if isinstance(w.org, list) else w.org
        elif w.registrant_name:
            info['registrant'] = ", ".join(w.registrant_name) if isinstance(w.registrant_name, list) else w.registrant_name


        if w.emails:
            info['emails'] = w.emails if isinstance(w.emails, list) else [w.emails]

        if w.creation_date:
            info['creation_date'] = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date

        if w.expiration_date:
            info['expiration_date'] = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date

        return info

    except whois.parser.PywhoisError as e:
        console_instance.print(f"[error]Errore WHOIS per {domain}: {e}[/error]")
        return None
    except Exception as e:
        console_instance.print(f"[error]Si è verificato un errore inatteso durante il lookup WHOIS per {domain}: {e}[/error]")
        return None


def get_dns_records(domain, console_instance):
    dns_records = {
        'A': [],
        'MX': [],
        'TXT': [],
        'NS': []
    }

    record_types = ['A', 'MX', 'TXT', 'NS']

    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            for rdata in answers:
                if record_type == 'A':
                    dns_records['A'].append(str(rdata))
                elif record_type == 'MX':
                    dns_records['MX'].append(f"Preference: {rdata.preference}, Host: {rdata.exchange}")
                elif record_type == 'TXT':
                    txt_data = b''.join(rdata.strings).decode('utf-8')
                    dns_records['TXT'].append(txt_data)
                elif record_type == 'NS':
                    dns_records['NS'].append(str(rdata))
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            console_instance.print(f"[warning]Dominio '{domain}' non esiste o non ha record DNS per {record_type}.[/warning]")
            return None
        except dns.resolver.LifetimeTimeout:
            console_instance.print(f"[error]Timeout durante la risoluzione DNS per {domain} (tipo {record_type}).[/error]")
            return None
        except Exception as e:
            console_instance.print(f"[error]Si è verificato un errore inatteso durante il lookup DNS per {domain} (tipo {record_type}): {e}[/error]")
            return None
    return dns_records


def get_subdomains_from_crtsh(domain, console_instance):
    url = f"https://crt.sh/?q=%25.{domain}"
    subdomains = set()

    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()

        soup = BeautifulSoup(response.text, 'html.parser')

        tables = soup.find_all('table')
        for table in tables:
            rows = table.find_all('tr')
            for row in rows:
                cells = row.find_all('td')
                if len(cells) < 4:
                    continue

                common_names_cell = cells[4]
                names_raw = common_names_cell.get_text(separator=' ', strip=True)

                for name_entry in names_raw.split():
                    name_entry = name_entry.strip()
                    if name_entry.endswith(f".{domain}") or name_entry == domain:
                        if name_entry.startswith('*.'):
                            name_entry = name_entry[2:]
                        subdomains.add(name_entry)

    except requests.exceptions.RequestException as e:
        console_instance.print(f"[error]Errore di rete durante lo scraping di crt.sh per {domain}: {e}[/error]")
        return []
    except Exception as e:
        console_instance.print(f"[error]Si è verificato un errore inatteso durante lo scraping di crt.sh per {domain}: {e}[/error]")
        return []

    sorted_subdomains = sorted(list(subdomains))
    return sorted_subdomains


def get_ip_geolocation_info(domain, console_instance):
    ip_address = None
    try:
        answers = dns.resolver.resolve(domain, 'A')
        if answers:
            ip_address = str(answers[0])
        else:
            console_instance.print(f"[warning]Nessun indirizzo IP (record A) trovato per {domain}.[/warning]")
            return None
    except dns.resolver.NoAnswer:
        console_instance.print(f"[warning]Nessun record A trovato per '{domain}'.[/warning]")
        return None
    except dns.resolver.NXDOMAIN:
        console_instance.print(f"[warning]Dominio '{domain}' non esiste.[/warning]")
        return None
    except dns.resolver.LifetimeTimeout:
        console_instance.print(f"[error]Timeout durante la risoluzione DNS per l'IP di {domain}.[/error]")
        return None
    except Exception as e:
        console_instance.print(f"[error]Si è verificato un errore durante la risoluzione dell'IP per {domain}: {e}[/error]")
        return None

    if not ip_address:
        return None

    api_url = f"https://ipinfo.io/{ip_address}/json"
    try:
        response = requests.get(api_url, timeout=5)
        response.raise_for_status()
        data = response.json()

        info = {
            'ip': data.get('ip'),
            'asn': data.get('org', '').split(' ', 1)[0] if data.get('org') else 'N/A',
            'isp': data.get('org', '').split(' ', 1)[1] if len(data.get('org', '').split(' ', 1)) > 1 else data.get('org', 'N/A'),
            'country': data.get('country', 'N/A'),
            'city': data.get('city', 'N/A')
        }
        return info

    except requests.exceptions.RequestException as e:
        console_instance.print(f"[error]Errore di rete durante la query a ipinfo.io per l'IP {ip_address}: {e}[/error]")
        return None
    except ValueError:
        console_instance.print(f"[error]Errore: Risposta non JSON da ipinfo.io per l'IP {ip_address}.[/error]")
        return None
    except Exception as e:
        console_instance.print(f"[error]Si è verificato un errore inatteso durante il recupero delle informazioni IP per {ip_address}: {e}[/error]")
        return None


def search_for_emails_and_docs(domain, console_instance):
    found_emails = set()
    found_documents = set()
    results = {
        'emails': [],
        'documents': []
    }

    headers = {
        'User-Agent': 'osint_scanner_domain_search (gpane947@gmail.com)'
    }

    email_query = f'site:{domain} "@.{domain}"'
    email_url = f"https://duckduckgo.com/html/?q={requests.utils.quote(email_query)}"

    try:
        console_instance.print(f"[info]Cercando email su DuckDuckGo con query: '{email_query}'...[/info]")
        response = requests.get(email_url, headers=headers, timeout=15)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')

        for link in soup.find_all('a', class_='result__a'):
            href = link.get('href')
            if href:
                email_pattern = r'[a-zA-Z0-9._%+-]+@' + re.escape(domain)
                emails_in_link = re.findall(email_pattern, href, re.IGNORECASE)
                if emails_in_link:
                    for email in emails_in_link:
                        found_emails.add(email.lower())

        body_text = soup.get_text()
        email_pattern = r'[a-zA-Z0-9._%+-]+@' + re.escape(domain) + r'\b'
        emails_in_body = re.findall(email_pattern, body_text, re.IGNORECASE)
        if emails_in_body:
            for email in emails_in_body:
                found_emails.add(email.lower())


    except requests.exceptions.RequestException as e:
        console_instance.print(f"[error]Errore di rete durante la ricerca email su DuckDuckGo per {domain}: {e}[/error]")
    except Exception as e:
        console_instance.print(f"[error]Si è verificato un errore inatteso durante la ricerca email su DuckDuckGo per {domain}: {e}[/error]")

    doc_query_pdf = f'site:{domain} filetype:pdf'
    doc_query_docx = f'site:{domain} filetype:docx'

    doc_urls = [
        f"https://duckduckgo.com/html/?q={requests.utils.quote(doc_query_pdf)}",
        f"https://duckduckgo.com/html/?q={requests.utils.quote(doc_query_docx)}"
    ]

    for doc_url in doc_urls:
        try:
            console_instance.print(f"[info]Cercando documenti su DuckDuckGo con URL: '{doc_url}'...[/info]")
            response = requests.get(doc_url, headers=headers, timeout=15)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')

            for link in soup.find_all('a', class_='result__a'):
                href = link.get('href')
                if href and (href.lower().endswith('.pdf') or href.lower().endswith('.docx')):
                    if domain in href:
                        found_documents.add(href)
        except requests.exceptions.RequestException as e:
            console_instance.print(f"[error]Errore di rete durante la ricerca documenti su DuckDuckGo (URL: {doc_url}): {e}[/error]")
        except Exception as e:
            console_instance.print(f"[error]Si è verificato un errore inatteso durante la ricerca documenti su DuckDuckGo (URL: {doc_url}): {e}[/error]")

    results['emails'] = sorted(list(found_emails))
    results['documents'] = sorted(list(found_documents))
    return results


def search_person_info(person_name, console_instance):
    found_articles = set()
    found_emails = set()
    found_social_profiles = set()

    headers = {
        'User-Agent': 'osint_scanner_person_search (gpane947@gmail.com)',
        'Content-Type': 'application/json'
    }

    queries = [
        f'"{person_name}" intitle:news',
        f'"{person_name}" email',
        f'"{person_name}" contact',
        f'"{person_name}" site:linkedin.com',
        f'"{person_name}" site:twitter.com',
        f'"{person_name}" site:facebook.com',
        f'"{person_name}" site:instagram.com',
        f'"{person_name}" site:github.com',
        f'"{person_name}" site:medium.com',
        f'"{person_name}" site:reddit.com',
        f'"{person_name}" curriculum vitae',
        f'"{person_name}" "bio"'
    ]

    social_media_domains = [
        'linkedin.com', 'twitter.com', 'facebook.com', 'instagram.com',
        'github.com', 'reddit.com', 'medium.com'
    ]

    for query_text in queries:
        encoded_query = requests.utils.quote(query_text)
        search_url = f"https://duckduckgo.com/html/?q={encoded_query}"
        console_instance.print(f"[info]Cercando su DuckDuckGo con query: '{query_text}'...[/info]")

        try:
            response = requests.get(search_url, headers=headers, timeout=15)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')

            for link in soup.find_all('a', class_='result__a'):
                href = link.get('href')
                title = link.get_text()

                if not href:
                    continue

                email_pattern = r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
                found_emails_in_link = re.findall(email_pattern, href, re.IGNORECASE)
                if found_emails_in_link:
                    for email in found_emails_in_link:
                        found_emails.add(email.lower())
                
                is_social = False
                for social_domain in social_media_domains:
                    if social_domain in href:
                        found_social_profiles.add(href)
                        is_social = True
                        break
                
                if not is_social:
                    if person_name.lower() in title.lower() or person_name.lower() in href.lower():
                        found_articles.add(href)

            body_text = soup.get_text()
            email_pattern = r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
            emails_in_body = re.findall(email_pattern, body_text, re.IGNORECASE)
            if emails_in_body:
                for email in emails_in_body:
                    found_emails.add(email.lower())

        except requests.exceptions.RequestException as e:
            console_instance.print(f"[error]Errore di rete durante la ricerca su DuckDuckGo per '{query_text}': {e}[/error]")
        except Exception as e:
            console_instance.print(f"[error]Si è verificato un errore inatteso durante la ricerca su DuckDuckGo per '{query_text}': {e}[/error]")
        
        time.sleep(0.5)

    return {
        'articles': sorted(list(found_articles)),
        'emails': sorted(list(found_emails)),
        'social_profiles': sorted(list(found_social_profiles))
    }


def find_social_profiles_by_username(usernames_to_check, console_instance):
    found_profiles = {}
    headers = {
        'User-Agent': 'osint_scanner_social_profile_checker (gpane947@gmail.com)',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Connection': 'keep-alive'
    }

    social_platforms = [
        ("Instagram", "https://www.instagram.com/{}/", "Page Not Found"),
        ("Twitter", "https://twitter.com/{}/", "This account doesn't exist"),
        ("TikTok", "https://www.tiktok.com/@{}/", "Couldn't find this account"),
        ("GitHub", "https://github.com/{}/", "page not found"),
        ("Reddit", "https://www.reddit.com/user/{}/", "Sorry, nobody on Reddit goes by that username."),
        ("Pinterest", "https://www.pinterest.it/{}/", "Not Found"),
        ("Snapchat", "https://www.snapchat.com/add/{}/", "Page not found"),
        ("Spotify", "https://open.spotify.com/user/{}/", "Page not found"), # Questo URL potrebbe non funzionare come previsto per la ricerca diretta
        ("Twitch", "https://www.twitch.tv/{}/", "Sorry. Unless you’ve got a time machine"),
        ("YouTube (User)", "https://www.youtube.com/user/{}/", "This channel doesn't exist"), # Questo URL potrebbe non funzionare come previsto per la ricerca diretta
        ("YouTube (Channel)", "https://www.youtube.com/channel/{}/", "This channel does not exist"), # Questo URL potrebbe non funzionare come previsto per la ricerca diretta
    ]

    for username in usernames_to_check:
        console_instance.print(f"\n[sub_heading]--- Ricerca profili per username: '{username}' ---[/sub_heading]")
        for platform_name, url_pattern, not_found_string in social_platforms:
            profile_url = url_pattern.format(username)
            try:
                console_instance.print(f"  Verificando [item]{platform_name}[/item]: [data]{profile_url}[/data]...", end=' ')
                
                # Usiamo GET per controllare il contenuto del body se la stringa di non esistenza è definita
                full_response = requests.get(profile_url, headers=headers, timeout=7)
                
                if not_found_string and not_found_string.lower() in full_response.text.lower() or full_response.status_code == 404:
                    console_instance.print("[warning]NON TROVATO (404 o stringa errore)[/warning]")
                    continue
                elif full_response.status_code == 200:
                    if platform_name not in found_profiles:
                        found_profiles[platform_name] = []
                    found_profiles[platform_name].append(full_response.url)
                    console_instance.print("[success]TROVATO![/success]")
                elif 300 <= full_response.status_code < 400: # Redirect
                    console_instance.print(f"[info]REDIRECT ({full_response.status_code}) -> {full_response.headers.get('Location', 'N/A')}[/info]")
                else:
                    console_instance.print(f"[error]ERRORE/ALTRO STATO: {full_response.status_code}[/error]")

            except requests.exceptions.RequestException as e:
                console_instance.print(f"[error]ERRORE DI RETE: {e}[/error]")
            except Exception as e:
                console_instance.print(f"[error]ERRORE INATTESO: {e}[/error]")
            
            time.sleep(0.7)

    return found_profiles

def generate_common_usernames(full_name):
    parts = full_name.lower().split()
    usernames = set()

    if not parts:
        return []

    first_name = parts[0]
    last_name = parts[-1] if len(parts) > 1 else ""

    usernames.add(first_name)
    if last_name:
        usernames.add(last_name)
        usernames.add(f"{first_name}{last_name}")
        usernames.add(f"{first_name}.{last_name}")
        usernames.add(f"{first_name}_{last_name}")
        usernames.add(f"{first_name[0]}{last_name}")
        usernames.add(f"{last_name}{first_name[0]}")
        usernames.add(f"{first_name}-{last_name}")
    
    for u in list(usernames):
        usernames.add(f"{u}1")
        usernames.add(f"{u}01")
        usernames.add(f"{u}x")

    return sorted(list(usernames))

# ---
## Funzioni per la Generazione del Report LLM
# ---

### LLM API (Gemini)

def summarize_results_with_gemini_api(all_results, target_type, target_value, console_instance):
    """
    Prende tutti i risultati OSINT raccolti e li invia a un LLM API di Google (Gemini)
    per generare un report leggibile e suggerimenti di attacco.

    Args:
        all_results (dict): Un dizionario contenente tutti i risultati delle scansioni.
        target_type (str): Il tipo di target ("domain" o "person").
        target_value (str): Il dominio o il nome/username della persona.
        console_instance (Console): L'istanza della console per l'output.
    """
    gemini_api_key = os.getenv("GEMINI_API_KEY") # Modificato: usa os.getenv()
    if not gemini_api_key:
        console_instance.print("\n[error]Chiave API Gemini non trovata. Assicurati di averla impostata come GEMINI_API_KEY nel file .env.[/error]")
        return

    genai.configure(api_key=gemini_api_key)

    model_name_to_use = "gemini-1.5-flash" 
    
    try:
        model = genai.GenerativeModel(model_name_to_use)
        console_instance.print(f"[info]Utilizzo il modello Gemini specificato: {model_name_to_use}[/info]")

    except Exception as e:
        console_instance.print(f"\n[error]Errore durante il caricamento del modello '{model_name_to_use}': {e}[/error]")
        console_instance.print("[error]Assicurati che il modello specificato sia disponibile per la tua API Key e regione.[/error]")
        return

    formatted_results = []
    if target_type == "domain":
        formatted_results.append(f"OSINT Report for Domain: {target_value}\n")
        if all_results.get('whois'):
            formatted_results.append("\n--- WHOIS Information ---")
            for key, value in all_results['whois'].items():
                if value:
                    formatted_results.append(f"{key.replace('_', ' ').title()}: {value}")
        if all_results.get('dns'):
            formatted_results.append("\n--- DNS Records ---")
            for record_type, records in all_results['dns'].items():
                if records:
                    formatted_results.append(f"  {record_type}: {', '.join(records)}")
        if all_results.get('subdomains'):
            formatted_results.append("\n--- Subdomains Found ---")
            formatted_results.append(f"{', '.join(all_results['subdomains'])}")
        if all_results.get('ip_geolocation'):
            formatted_results.append("\n--- IP Geolocation ---")
            for key, value in all_results['ip_geolocation'].items():
                if value:
                    formatted_results.append(f"{key.replace('_', ' ').title()}: {value}")
        if all_results.get('emails_docs'):
            if all_results['emails_docs'].get('emails'):
                formatted_results.append("\n--- Emails Found ---")
                formatted_results.append(f"{', '.join(all_results['emails_docs']['emails'])}")
            if all_results['emails_docs'].get('documents'):
                formatted_results.append("\n--- Public Documents Found ---")
                formatted_results.append(f"{', '.join(all_results['emails_docs']['documents'])}")

    elif target_type == "person":
        formatted_results.append(f"OSINT Report for Person: {target_value}\n")
        if all_results.get('person_info_ddg'):
            if all_results['person_info_ddg'].get('articles'):
                formatted_results.append("\n--- Articles and General Mentions (DuckDuckGo) ---")
                formatted_results.append(f"{', '.join(all_results['person_info_ddg']['articles'])}")
            if all_results['person_info_ddg'].get('emails'):
                formatted_results.append("\n--- Emails Found (DuckDuckGo) ---")
                formatted_results.append(f"{', '.join(all_results['person_info_ddg']['emails'])}")
        if all_results.get('social_profiles_direct'):
            formatted_results.append("\n--- Social Profiles Found (Direct Check) ---")
            for platform, urls in all_results['social_profiles_direct'].items():
                formatted_results.append(f"  {platform}: {', '.join(urls)}")
        if all_results.get('potential_usernames'):
            formatted_results.append("\n--- Potential Usernames Tested ---")
            formatted_results.append(f"{', '.join(all_results['potential_usernames'])}")

    full_results_string = "\n".join(formatted_results)

    prompt = f"""
Genera un report di Open Source Intelligence (OSINT) e suggerimenti di pentesting **esclusivamente in italiano**.

Sei un esperto di Open Source Intelligence (OSINT) e un pentester etico.
Hai condotto una scansione OSINT su un obiettivo e hai raccolto le seguenti informazioni:

{full_results_string}

Analizza queste informazioni e genera un report conciso e leggibile.
Il report deve contenere le seguenti sezioni:

1.  **Riepilogo dei Risultati:** Un riepilogo chiaro e conciso di tutte le informazioni rilevanti trovate. Evita di ripetere i dati grezzi, sintetizza l'importanza.
2.  **Vettori di Attacco Potenziali e Suggerimenti per il Pentesting:** Basandoti sulle informazioni, suggerisci possibili aree di attacco o prossimi passi per un pentester. Pensa a vettori di ingegneria sociale, attacchi a siti web, raccolta di credenziali, ecc. Sii specifico dove possibile.

Formato del Report:
Inizia con un titolo chiaro. Utilizza intestazioni di sezione e elenchi puntati per chiarezza.
Alla fine del report, includi esattamente la frase "numero tentativi: 16" e ringrazia l'utente per la splendida giornata passata insieme.
"""
    console_instance.print(f"\n[sub_heading]--- Generazione Report LLM (Gemini API) in corso... (potrebbe richiedere tempo) ---[/sub_heading]")
    try:
        response = model.generate_content(prompt, request_options={"timeout": 120})
        
        if response and response.text:
            console_instance.print(Panel(f"[bold white on blue]          OSINT Summary & Pentesting Report (Powered by Gemini API)         [/bold white on blue]", expand=False))
            # Usiamo print direttamente sulla console_instance per il testo generato da Gemini
            console_instance.print(response.text) 
            console_instance.print(Panel(f"[bold white on blue]          Fine Report LLM         [/bold white on blue]", expand=False))
        else:
            console_instance.print("[error]Errore: Nessuna risposta testuale valida dall'LLM di Gemini.[/error]")
            if hasattr(response, 'prompt_feedback') and response.prompt_feedback.block_reason:
                console_instance.print(f"[error]Bloccato da policy di sicurezza: {response.prompt_feedback.block_reason}[/error]")
            elif hasattr(response, 'candidates') and not response.candidates:
                console_instance.print(f"[error]Nessun candidato generato. Possibile problema di sicurezza o contenuto.[/error]")
            else:
                console_instance.print(f"[error]Dettagli risposta: {response}[/error]")


    except Exception as e:
        console_instance.print(f"\n[error]Errore inatteso durante la generazione del report LLM con Gemini API: {e}[/error]")
        console_instance.print("[error]Assicurati che la tua GEMINI_API_KEY sia corretta e che il modello 'gemini-pro' sia disponibile.[/error]")

# ---
## Funzione Principale (main)
# ---

def main():
    # ASCII Art Banner per RACCOON (corretto)
    raccoon_banner = r"""
██████╗  █████╗  ██████╗ ██████╗ ██████╗  ██████╗ ███╗   ██╗
██╔══██╗██╔══██╗██╔════╝██╔════╝██╔═══██╗██╔═══██╗████╗  ██║
██████╔╝███████║██║     ██║     ██║   ██║██║   ██║██╔██╗ ██║
██╔══██╗██╔══██║██║     ██║     ██║   ██║██║   ██║██║╚██╗██║
██║  ██║██║  ██║╚██████╗╚██████╗╚██████╔╝╚██████╔╝██║ ╚████║
╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝
                                                            
               [bold blue]Open Source Intelligence Tool[/bold blue]
    """

    parser = argparse.ArgumentParser(description="OSINT Scanner Tool - RACCOON.")
    parser.add_argument('target', nargs='?', help="Domain to scan (e.g., example.com) or use with --person/--username.")
    parser.add_argument('--person', type=str, help="Full name of a person to scan (e.g., \"John Doe\").")
    parser.add_argument('--username', type=str, help="Specific username to scan social profiles for (e.g., myusername).")
    parser.add_argument('-o', '--output', type=str, help="Specify an output file to save results (e.g., report.txt). Output will not be displayed in console.")
    
    args = parser.parse_args()

    # Gestione dell'output in file
    output_file = None
    if args.output:
        try:
            output_file = open(args.output, 'w', encoding='utf-8')
            # Creiamo una nuova istanza di Console che scriverà sul file, usando custom_theme
            console = Console(file=output_file, theme=custom_theme) 
            console.print(f"--- RACCOON OSINT Report for {args.target or args.person or args.username} ---")
            console.print(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            # Informiamo l'utente che l'output è stato reindirizzato
            default_console.print(f"[bold green]Output reindirizzato a:[/bold green] [yellow]{args.output}[/yellow] (Nessun output a console)\n")
        except IOError as e:
            default_console.print(f"[error]Errore: Impossibile aprire il file di output '{args.output}': {e}[/error]")
            sys.exit(1)
    else:
        # Se non c'è un file di output, usiamo la console predefinita (stdout)
        console = default_console
        console.print(raccoon_banner, style="bold green")
        console.print("[bold cyan]RACCOON - Il tuo fidato partner nell'OSINT.[/bold cyan]\n")


    all_collected_results = {} # Dizionario per conservare tutti i risultati per il report finale

    # Passiamo l'istanza della console a tutte le funzioni di raccolta dati
    if args.person:
        person_full_name = args.person
        all_collected_results['target_type'] = "person"
        all_collected_results['target_value'] = person_full_name
        console.print(f"[heading]Ricerca per persona (nome completo): {person_full_name}[/heading]\n")
        
        console.print(Panel("[warning]ATTENZIONE: La ricerca di persone automatica può essere imprecisa e incompleta.\nLe informazioni trovate dipendono dalla loro disponibilità pubblica e dall'indicizzazione dei motori di ricerca.\nPotrebbero esserci molti falsi positivi o risultati irrilevanti per nomi comuni.[/warning]", title="[bold yellow]Avviso[/bold yellow]", expand=False))

        potential_usernames = generate_common_usernames(person_full_name)
        all_collected_results['potential_usernames'] = potential_usernames
        if not potential_usernames:
            console.print("[warning]Nessun potenziale username generato dal nome fornito.[/warning]")
        else:
            console.print(f"[info]Potenziali username generati da testare: {', '.join(potential_usernames)}[/info]\n")

        person_results_ddg = search_person_info(person_full_name, console) # Passa console
        all_collected_results['person_info_ddg'] = person_results_ddg

        console.print(f"\n[sub_heading]--- Articoli e Menzioni Generiche trovate (DuckDuckGo) ---[/sub_heading]")
        if person_results_ddg['articles']:
            for url in person_results_ddg['articles']:
                console.print(f"- [item]{url}[/item]")
        else:
            console.print("[info]Nessun articolo o menzione generica trovata.[/info]")
        console.print("---------------------------------------------------------")

        console.print(f"\n[sub_heading]--- Email trovate (DuckDuckGo) ---[/sub_heading]")
        if person_results_ddg['emails']:
            for email in person_results_ddg['emails']:
                console.print(f"- [item]{email}[/item]")
        else:
            console.print("[info]Nessuna email trovata.[/info]")
        console.print("----------------------------------")

        console.print(f"\n[sub_heading]--- Ricerca diretta profili social per username ---[/sub_heading]")
        found_social_profiles_direct = find_social_profiles_by_username(potential_usernames, console) # Passa console
        all_collected_results['social_profiles_direct'] = found_social_profiles_direct
        
        if found_social_profiles_direct:
            for platform, urls in found_social_profiles_direct.items():
                console.print(f"  [data]{platform}[/data]:")
                for url in urls:
                    console.print(f"    - [item]{url}[/item]")
        else:
            console.print("[info]Nessun profilo social trovato tramite verifica diretta per i potenziali username.[/info]")
        console.print("----------------------------------------------------")

    elif args.username:
        target_username = args.username
        all_collected_results['target_type'] = "person"
        all_collected_results['target_value'] = target_username
        all_collected_results['potential_usernames'] = [target_username]
        console.print(f"[heading]Ricerca profili social per username: '{target_username}'[/heading]\n")

        found_social_profiles_direct = find_social_profiles_by_username([target_username], console) # Passa console
        all_collected_results['social_profiles_direct'] = found_social_profiles_direct

        if found_social_profiles_direct:
            console.print(f"\n[sub_heading]--- Profili Social trovati tramite verifica diretta ---[/sub_heading]")
            for platform, urls in found_social_profiles_direct.items():
                console.print(f"  [data]{platform}[/data]:")
                for url in urls:
                    console.print(f"    - [item]{url}[/item]")
            console.print("------------------------------------------------------")
        else:
            console.print("[info]Nessun profilo social trovato tramite verifica diretta per l'username specificato.[/info]")
        console.print("----------------------------------------------------")

    elif args.target: # Logica per la scansione del dominio
        domain = args.target
        all_collected_results['target_type'] = "domain"
        all_collected_results['target_value'] = domain
        console.print(f"[heading]Scansione dominio: {domain}[/heading]\n")

        # WHOIS Info
        console.print("[sub_heading]Esecuzione del lookup WHOIS...[/sub_heading]")
        whois_info = get_whois_info(domain, console) # Passa console
        all_collected_results['whois'] = whois_info
        if whois_info:
            table = Table(title="--- Informazioni WHOIS ---", header_style="bold magenta")
            table.add_column("Dettaglio", style="data")
            table.add_column("Valore", style="item")
            table.add_row("Registrante", whois_info.get('registrant') or "None")
            table.add_row("Email di contatto", ", ".join(whois_info.get('emails')) if whois_info.get('emails') else "N/A")
            table.add_row("Data di creazione", str(whois_info.get('creation_date')) or "N/A")
            table.add_row("Data di scadenza", str(whois_info.get('expiration_date')) or "N/A")
            console.print(table)
        console.print("--------------------------\n")

        # DNS Records
        console.print("[sub_heading]Esecuzione del lookup DNS...[/sub_heading]")
        dns_records = get_dns_records(domain, console) # Passa console
        all_collected_results['dns'] = dns_records
        if dns_records:
            table = Table(title="--- Informazioni DNS ---", header_style="bold magenta")
            table.add_column("Record Type", style="data")
            table.add_column("Records", style="item")
            for record_type, records in dns_records.items():
                if records:
                    table.add_row(record_type, "\n".join([f"- {rec}" for rec in records]))
            console.print(table)
        console.print("------------------------\n")

        # Subdomains from crt.sh
        console.print("[sub_heading]Ricerca sottodomini su crt.sh...[/sub_heading]")
        subdomains = get_subdomains_from_crtsh(domain, console) # Passa console
        all_collected_results['subdomains'] = subdomains
        if subdomains:
            console.print(f"[info]Sottodomini trovati per {domain} su crt.sh:[/info]")
            for s in subdomains:
                console.print(f"- [item]{s}[/item]")
        else:
            console.print(f"[warning]Nessun sottodominio trovato per {domain} su crt.sh o si è verificato un errore.[/warning]")
        console.print("-------------------------------------------\n")

        # IP Geolocation
        console.print("[sub_heading]Recupero informazioni IP e geolocalizzazione...[/sub_heading]")
        ip_geo_info = get_ip_geolocation_info(domain, console) # Passa console
        all_collected_results['ip_geolocation'] = ip_geo_info
        if ip_geo_info:
            table = Table(title="--- Informazioni IP e Geolocalizzazione ---", header_style="bold magenta")
            table.add_column("Dettaglio", style="data")
            table.add_column("Valore", style="item")
            table.add_row("Indirizzo IP", ip_geo_info.get('ip') or "N/A")
            table.add_row("ASN", ip_geo_info.get('asn') or "N/A")
            table.add_row("ISP", ip_geo_info.get('isp') or "N/A")
            table.add_row("Paese", ip_geo_info.get('country') or "N/A")
            table.add_row("Città", ip_geo_info.get('city') or "N/A")
            console.print(table)
        console.print("-------------------------------------------\n")

        # Email & Public Docs Search
        console.print("[sub_heading]Ricerca email e documenti pubblici (tramite DuckDuckGo)...[/sub_heading]")
        emails_docs_results = search_for_emails_and_docs(domain, console) # Passa console
        all_collected_results['emails_docs'] = emails_docs_results

        console.print(f"\n[sub_heading]--- Email trovate ---[/sub_heading]")
        if emails_docs_results['emails']:
            for email in emails_docs_results['emails']:
                console.print(f"- [item]{email}[/item]")
        else:
            console.print("[info]Nessuna email trovata.[/info]")
        console.print("----------------------\n")

        console.print(f"\n[sub_heading]--- Documenti pubblici trovati ---[/sub_heading]")
        if emails_docs_results['documents']:
            for doc in emails_docs_results['documents']:
                console.print(f"- [item]{doc}[/item]")
        else:
            console.print("[info]Nessun documento pubblico trovato.[/info]")
        console.print("---------------------------------\n")

    else:
        # Messaggio di aiuto se non viene fornito nessun argomento
        console.print("[error]Errore: Devi fornire un dominio (--target <dominio>), un nome persona (--person \"Nome Cognome\") o un username (--username <username>).[/error]")
        parser.print_help(file=console.file) # Stampa l'help nella console corretta
        sys.exit(1) # Esci con un codice di errore

    # --- Generazione del Report LLM ---
    if all_collected_results:
        console.print(Panel(f"[bold green]╭───────────────────────────────╮\n│ Inizio Generazione Report LLM │\n╰───────────────────────────────╯[/bold green]", expand=False))
        
        # Aggiungi un messaggio informativo per l'utente sulla API key
        if os.getenv("GEMINI_API_KEY"):
            console.print("[info]Utilizzo LLM API (Gemini). Il modello sarà auto-rilevato.[/info]")
        else:
            console.print("[warning]La chiave API Gemini non è stata trovata. La generazione del report LLM verrà saltata.[/warning]")

        # Chiama la funzione per generare il report LLM
        # Assicurati che gemini_api_key sia disponibile qui o che la funzione la carichi
        if os.getenv("GEMINI_API_KEY"): # Controlla nuovamente la chiave prima di chiamare
            summarize_results_with_gemini_api(
                all_collected_results,
                all_collected_results['target_type'],
                all_collected_results['target_value'],
                console # Passa l'istanza della console
            )
        console.print(Panel(f"[bold green]╭─────────────────────────────╮\n│ Fine Generazione Report LLM │\n╰─────────────────────────────╯[/bold green]", expand=False))

    # Chiudi il file di output se è stato usato
    if output_file:
        output_file.close()

if __name__ == "__main__":
    main()
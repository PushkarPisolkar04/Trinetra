import sys
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from core.file_id import Gatekeeper

console = Console()

def main():
    console.print(Panel("[bold red]TRINETRA[/bold red] - [bold white]The Universal Static Analyzer[/bold white]", subtitle="v1.0"))
    
    if len(sys.argv) < 2:
        console.print("[yellow]Usage: python main.py <file_path>[/yellow]")
        return

    file_path = sys.argv[1]
    console.print(f"[cyan]Scanning target:[/cyan] {file_path}")

    # Step 1: The Gatekeeper (Identification)
    gatekeeper = Gatekeeper()
    file_type = gatekeeper.identify(file_path)
    
    # Step 2: Karma (Hashing)
    from core.hasher import Karma
    karma = Karma()
    hashes = karma.calculate_hashes(file_path)
    
    # Step 3: Vani (Strings)
    from modules.ioc_extractor import Vani
    vani = Vani()
    iocs = vani.hunt_iocs(file_path)

    # Step 4: Kundli (PE Analysis)
    from modules.pe_analyzer import Kundli
    kundli = Kundli()
    pe_report = kundli.analyze_pe(file_path)

    # Step 5: Kagaz (Archive/Doc Analysis)
    from modules.archive_scanner import Kagaz
    kagaz = Kagaz()
    archive_report = kagaz.check_zip(file_path)
    
    # Step 6: Drishti (Image Forensics)
    from modules.image_forensics import Drishti
    drishti = Drishti()
    stego_report = drishti.analyze_image(file_path, file_type)

    # Step 7: Mayajaal (Deobfuscation)
    from modules.deobfuscator import Mayajaal
    maya = Mayajaal()
    maya_report = maya.lift_curse(file_path)

    # Step 8: Chitragupta (AI/Heuristic)
    from modules.ai_engine import Chitragupta
    chitra = Chitragupta()
    
    # We use data from previous steps for the judgment
    entropy_score = pe_report["dosha_score"] if pe_report else 0
    dangerous_count = len(pe_report["imports"]) if pe_report else 0
    strings_found = len(iocs["ips"]) + len(iocs["urls"])
    
    ai_score = chitra.heuristic_judgment(entropy_score, dangerous_count, strings_found > 0)
    
    # Display Results
    table = Table(title="Trinetra Examination Results")
    table.add_column("Module", style="cyan")
    table.add_column("Result", style="green")
    
    table.add_row("Gatekeeper", f"{file_type}")
    table.add_row("MD5 Hash", hashes.get("md5", "Error"))
    table.add_row("SHA256", hashes.get("sha256", "Error"))
    
    table.add_row("Chitragupta", f"[bold magenta]Threat Score: {ai_score}/100[/bold magenta]")
    
    if pe_report:
        table.add_row("PE Analyzer", "[bold red]Detected Windows Executable[/bold red]")
        table.add_row("Dosha Score", str(round(pe_report["dosha_score"], 2)))
        for sect in pe_report["suspicious_sections"]:
            table.add_row("Packed Section", f"{sect['name']} (Entropy: {round(sect['entropy'], 2)})")
        if pe_report["imports"]:
            table.add_row("Dangerous Imports", ", ".join(pe_report["imports"][:3]))

    if archive_report:
        table.add_row("Archive Scanner", "[bold yellow]Zip Archive Detected[/bold yellow]")
        if archive_report["zip_bomb_risk"]:
            table.add_row("Risk", "[bold red]POTENTIAL ZIP BOMB[/bold red]")
        if archive_report["contains_executable"]:
            table.add_row("Contents", "[bold red]Contains Executable Files![/bold red]")

    if stego_report["has_hidden_data"]:
        table.add_row("Drishti (Stego)", "[bold red]Hidden Data Detected![/bold red]")
        table.add_row("Suspicion Level", stego_report["stego_suspicion"])
    
    if maya_report["base64_payloads"]:
        table.add_row("Mayajaal (Deobfuscator)", f"[bold red]Found {len(maya_report['base64_payloads'])} Base64 Payloads[/bold red]")
        table.add_row("Payload Preview", maya_report["base64_payloads"][0])

    if maya_report["xor_detected"]:
        table.add_row("Mayajaal (XOR)", "[bold red]XOR Encryption Detected[/bold red]")
        table.add_row("Decrypted Sample", maya_report["xor_detected"][0]["snippet"])

    if iocs["ips"]:
        table.add_row("Suspicious IPs", ", ".join(iocs["ips"][:5]))
    if iocs["urls"]:
        table.add_row("Suspicious URLs", ", ".join(iocs["urls"][:5]))
    
    console.print(table)
    
    # VT Link
    if "sha256" in hashes:
        console.print(f"\n[bold yellow]VirusTotal Link:[/bold yellow] {karma.check_virustotal(hashes['sha256'])}")

if __name__ == "__main__":
    main()

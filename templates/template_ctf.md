# 🚩 [Nom de la Machine/Challenge] - [Plateforme : HackTheBox/Root-Me]

**Difficulté :** Moyenne
**Date :** Octobre 2026

## 1. Reconnaissance & Énumération

_Quels ports étaient ouverts ? Quelle était la surface d'attaque ?_

- Scan Nmap (ajouter le bloc de code de la sortie Nmap).
- Découverte d'un service web tournant sur le port 8080.
- Énumération des répertoires cachés avec Gobuster.

## 2. Exploitation (Accès Initial)

_Comment es-tu rentré ?_

- Analyse de la vulnérabilité trouvée (ex: SQL Injection, CVE-202X-XXXX).
- Script utilisé ou méthode manuelle.
- _[Insérer une capture d'écran ou un Asciinema de l'obtention du reverse shell]_

## 3. Élévation de Privilèges (PrivEsc)

_Comment es-tu passé de simple utilisateur à Administrateur/Root ?_

- Énumération locale (ex: utilisation de LinPEAS).
- Découverte d'une tâche cron mal configurée.
- Exploitation et obtention du flag root.

## 4. 🛡️ Le regard du Défenseur (Très important)

_C'est ce qui te différenciera des autres étudiants. Comment cette entreprise aurait-elle pu éviter cette attaque ?_

- **Correction 1 :** Mettre à jour la version du CMS pour patcher la CVE.
- **Correction 2 :** Ne pas faire tourner le service avec l'utilisateur `root`.
- **Correction 3 :** Restreindre les permissions du fichier cron.

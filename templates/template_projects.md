# 🚀 Titre du Projet (ex: Déploiement d'un SIEM Wazuh & Détection de menaces)

**Temps de réalisation :** 10 jours
**Technologies :** Wazuh, Elastic Stack, Ubuntu, Windows Server, Draw.io

## 1. Contexte & Objectif Métier

_Ne parle pas technique ici. Explique le "Pourquoi"._
(Ex: "Dans le cadre de la protection d'un système d'information, la centralisation des journaux est indispensable. L'objectif de ce lab est de déployer une solution de détection open-source capable de remonter des alertes en temps réel sur des attaques communes.")

## 2. Architecture Technique

_Insère ici ton schéma Draw.io ou Excalidraw._

- **Zone Attaquant :** Kali Linux (IP dynamique)
- **Zone Cible :** Windows Server 2022 (Agent Wazuh)
- **Zone Défense :** Serveur Wazuh Manager (Ubuntu)

## 3. Déploiement (Build)

_Ne mets pas toutes les étapes de l'installation. Mets en avant les configurations complexes que tu as réalisées._

- Configuration du fichier `ossec.conf`.
- Mise en place du routage réseau.
- Extrait de code/fichier de configuration (utiliser les blocs de code).

## 4. Simulation d'Attaque (Red Team)

_Comment as-tu testé ton infrastructure ?_

- Lancement d'une attaque par force brute RDP depuis Kali Linux.
- _[Insérer ici un GIF ou un terminal interactif Asciinema montrant l'attaque]_

## 5. Détection & Remédiation (Blue Team)

_La valeur ajoutée de ton projet._

- Création d'une règle personnalisée dans Wazuh pour détecter cet événement spécifique.
- _[Insérer capture d'écran du dashboard montrant l'alerte rouge]_
- **Remédiation proposée :** Mise en place du module Active Response pour bannir l'IP attaquante via le pare-feu Windows.

## 6. Bilan et Compétences acquises

_Qu'as-tu appris ? Quelles difficultés as-tu surmontées ?_

- Maîtrise de la syntaxe des règles Wazuh.
- Compréhension des événements Windows (Event ID 4625).

# 🛡️ URL Risk Analyzer

## Problem Solved
Les employés reçoivent souvent des liens suspects par email ou messagerie. Cet outil permet d'analyser rapidement la sécurité d'une URL avant de cliquer dessus.

## Features
- Validation du format de l'URL saisie.
- Analyse en temps réel via l'API VirusTotal.
- Calcul d'un niveau de risque (`SAFE`, `SUSPICIOUS`, `DANGEROUS`) et d'un score sur 100.
- Enregistrement des données d'analyse dans une base Supabase.
- Consultation de l'historique des requêtes récentes.

## Tech Stack
- **Langage** : Python 3.10+
- **Interface Web** : Streamlit
- **Base de données** : Supabase (PostgreSQL)
- **API Externe** : VirusTotal API v3
- **Déploiement** : Streamlit Community Cloud

## API Used
- **VirusTotal API v3**
  - **Endpoint** : `https://www.virustotal.com/api/v3/urls`
  - **Method** : `POST` (soumission) & `GET` (rapport)
  - **Headers** : `x-apikey`

## Installation Locale
1. Cloner le projet :
   ```bash
   git clone [https://github.com/votre-user/url-risk-analyzer.git](https://github.com/votre-user/url-risk-analyzer.git)
   cd url-risk-analyzer
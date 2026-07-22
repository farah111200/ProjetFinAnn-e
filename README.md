# AI Pentest Platform

Plateforme d'audit de sécurité web automatisé, assistée par intelligence artificielle.

## Architecture

```
Utilisateur → Frontend → Backend (FastAPI) → PostgreSQL
                                 │
                                 └──→ Kali Linux (OWASP ZAP, Nuclei, Nmap)
                                            │
                                            └──→ Module IA (Claude API)
                                                       │
                                                       └──→ Rapport PDF
```

## Stack technique

- **Backend** : FastAPI (Python)
- **Base de données** : PostgreSQL
- **Tâches asynchrones** : Celery + Redis
- **Outils de scan** : OWASP ZAP (Kali Linux, VM VirtualBox)
- **IA** : Claude API (Anthropic)
- **Rapport** : WeasyPrint (HTML → PDF)
- **Conteneurisation** : Docker / docker-compose

## Lancer le projet

1. Copier `.env.example` en `.env` et renseigner les valeurs (clé API Anthropic notamment)
2. Lancer :
   ```bash
   docker-compose up --build
   ```
3. Le backend est disponible sur http://localhost:8000
4. Documentation interactive (Swagger) : http://localhost:8000/docs

## Structure du projet

```
backend/
├── app/
│   ├── main.py          # Point d'entrée FastAPI
│   ├── database.py      # Connexion PostgreSQL (SQLAlchemy)
│   ├── models.py        # Modèles: User, Scan, Vulnerability
│   └── routes/          # Endpoints de l'API
├── requirements.txt
└── Dockerfile
```

## Avertissement

Cet outil ne doit être utilisé que sur des applications pour lesquelles une autorisation explicite de test a été obtenue (environnements de test dédiés comme OWASP Juice Shop, DVWA, ou accord écrit du propriétaire du système).

import os
from dotenv import load_dotenv

load_dotenv()


class Settings:
    DATABASE_URL: str = os.getenv("DATABASE_URL")
    SECRET_KEY: str = os.getenv("SECRET_KEY", "change_me")
    ALGORITHM: str = os.getenv("ALGORITHM", "HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))
    ANTHROPIC_API_KEY: str = os.getenv("ANTHROPIC_API_KEY", "")
    ZAP_API_URL: str = os.getenv("ZAP_API_URL", "http://zap:8080")

    # Fournisseur d'IA pour l'analyse des vulnérabilités : "claude" (payant, meilleure
    # qualité) ou "ollama" (gratuit, tourne en local/conteneur, qualité correcte)
    AI_PROVIDER: str = os.getenv("AI_PROVIDER", "claude")
    OLLAMA_API_URL: str = os.getenv("OLLAMA_API_URL", "http://ollama:11434")
    OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "llama3.1")
    OPENROUTER_API_KEY: str = os.getenv("OPENROUTER_API_KEY", "")
    OPENROUTER_MODEL: str = os.getenv("OPENROUTER_MODEL", "nvidia/nemotron-3-ultra:free")

    # Où exécuter les scans : "local" (outils installés dans le conteneur backend)
    # ou "kali" (envoyés par SSH à une VM Kali qui fait le vrai travail)
    SCAN_MODE: str = os.getenv("SCAN_MODE", "local")
    KALI_HOST: str = os.getenv("KALI_HOST", "")
    KALI_SSH_PORT: int = int(os.getenv("KALI_SSH_PORT", "22"))
    KALI_SSH_USER: str = os.getenv("KALI_SSH_USER", "kali")
    KALI_SSH_PASSWORD: str = os.getenv("KALI_SSH_PASSWORD", "")

    # Premier compte admin créé automatiquement au démarrage si aucun n'existe
    FIRST_ADMIN_USERNAME: str = os.getenv("FIRST_ADMIN_USERNAME", "admin")
    FIRST_ADMIN_EMAIL: str = os.getenv("FIRST_ADMIN_EMAIL", "admin@example.com")
    FIRST_ADMIN_PASSWORD: str = os.getenv("FIRST_ADMIN_PASSWORD", "changeme123")


settings = Settings()

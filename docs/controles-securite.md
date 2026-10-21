# Contrôles de l'audit de sécurité

[← Retour au README](../README.md)

Le script [`scripts/audit.py`](../scripts/audit.py) interroge les **API AWS réelles** avec boto3. Il ne modifie rien dans le compte : il lit la configuration, signale chaque écart avec un niveau de gravité et produit un rapport JSON horodaté.

## Les 5 contrôles

| # | Contrôle | Service | Appel API | Gravité | Risque couvert |
| --- | --- | --- | --- | --- | --- |
| 1 | Bucket rendu public par sa politique | S3 | `get_bucket_policy_status` | **CRITICAL** | Fuite de données accessibles à tous |
| 2 | Chiffrement du bucket absent | S3 | `get_bucket_encryption` | **HIGH** | Données stockées en clair |
| 3 | Utilisateur sans MFA | IAM | `list_mfa_devices` | **HIGH** | Compte pris par vol ou devinette de mot de passe |
| 4 | Clé d'accès de plus de 90 jours | IAM | `list_access_keys` | MEDIUM | Clé ancienne, plus exposée aux fuites |
| 5 | Port sensible ouvert à `0.0.0.0/0` | EC2 | `describe_security_groups` | **CRITICAL** | Service d'administration ou base de données exposé à Internet |

### Ports sensibles surveillés (contrôle 5)

| Port | Service |
| --- | --- |
| 22 | SSH |
| 3389 | RDP |
| 3306 | MySQL |
| 5432 | PostgreSQL |
| 27017 | MongoDB |
| 6379 | Redis |

Le contrôle détecte aussi les **plages de ports** : une règle ouvrant `0-65535` à Internet est signalée pour chacun de ces services.

## Format du rapport

Chaque exécution produit un fichier `security_report_AAAAMMJJ_HHMMSS.json` :

```json
{
    "scan_date": "2026-03-31T17:43:14",
    "total_findings": 1,
    "critical": 0,
    "high": 1,
    "medium": 0,
    "low": 0,
    "findings": [
        {
            "severity": "HIGH",
            "service": "IAM",
            "resource": "user_test",
            "message": "MFA is not enabled — account vulnerable to brute force",
            "timestamp": "2026-03-31T17:43:13"
        }
    ]
}
```

## Résultat obtenu sur l'environnement déployé

Audit lancé le 31 mars 2026, juste après le déploiement Terraform :

| Gravité | Nombre | Détail |
| --- | --- | --- |
| CRITICAL | **0** | Aucun port sensible ouvert à Internet : le Security Group durci passe le contrôle (SSH limité à une IP `/32`) |
| HIGH | **1** | `user_test` : utilisateur IAM sans MFA |
| MEDIUM | 0 | Aucune clé d'accès de plus de 90 jours |
| LOW | 0 | — |

**Lecture :** l'infrastructure déployée par Terraform ne présente aucun écart. Le seul constat porte sur un compte IAM créé hors de ce projet, ce qui montre l'intérêt d'auditer **tout le compte AWS** et pas seulement ce que l'on vient de déployer.

**Remédiation :** activer le MFA sur `user_test`, ou supprimer ce compte s'il n'est plus utilisé.

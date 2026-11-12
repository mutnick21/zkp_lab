# ZKP Lab : cassez la preuve

Une page web **volontairement vulnérable** pour faire découvrir les preuves à divulgation nulle de connaissance (protocole d'identification de Schnorr). Chaque étudiant reçoit **sa propre clé privée** et doit la retrouver en exploitant trois erreurs d'implémentation classiques.

> ⚠️ La cryptographie est cassée exprès. N'en réutilisez aucun morceau dans un vrai projet.

## Déploiement (Docker)

```bash
# sur le serveur, dans ce dossier
ZKP_ADMIN_TOKEN='un-mot-de-passe-long' docker compose up -d --build
docker compose logs zkp-lab        # affiche le jeton admin s'il a été généré
```

- Page étudiants : `http://<serveur>:8080/`
- Panneau enseignant : `http://<serveur>:8080/admin` (avec le jeton admin)

L'état (secret serveur, joueurs, réussites) est conservé dans le volume Docker `zkp-data` et survit aux redémarrages.

| Variable | Défaut | Rôle |
|---|---|---|
| `ZKP_ADMIN_TOKEN` | généré à chaque démarrage | jeton du panneau `/admin` |
| `ZKP_SMALL_BITS` | `40` | taille de *p* au niveau 1, prise en compte **seulement à la création de l'état** (sinon : bouton « Tout régénérer », ou `docker compose down -v`) |

Sans Docker : `python3 server.py --port 8080` (Python 3.8 ou plus, aucune dépendance).

### Derrière nginx (optionnel, pour le HTTPS)

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host $host;
}
```

## Les trois niveaux

| Niveau | Thème | Points |
|---|---|---|
| 1. Le groupe miniature | la taille des paramètres | 100 |
| 2. L'optimisation de trop | la gestion du nonce | 200 |
| 3. Le hasard prévisible | la qualité de l'aléa | 300 |

Chaque niveau propose trois indices progressifs dans la page. Les clés sont dérivées par HMAC d'un secret serveur et du pseudo : deux étudiants n'ont jamais la même clé.

> Les solutions et le document d'explications détaillées ne sont volontairement **pas** publiés dans ce dépôt, pour ne pas gâcher le défi. Attention : lire `server.py` donne de gros indices.

### Déroulé suggéré (≈ 1 h 30)
1. **10 min** : présentation du protocole (schéma en haut de la page), inscription des étudiants.
2. **25 min** par niveau, indices compris.
3. **10 min** : débrief sur le classement.

## Panneau admin
- Liste des joueurs, niveaux résolus, nombre de tentatives, clés privées (pour vérifier une réponse).
- **Effacer les joueurs** : vide le classement en gardant le secret, donc un même pseudo retrouve les mêmes clés.
- **Tout régénérer** : nouveau secret et nouveau groupe pour le niveau 1, à faire entre deux classes.

## Côté web
L'application est faible en crypto, pas en web : fichiers statiques en liste blanche, corps de requête limité à 16 Ko, entiers limités à 4096 bits, CSP stricte, pseudos filtrés et affichés via `textContent`, conteneur non-root en lecture seule, sans aucune capability. Pensez quand même à couper le service après la séance.

## API
Voir le « Mémo API » en bas de la page étudiant. Toutes les routes authentifiées attendent l'en-tête `X-Token`.

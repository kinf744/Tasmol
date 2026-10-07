# DOCUMENTATION TECHNIQUE — utunnel

Tunnel UDP propriétaire (type Hysteria, **sans** Hysteria ni QUIC), écrit
from scratch en Go. Cette documentation est le référentiel pour toute
modification ou amélioration future : architecture, protocole octet par
octet, algorithmes, concurrence, réglages, tests, diagnostic.

---

## Table des matières

1. [Vue d'ensemble](#1-vue-densemble)
2. [Arborescence et rôle de chaque fichier](#2-arborescence)
3. [Spécification du protocole (octet par octet)](#3-protocole)
4. [Algorithmes](#4-algorithmes)
5. [Concurrence et verrous](#5-concurrence)
6. [Constantes et réglages](#6-constantes)
7. [Intégration application Android](#7-application)
8. [Intégration serveur (stivaros)](#8-serveur)
9. [Tests](#9-tests)
10. [Diagnostic des erreurs](#10-diagnostic)
11. [Limites connues et améliorations futures](#11-limites-et-roadmap)

---

## 1. Vue d'ensemble

```
┌───────────────────────────── CLIENT ─────────────────────────────┐
│  App Android (SOCKS5 TUN) / CLI                                  │
│      │  handshake1 [eph X25519 | ts | HMAC16 | pad aléatoire]    │
│      ├──────────────────────────────────────────────────►        │
│      │  handshake2 [eph X25519 | confirm16]                      │
│      ◄──────────────────────────────────────────────────          │
│      │  paquets [8B token | 24B nonce | AEAD XChaCha20|payload]  │
│      ├──────────────────────────────────────────────────►        │
└───────────────────────────── SERVEUR ────────────────────────────┘
        multi-sessions, ARQ sélectif, mux TCP + relais UDP
```

| Propriété | Valeur |
| :--- | :--- |
| Transport | UDP pur, un seul port d'écoute + plage DNAT-ée |
| Chiffrement | X25519 (handshake) + XChaCha20-Poly1305 (paquets) |
| Dérivation des clés | HKDF-SHA3(secret DH, psk, "utunnel/v1 session") |
| Fiabilité | ACK cumulatif honnête + SACK 32, triple-ACK, RTO Jacobson |
| Congestion | slow-start + AIMD (×0.7 par RTO), pacing `srtt/cwnd` |
| Multiplexage | N streams par session (TCP CONNECT + UDP ASSOCIATE) |
| Port-hopping | rotation du port source côté client (serveur suit le pair) |
| Binaires | `utunnel-server` (VPS) + `utunnel-client` (VPS/Android) |

---

## 2. Arborescence

| Fichier | Rôle |
| :--- | :--- |
| `proto/packet.go` | Format du paquet sur le fil : encode/decode, AEAD, masque d'en-tête, constantes |
| `proto/crypto.go` | X25519, HKDF-SHA3, HMAC handshake, confirm AEAD, seal/open |
| `proto/session.go` | Session fiable : ARQ, SACK, RTO, congestion, pacing, ticker, keepalive/pong, hop de socket |
| `proto/mux.go` | Multiplexage : frames par stream, ordonnancement, FIN ordonné, OPEN idempotent, bridgeTCP |
| `cmd/utunnel-server/main.go` | Endpoint serveur : démultiplexage par token, handshakes multi-PSK, relais UDP, plage DNAT |
| `cmd/utunnel-client/main.go` | Client : SOCKS5 local (CONNECT+ASSOCIATE), port-hopping, cause des échecs de dial |
| `proto/e2e_test.go` | Tests : paquet, handshake, E2E (TCP+UDP 1 Mo), pertes 15 % |
| `deploy/utunnel.service` | Unité systemd durcie (Restart, ExecStartPre nft, LimitNOFILE) |
| `deploy/utunnel.nft` | Table nftables : ACCEPT :5669 + DNAT plage 34000-49999 |
| `deploy/install_utunnel_stivaros.sh` | Installation idempotente au style stivaros.sh |
| `scripts/build_utunnel.sh` | Cross-compile amd64/arm64/armv7 (garble si installé) |
| `dist/` | Binaires produits (server + client, 3 arches) |

---

## 3. Protocole

### 3.1 Handshake (en clair, authentifié)

**handshake1** (client → serveur, `BuildHandshake1`, PreKeyLen=56) :

```
[32B ephClient X25519][8B timestamp Unix BE][16B HMAC-SHA256(psk, eph|ts)[:16]]
[0..55B padding aléatoire]   ← anti-détection de longueur fixe
```

Vérifications serveur (`ParseHandshake1`) : longueur ≥56 et ≤120, ts ±120 s
(anti-rejeu), HMAC constant-time. Un serveur NE RÉPOND QU'AUX HANDSHAKES
AUTHENTIQUES — un silence côté client = port fermé / DNAT absent / serveur
arrêté, jamais une mauvaise PSK seule (voir §10).

**handshake2** (serveur → client, 48 octets) :

```
[32B ephServer X25519][16B confirm = AEAD(C2S, nonce=0, ∅, AAD=ephClient)[:16]]
```

Le client vérifie le confirm (`HandshakeConfirm`) — mauvaise PSK → `ErrBadAuth`.

### 3.2 Paquet de session (chiffré, `encodePacket`/`decodePacket`)

```
[8B token^mask(key)][12..24B nonce aléatoire][ciphertext AEAD]
ciphertext = AEAD( header16B | payload, nonce, AAD=token )
header clair : [1B type][1B flags][2B window][4B seq][4B ack][4B ackBits]
```

- **token** = 8 premiers octets de la clé TX du pair. Le masque
  (`headerMask`) est dérivé de la clé : aucun motif constant sur le fil.
  Le serveur indexe sa table de sessions sur les 8 premiers octets BRUTS
  (`WireToken`), avant tout déchiffrement — démux O(1).
- **nonce** : XChaCha20-Poly1305 (`NewX`, 24 B) — aléatoire par paquet,
  sûr sans compteur (espace 2^96 nonces).
- **types** : 0x01 H1, 0x02 H2, 0x10 DATA (frames mux), 0x11 PureAck,
  0x12 UDPData (relais non fiable), 0x1f CloseSess.
- **ack/ackBits** : cumulative (frontière contiguë) + SACK des 32 seq
  hors-ordre AU-DESSUS de la frontière (bit i ⇔ rxBase+i reçu).
- **flags** : bit 1 = pong (ne déclenche pas de réponse — anti-boucle).

### 3.3 Frames mux (dans un paquet TypeData, `sendFrame`/`deliver`)

```
[1B op][4B sid][4B seq][4B finSeq][2B len][payload]   (byte 15 = padding zéro)
```

| op | Sens | Signification |
| :--- | :--- | :--- |
| 0x01 OPEN | C→S | payload = `"tcp:host:port"` ou `"udp:"` — **IDEMPOTENT** : sid déjà présent = réémission ARQ, ignoré |
| 0x02 OK | S→C | ouverture confirmée (chOpen du stream) |
| 0x03 DATA | les deux | segment ordonné par stream (seq = txSeq du stream) |
| 0x04 FIN | les deux | demi-fermeture **ordonnée** : n'agit qu'une fois TOUTES les données qui le précèdent livrées (finSeq) |
| 0x05 RST | S→C | erreur (payload = message), fermeture forcée |

Chaque paquet de session transporte EXACTEMENT UNE frame (un queue() = un
seq de session = un paquet). L'ordre des frames d'un stream est rétabli
par les séquences internes du stream (rxExpect + rxBuf).

### 3.4 Relais UDP (framing applicatif, `packUDPGram`/`unpackUDPGram`)

Dans un stream `"udp:"` : `[2B addrLen][addr "ip:port"][données]`.
Côté client (SOCKS UDP ASSOCIATE) : datagramme SOCKS `[RSV2|FRAG1|ATYP|addr|port|data]`
dénudé/reconstruit (`socksUDPUnwrap`/`socksUDPWrap`).

---

## 4. Algorithmes

### 4.1 Fiabilité (session, `session.go`)

- **Émission** : queue → heap min-seq (`unackedQ`) → flush envoie selon
  fenêtre/pacing → segment dans `unacked` (map) jusqu'à acquittement.
- **ACK cumulatif honnête** (`seenIsNew`) : rxBase n'avance QUE sur le
  flux contigu livré. Un seq hors-ordre est bufferisé (rxSeen) et signalé
  par SACK — JAMAIS couvert par le cumulatif (sinon l'émetteur abandonne
  des segments perdus = perte sans récupération).
- **SACK** : 32 bits au-dessus de rxBase ; l'émetteur purge
  `try(ack + i)`.
- **Retransmission** : RTO (srtt + max(10 ms, 4×rttvar), min 80 ms) OU
  triple-ACK dupliqué sur le plus bas seq en vol (fastRetr ≥ 3).
- **Congestion** : slow-start (+1/ack jusqu'à 64) puis AIMD (+1/cwnd),
  ×0.7 par expiration RTO, max 4096.
- **Pacing** : émissions espacées de `srtt/cwnd` ; le PREMIER envoi d'un
  flush n'est jamais pacing-bridé (les ACK s'auto-cadencent ensuite).
- **Pure-ack** (`ackPend`) : données reçues et rien à porter → pure-ack
  64 B en fin de flush — sinon l'émetteur retransmettrait en aveugle.
- **Keepalive/pong** : PureAck toutes les 10 s ; le récepteur répond un
  pong (flags=1) — MAINTIENT lastRX DES DEUX CÔTÉS en idle (sans pong,
  le client se tuait après 45 s et le serveur 45 s plus tard).
- **Session morte** : 45 s sans paquet reçu → kill. TypeCloseSess au Stop.
- **Hop de socket** (`SwapConn`) : remplace la socket UDP sous-jacente ;
  le reader en cours repart sur la nouvelle (`swapped && !dead → continue`),
  clés et streams préservés, aucun re-handshake. `SendKeepalive()` est
  appelé immédiatement après le hop pour mettre l'adresse du pair à jour.

### 4.2 Multiplexage (`mux.go`)

- **Ordonnancement par stream** : DATA seq == rxExpect → append + drain
  contigu (`rxAdvance`, qui incrémente rxExpect POUR LE FRAME COURANT) ;
  seq > rxExpect → rxBuf ; seq < rxExpect → doublon ARQ, ignoré.
- **FIN ordonné** : le FIN porte la seq du txSeq courant ; n'arme rEOF que
  lorsque rxExpect l'atteint (finSet/finSeq). Sans cela, un FIN arrivé
  pendant des réémissions tronquait le flux.
- **OPEN idempotent** : sid déjà dans la map = réémission, ignoré — sans
  cela un OPEN réémis recréait le stream, orphanait le pont et bufferisait
  tout le flux à jamais.
- **bridgeTCP** : les DEUX sens pompent indépendamment (sync.WaitGroup) ;
  fermeture seulement une fois chacun terminé (fermer à la première fin
  de sens tuait l'autre en cours = troncature).

---

## 5. Concurrence

**Verrous et ordre** (jamais de cycle) :

| Verrou | Protège | Ordre |
| :--- | :--- | :--- |
| `Session.mu` | état session, heap, unacked, remote, keys | toujours en premier |
| `Stream.mu` (rCond) | readBuf, txSeq, rxExpect | pris APRÈS Session.mu (dispatch → sendFrame → queue) |
| `Mux.mu` | map streams, nextSID | isolé |

**Goroutines par session** : reader (client seulement ; le serveur
démuxe globalement via `HandleFromServer`), ticker (10 ms flush / 25 ms
détection pertes / 10 s keepalive / 2 s timeout), hopLoop (client,
optionnel). Côté serveur : une boucle de lecture unique + un goroutine de
handshake par tentative (sémaphore 64, max-sessions).

---

## 6. Constantes

| Constante | Valeur | Réglage futur |
| :--- | :--- | :--- |
| `nonceLen` | 24 | NE PAS réduire (XChaCha exige 24) |
| `MTUDefault` / payload max frame | 1232 / 1100 | overhead session = 8+24+16+16 = 64 ; garder paquet ≤1232 |
| `sessTimeout` | 45 s | > keepalive×4 |
| `keepalive` | 10 s | NAT/firewall timeout |
| `minRTO` / `initRTO` | 80 ms / 300 ms | min trop bas = retransmissions précoces |
| `defaultCWND` / `maxCWND` | 32 / 4096 | max × 1100 B = plafond débit par RTT |
| `DefaultUtunnelHopInterval` | 10 s | 0 = jamais |
| Serveur `-listen` | :5669 | plage DNAT côté serveur (distincte des autres tunnels) |

Clé client (`resolveClientKey`, dans `internal/tunnel/utunnel_tunnel.go`
côté app) : champ de 64 hex = clé directe ; sinon SHA256(secret) hex —
correspond à la dérivation serveur (`server.psk` en clair → SHA256) et au
mode users.list stivaros.

---

## 7. Application

Le type de tunnel `utunnel` est intégré à l'app Android (EPHANG VPN) :

| Fichier | Modification |
| :--- | :--- |
| `internal/config/types.go` | `TunnelUtunnel = "utunnel"` |
| `internal/tunnel/utunnel_tunnel.go` | **NOUVEAU** — lance le client, log détaillé |
| `internal/tunnel/bins.go` | `BinUtunnel`, `DefaultUtunnelPort = 10812`, case SocksPort |
| `internal/tunnel/manager.go` | `CreateTunnel` → `NewUtunnelTunnel` |
| `bin/armv7/utunnel`, `bin/arm64/utunnel` | client dans le bundle repo |
| `scripts/fetch_android_bins.sh` | stage → `lib_utunnel.so` (jniLibs) |
| `BinaryManager.java` | `NATIVE_LIBS` + `bin_names` (`lib_utunnel.so` → `utunnel`) |
| `activity_tunnel_editor.xml` | section `sec_utunnel` (clé PSK + rotation) |
| `TunnelEditorActivity.java` | TYPES/TYPE_LABELS, champs, visibilité, load, save |
| `UdpSessionLog.java` | `kindOf("utunnel")` → Kind("UDP", "Utunnel") |
| `TunnelAdapter.java` | `prettyType` case |
| `ConfigsFragment.java` | filtre + `typeMatches` |
| `ProfileTransfer.java` | `KNOWN_TYPES` (import/export .epha) |

Champs de l'éditeur (« CONFIGS » → « add server » → type **Utunnel UDP**) :
**Host**, **Port** (port RÉEL d'écoute du serveur, ex. 5669 — la plage
clients est DNAT-ée côté serveur, jamais dialée), **Clé PSK** (secret
serveur ou clé hex 64), **Rotation du port source** (secondes, 0 = jamais).

### Log détaillé (kighmu.txt)

Le journal live est `<filesDir>/logs/kighmu.txt` (app-private — Download/
est en lecture seule sur Android 10+ avec targetSdk 34) ; l'onglet LOGS
l'affiche et le bouton « Enregistrer en fichier » l'exporte vers Download
(`kighmu.txt`) via le sélecteur système.

Chaîne de logs utunnel (tout arrive dans kighmu.txt) :

```
[udp]      Connecting udp server from udp setting        (Java, UdpSessionLog)
[journal]  [utunnel] udp 1.2.3.4:5669 (socks 127.0.0.1:39210, hop 10s)
[info]     [utunnel] client lancé pid=12345 (serveur 1.2.3.4:5669)
[utunnel][err] 2026/10/07 07:10:01 tunnel établi vers 1.2.3.4:5669
[utunnel][err] 2026/10/07 07:10:11 hop: nouveau port source ...
[utunnel][out]  (trace des frames mux: UTUNNEL_TRACE=1)
[connection][utunnel] connecté 1.2.3.4:5669 (UDP, ARQ+XChaCha)
```

En cas d'échec :

```
[error] [utunnel] SOCKS 127.0.0.1:39210 not ready (handshake ou PSK invalide ?): ...
[utunnel][err] dial 1.2.3.4:5669: aucune réponse du serveur (timeout) — vérifiez le port, le DNAT de plage et que le serveur tourne — nouvelle tentative dans 2s
[error] [udp] Utunnel connection failed : utunnel socks not ready: ...
[warning] [app] connect attempt 1/10 failed: ... - retrying
```

---

## 8. Serveur

```sh
# Installation (serveur déjà stivaros ou vierge)
bash deploy/install_utunnel_stivaros.sh        # installe et démarre
bash deploy/install_utunnel_stivaros.sh remove # désinstalle

# Manuel
printf '<secret>' > /etc/utunnel/server.psk && chmod 600 /etc/utunnel/server.psk
cp deploy/utunnel.service deploy/utunnel.nft /...
nft -f /etc/nftables/utunnel.nft && systemctl enable --now utunnel

# Clé client = hex(sha256(secret))
sha256sum /etc/utunnel/server.psk
```

Mode stivaros : `-users-file /etc/utunnel/users.list` (`uuid|secret|date`)
— chaque entrée = PSK `SHA256(uuid:secret)`, purge quotidienne, la clé
statique est préservée.

Plage serveur : **34000-49999** DNAT-ée vers :5669 (DISTINCTE de
stivaros-zivpn). Le port-hopping client traverse la plage nativement.

---

## 9. Tests

```sh
cd /root/utunnel && go test ./proto/ -v -timeout 200s
```

| Test | Valide |
| :--- | :--- |
| `TestPacketRoundtrip` | encode/decode, tamper (AEAD), AAD (token), mauvaise clé |
| `TestHandshakeRoundtrip` | Build/Parse, confirm identique, mauvaise PSK → ErrBadAuth, rejeu → ErrSessExpired |
| `TestSessionE2E` | handshake UDP réel, proxy TCP (ping + 1 Mo intègre), stream UDP, zéro segment en vol |
| `TestSessionWithLoss` | 256 Ko à travers **15 % de pertes bidirectionnelles** (proxy perdant), récupération ARQ complète |

Ajouter un cas : modèle `TestSessionE2E` (socket serveur + `ParseHandshake1`
+ `RespondHandshake` + dispatcher `HandleFromServer` + client `NewSession`).

---

## 10. Diagnostic

| Symptôme | Cause probable | Vérification |
| :--- | :--- | :--- |
| `dial: aucune réponse du serveur` en boucle | port fermé, DNAT absent, serveur arrêté | `systemctl status utunnel` ; `nft list table inet utunnel` ; envoyer un paquet UDP sur un port de la plage |
| SOCKS not ready (15 s) mais pas d'erreur dial | mauvaise PSK (confirm rejeté → le client ne reçoit pas handshake2) OU handshake2 perdu | kighmu.txt : `ErrBadAuth` absent = silence = DNAT/port ; testé avec la même clé côté serveur |
| Le tunnel démarre puis sort tout de suite | clé invalide (fichier introuvable), port SOCKS occupé | `[utunnel] process exited` dans kighmu.txt |
| Débit anormalement bas | cwnd effondré (pertes), MTU fragmenté | réduire `utunnel_hop` ? non — vérifier `maxCWND` et le MTU du TUN |
| Rien ne passe alors que le client dit "tunnel établi" | frame OPEN jamais délivré (régression ordonnancement) | `UTUNNEL_TRACE=1` : les traces `DATA sid1 sseq=... -> inorder/buffer` doivent avancer `rxExp` |

`UTUNNEL_TRACE=1` (client ou serveur) : trace des 40 premiers frames mux
(op/sid/seq + décision inorder/buffer). Intégré à l'app (env du client
toujours tracé).

---

## 11. Limites et roadmap

| Limite | Point d'ancrage | Amélioration |
| :--- | :--- | :--- |
| Congestion AIMD classique (pas Brutal) | `Session.onAcked`/`onLoss` | mode "brutal" à débit garanti (comme Hysteria2) : taux fixe de l'éditeur |
| SACK limité à 32 seq | `rxAckState` | étendre à 64/128 bits (2 mots) |
| Session-level non ordonné (dédup seul) | `Session.handle` | réordonnancement complet au niveau session (buffer hors-ordre) |
| `processAck` O(n) par ack | `processAck` | index trié si cwnd > 1000 |
| Pas de reprise de session (reconnect = nouveau handshake) | `NewSession` | resumption ticket (comme TLS) |
| Queue d'émission non bornée | `queue` | backpressure bloquante au-delà de N segments |
| Slow-start initial lent sur gros RTT | `initRTO` 300 ms | l'estimation adapte vite, mais un CWND initial configurable est possible |
| Un seul process client par session | `runSessionMux` | pool de process par sous-plage (comme zivpn) |

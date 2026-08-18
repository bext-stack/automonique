// SPDX-License-Identifier: Elastic-2.0

"use strict";

const byId = (id) => document.getElementById(id);
const supportedLanguages = ["en", "fr"];
let currentLanguage = storedPreference("monique-language", supportedLanguages, navigator.language.toLowerCase().startsWith("fr") ? "fr" : "en");
const localeTag = () => currentLanguage === "fr" ? "fr-FR" : "en-US";
const count = (value) => Number.isSafeInteger(value) && value >= 0 ? value.toLocaleString(localeTag()) : "—";
const words = (value) => typeof value === "string" ? translatePhrase(value.replaceAll("_", " ")) : "—";
const yesNo = (value) => value === true ? translatePhrase("YES") : value === false ? translatePhrase("NO") : "—";
const safeMetric = (value) => Number.isSafeInteger(value) && value >= 0 ? value : 0;
const statusHistory = [];
let memorySnapshot = null;
let memoryKind = "all";
let memoryQuery = null;
let operationsSnapshot = null;
let ticketFilter = "all";
let ticketQuery = "";
let ticketSort = "updated_desc";
let lastObservedMs = null;
let lastStatusKey = null;
let lastPulseChangeAt = null;
let chatBusy = false;
let newChatArmed = false;
let newChatTimer = null;
let lastStatusSnapshot = null;
let configurationFilter = "all";
let configurationQuery = "";
let statusRefreshTimer = null;
let lastNotifiedAttentionKey = null;
const frenchUi = Object.freeze({
  "Skip to workspace": "Aller à l’espace de travail",
  "Primary navigation": "Navigation principale",
  "Open Monique chat": "Ouvrir la discussion avec Monique",
  "Collapse sidebar": "Réduire la barre latérale",
  "Expand sidebar": "Déployer la barre latérale",
  "Toggle sidebar": "Afficher ou masquer la barre latérale",
  "Close navigation": "Fermer la navigation",
  "New conversation": "Nouvelle conversation",
  "Confirm new conversation": "Confirmer la nouvelle conversation",
  "Workspace": "Espace de travail",
  "Operations sections": "Sections opérationnelles",
  "Overview": "Vue d’ensemble",
  "OVERVIEW": "VUE D’ENSEMBLE",
  "Chat": "Discussion",
  "CHAT": "DISCUSSION",
  "Tickets": "Tickets",
  "TICKETS": "TICKETS",
  "Memory": "Mémoire",
  "MEMORY": "MÉMOIRE",
  "Configuration": "Configuration",
  "CONFIGURATION": "CONFIGURATION",
  "Appearance settings": "Paramètres d’apparence",
  "Open appearance settings": "Ouvrir les paramètres d’apparence",
  "Appearance": "Apparence",
  "Personalize": "Personnaliser",
  "PROTECTED": "PROTÉGÉ",
  "Basic auth · TLS only": "Authentification basique · TLS uniquement",
  "Connecting": "Connexion",
  "No snapshot": "Aucun instantané",
  "Switch to French": "Passer au français",
  "Switch to English": "Passer à l’anglais",
  "Language": "Langue",
  "Interface and navigation language": "Langue de l’interface et de la navigation",
  "English": "Anglais",
  "Increase text size": "Augmenter la taille du texte",
  "Decrease text size": "Réduire la taille du texte",
  "Change text size": "Modifier la taille du texte",
  "Text size": "Taille du texte",
  "System": "Système",
  "Paper": "Papier",
  "Midnight": "Minuit",
  "Ocean": "Océan",
  "Forest": "Forêt",
  "High contrast": "Contraste élevé",
  "Contrast": "Contraste",
  "Standard": "Standard",
  "Comfortable": "Confortable",
  "Large": "Grand",
  "Extra large": "Très grand",
  "Spacious": "Spacieux",
  "Color theme": "Thème de couleurs",
  "Close appearance settings": "Fermer les paramètres d’apparence",
  "Monique adapts to the way you prefer to read.": "Monique s’adapte à votre confort de lecture.",
  "Interface density": "Densité de l’interface",
  "Start page": "Page de démarrage",
  "Default view when no direct link is used": "Vue par défaut lorsqu’aucun lien direct n’est utilisé",
  "Reduce motion": "Réduire les animations",
  "Limit interface animation and transitions": "Limiter les animations et transitions de l’interface",
  "Reset appearance defaults": "Rétablir les réglages d’apparence",
  "Appearance is saved only in this browser.": "L’apparence est enregistrée uniquement dans ce navigateur.",
  "Appearance settings reset.": "Les paramètres d’apparence ont été réinitialisés.",
  "CONTROL PLANE / LIVE": "PLAN DE CONTRÔLE / TEMPS RÉEL",
  "Operations overview": "Vue d’ensemble des opérations",
  "A live, secret-safe view of Monique’s execution path and delivery certainty.": "Une vue en temps réel et sans secrets du parcours d’exécution de Monique et de la certitude de livraison.",
  "Ask Monique": "Demander à Monique",
  "Open Manage ↗": "Ouvrir Manage ↗",
  "Establishing snapshot": "Établissement de l’instantané",
  "Waiting for the daemon’s sanitized operational projection.": "En attente de la projection opérationnelle assainie du démon.",
  "Operational counters": "Compteurs opérationnels",
  "ACTIVE RUNS": "EXÉCUTIONS ACTIVES",
  "executing now": "en cours maintenant",
  "INBOX": "BOÎTE D’ENTRÉE",
  "awaiting intake": "en attente d’admission",
  "OUTBOX": "BOÎTE DE SORTIE",
  "awaiting delivery": "en attente de livraison",
  "RECONCILE": "RÉCONCILIATION",
  "manual outcomes": "résultats manuels",
  "AMBIGUOUS": "AMBIGU",
  "uncertain effects": "effets incertains",
  "ATTENTION": "ATTENTION",
  "failed invariants": "invariants en échec",
  "Suggested operational questions": "Questions opérationnelles suggérées",
  "QUICK BRIEFS": "RÉSUMÉS RAPIDES",
  "Explain health": "Expliquer l’état de santé",
  "Read Slack activity": "Lire l’activité Slack",
  "Review memory": "Examiner la mémoire",
  "PIPELINE": "PIPELINE",
  "Work path": "Parcours de travail",
  "LIVE": "TEMPS RÉEL",
  "Work pipeline": "Pipeline de travail",
  "Intake": "Admission",
  "Durable admission": "Admission durable",
  "Execution": "Exécution",
  "Fenced provider runs": "Exécutions fournisseur cloisonnées",
  "Delivery": "Livraison",
  "Idempotent effects": "Effets idempotents",
  "Reconcile": "Réconcilier",
  "Outcome certainty": "Certitude du résultat",
  "INVARIANTS": "INVARIANTS",
  "Runtime posture": "Posture d’exécution",
  "CHECKING": "VÉRIFICATION",
  "Daemon": "Démon",
  "Provider lane": "Voie fournisseur",
  "Accepting intake": "Admission ouverte",
  "Telegram": "Telegram",
  "Snapshot": "Instantané",
  "CLIENT OBSERVATION WINDOW": "FENÊTRE D’OBSERVATION CLIENT",
  "System pulse": "Pouls du système",
  "COLLECTING": "COLLECTE",
  "Recent operational queue levels": "Niveaux récents des files opérationnelles",
  "Client-observed history for running work, inbox, and outbox counts.": "Historique observé côté client des travaux en cours et des files d’entrée et de sortie.",
  "Running": "En cours",
  "Inbox": "Entrée",
  "Outbox": "Sortie",
  "Samples": "Échantillons",
  "Window": "Fenêtre",
  "Last change": "Dernier changement",
  "Just started": "À l’instant",
  "Waiting": "En attente",
  "Chat with Monique": "Discuter avec Monique",
  "Contained assistant": "Assistante cloisonnée",
  "Conversation context": "Contexte de conversation",
  "memory": "mémoire",
  "live": "temps réel",
  "last turn": "dernier échange",
  "Actions ready": "Actions disponibles",
  "＋ New chat": "＋ Nouvelle discussion",
  "What can I help with?": "Comment puis-je vous aider ?",
  "How can I help?": "Comment puis-je vous aider ?",
  "Ask naturally. I can reason with reviewed memory, use configured live sources, and prepare actions for your approval.": "Posez votre question naturellement. Je peux raisonner à partir de la mémoire vérifiée, utiliser les sources en temps réel configurées et préparer des actions soumises à votre approbation.",
  "Ask naturally. I can use reviewed memory, live sources, and prepare actions for your approval.": "Posez votre question naturellement. Je peux utiliser la mémoire vérifiée, les sources en temps réel et préparer des actions soumises à votre approbation.",
  "Explain system health": "Expliquer l’état du système",
  "Review live status and surface risks": "Examiner l’état en temps réel et signaler les risques",
  "Catch me up": "Me mettre à jour",
  "Read recent configured Slack context": "Lire le contexte Slack configuré récent",
  "Explore memory": "Explorer la mémoire",
  "Use reviewed durable evidence": "Utiliser des éléments durables vérifiés",
  "Work in Manage": "Travailler dans Manage",
  "Prepare a reviewable AI Operations action": "Préparer une action AI Operations vérifiable",
  "Message Monique…": "Écrire à Monique…",
  "Message Monique": "Écrire à Monique",
  "Route": "Profil",
  "Fast conversation": "Conversation rapide",
  "Operational reasoning": "Raisonnement opérationnel",
  "send": "envoyer",
  "Ready": "Prêt",
  "Send message": "Envoyer le message",
  "Monique can make mistakes. Durable memory and live sources are labeled when they support an answer.": "Monique peut se tromper. La mémoire durable et les sources en temps réel sont signalées lorsqu’elles étayent une réponse.",
  "DISCOVERED / AUTHORITY-AWARE / LIVE": "DÉCOUVERT / AUTORITÉ MAÎTRISÉE / TEMPS RÉEL",
  "Work directly with the connected control plane. Safe reads are live; every mutation remains staged for explicit approval.": "Travaillez directement avec le plan de contrôle connecté. Les lectures sûres sont immédiates ; chaque modification reste en attente d’une approbation explicite.",
  "Refresh": "Actualiser",
  "Refresh operational status": "Actualiser l’état opérationnel",
  "Refresh status": "Actualiser l’état",
  "Open AI Operations ↗": "Ouvrir AI Operations ↗",
  "Connecting to AI Operations": "Connexion à AI Operations",
  "Discovering the live capability catalog…": "Découverte du catalogue de fonctionnalités en temps réel…",
  "AI Operations capability counts": "Compteurs de fonctionnalités AI Operations",
  "TOOLS": "OUTILS",
  "discovered capabilities": "fonctionnalités découvertes",
  "SAFE READS": "LECTURES SÛRES",
  "available immediately": "disponibles immédiatement",
  "APPROVAL ACTIONS": "ACTIONS À APPROUVER",
  "staged before execution": "préparées avant exécution",
  "PENDING": "EN ATTENTE",
  "awaiting your decision": "en attente de votre décision",
  "LIVE MCP CATALOG": "CATALOGUE MCP EN TEMPS RÉEL",
  "Connected capabilities": "Fonctionnalités connectées",
  "Operations": "Opérations",
  "Deployments": "Déploiements",
  "General": "Général",
  "Read Only": "Lecture seule",
  "DISCOVERING": "DÉCOUVERTE",
  "Loading AI Operations capabilities…": "Chargement des fonctionnalités AI Operations…",
  "CONTROL BOUNDARY": "PÉRIMÈTRE DE CONTRÔLE",
  "How actions run": "Déroulement des actions",
  "Discover": "Découvrir",
  "Only tools advertised by the live control plane appear here.": "Seuls les outils annoncés par le plan de contrôle en temps réel apparaissent ici.",
  "Review": "Examiner",
  "Mutations show exact arguments and impact before anything runs.": "Les modifications affichent les arguments exacts et leur impact avant toute exécution.",
  "Approve": "Approuver",
  "Your one-time decision authorizes one exact action.": "Votre décision ponctuelle autorise une seule action précise.",
  "Ask Monique to operate": "Demander à Monique d’agir",
  "Plan with the live catalog →": "Planifier avec le catalogue en temps réel →",
  "LIVE / TRIAGED / ACTIONABLE": "TEMPS RÉEL / TRIÉ / ACTIONNABLE",
  "A focused queue from AI Operations, with live status and safe handoff into Monique for follow-up.": "Une file ciblée issue d’AI Operations, avec un état en temps réel et un transfert sûr vers Monique pour le suivi.",
  "Review with Monique": "Examiner avec Monique",
  "Ticket counts": "Compteurs de tickets",
  "TOTAL": "TOTAL",
  "in the live queue": "dans la file en temps réel",
  "OPEN": "OUVERTS",
  "awaiting progress": "en attente d’avancement",
  "IN PROGRESS": "EN COURS",
  "actively handled": "pris en charge",
  "BLOCKED": "BLOQUÉS",
  "needs attention": "nécessite une attention",
  "URGENT": "URGENTS",
  "highest priority": "priorité maximale",
  "Search tickets": "Rechercher des tickets",
  "ID, title, tenant, site or person": "ID, titre, espace, site ou personne",
  "Clear ticket search": "Effacer la recherche de tickets",
  "Sort by": "Trier par",
  "Recently updated": "Récemment mis à jour",
  "Priority": "Priorité",
  "Status": "État",
  "Oldest first": "Plus anciens d’abord",
  "Title": "Titre",
  "Filter tickets": "Filtrer les tickets",
  "All": "Tous",
  "Open": "Ouvert",
  "In progress": "En cours",
  "Blocked": "Bloqué",
  "Done": "Terminé",
  "Connecting to ticket intake…": "Connexion à la file de tickets…",
  "Waiting for a live source": "En attente d’une source en temps réel",
  "Ticket": "Ticket",
  "Context": "Contexte",
  "Lifecycle": "Cycle de vie",
  "Actions": "Actions",
  "Loading the live ticket queue…": "Chargement de la file de tickets en temps réel…",
  "TYPED / REVISIONED / PROVENANCE-BOUND": "TYPÉ / VERSIONNÉ / PROVENANCE LIÉE",
  "Memory system": "Système de mémoire",
  "Inspect the evidence Monique can retrieve without exposing raw private state.": "Examinez les éléments que Monique peut récupérer sans exposer l’état privé brut.",
  "Search memory evidence": "Rechercher dans les éléments de mémoire",
  "Clear memory search": "Effacer la recherche en mémoire",
  "Search": "Rechercher",
  "ACTIVE": "ACTIFS",
  "PROPOSALS": "PROPOSITIONS",
  "SUPERSEDED": "REMPLACÉS",
  "MESSAGES": "MESSAGES",
  "Evidence graph": "Graphe des éléments",
  "Records": "Enregistrements",
  "Kind": "Type",
  "All evidence": "Tous les éléments",
  "Loading canonical store…": "Chargement du stockage canonique…",
  "Typed memory evidence graph": "Graphe typé des éléments de mémoire",
  "EFFECTIVE / SECRET-SAFE PROJECTION": "PROJECTION EFFECTIVE / SANS SECRETS",
  "SYSTEM / WORKSPACE / PREFERENCES": "SYSTÈME / ESPACE / PRÉFÉRENCES",
  "Tune your workspace and understand every active system boundary from one place.": "Personnalisez votre espace et comprenez chaque périmètre actif du système depuis un seul endroit.",
  "SECRET-SAFE": "SANS SECRETS",
  "Configuration summary": "Résumé de la configuration",
  "Workspace": "Espace de travail",
  "Personalized": "Personnalisé",
  "Saved in this browser": "Enregistré dans ce navigateur",
  "Checking…": "Vérification…",
  "Tools and ticket control plane": "Plan de contrôle des outils et tickets",
  "Connections": "Connexions",
  "Enabled system integrations": "Intégrations système activées",
  "Security": "Sécurité",
  "Protected": "Protégé",
  "TLS, authentication and approvals": "TLS, authentification et approbations",
  "Search settings and integrations": "Rechercher des paramètres et intégrations",
  "Filter configuration": "Filtrer la configuration",
  "Workspace": "Espace de travail",
  "AI & operations": "IA et opérations",
  "Integrations": "Intégrations",
  "YOUR WORKSPACE": "VOTRE ESPACE",
  "Interface & accessibility": "Interface et accessibilité",
  "These settings apply immediately and remain on this browser.": "Ces paramètres s’appliquent immédiatement et restent dans ce navigateur.",
  "LOCAL": "LOCAL",
  "Choose from every installed visual theme": "Choisissez parmi tous les thèmes visuels installés",
  "Interface, labels and navigation": "Interface, libellés et navigation",
  "Scalable typography across the whole app": "Typographie adaptable dans toute l’application",
  "Control information spacing": "Ajuster l’espacement des informations",
  "Default destination when opening Monique": "Destination par défaut à l’ouverture de Monique",
  "ASSISTANT DEFAULTS": "PARAMÈTRES DE L’ASSISTANTE",
  "AI & live behavior": "IA et comportement en temps réel",
  "Choose how Monique starts conversations and refreshes operational context.": "Choisissez comment Monique démarre les conversations et actualise le contexte opérationnel.",
  "Default reasoning profile": "Profil de raisonnement par défaut",
  "Used for new conversations": "Utilisé pour les nouvelles conversations",
  "Live refresh rate": "Fréquence d’actualisation",
  "Status polling while this tab is visible": "Actualisation de l’état lorsque cet onglet est visible",
  "Every 5 seconds": "Toutes les 5 secondes",
  "Every 10 seconds": "Toutes les 10 secondes",
  "Every 30 seconds": "Toutes les 30 secondes",
  "Every minute": "Chaque minute",
  "Technical values": "Valeurs techniques",
  "Show detailed limits and runtime vocabulary": "Afficher les limites détaillées et le vocabulaire d’exécution",
  "Attention notifications": "Notifications d’attention",
  "Notify when a new operational risk appears": "Notifier lorsqu’un nouveau risque opérationnel apparaît",
  "EFFECTIVE SYSTEM": "SYSTÈME EFFECTIF",
  "Runtime configuration": "Configuration d’exécution",
  "Validated, secret-safe values reported by the running system.": "Valeurs validées et sans secrets signalées par le système actif.",
  "No matching settings": "Aucun paramètre correspondant",
  "Try a broader search or another category.": "Essayez une recherche plus large ou une autre catégorie.",
  "GUIDED SETUP": "CONFIGURATION GUIDÉE",
  "Configure safely with Monique": "Configurer en sécurité avec Monique",
  "Credentials remain outside this browser. Monique can inspect the active contract, collect only the missing details, and stage reviewable changes.": "Les identifiants restent hors de ce navigateur. Monique peut examiner le contrat actif, recueillir uniquement les éléments manquants et préparer des changements vérifiables.",
  "Review configuration": "Examiner la configuration",
  "Protected by design": "Protégé dès la conception",
  "Secrets never rendered": "Secrets jamais affichés",
  "Tokens and credentials are structurally absent.": "Les jetons et identifiants sont structurellement absents.",
  "Mutations require approval": "Modifications soumises à approbation",
  "AI Operations actions remain staged first.": "Les actions AI Operations sont toujours préparées avant exécution.",
  "Runtime-owned settings": "Paramètres gérés par l’exécution",
  "Deployment settings stay validated and auditable.": "Les paramètres de déploiement restent validés et auditables.",
  "Secret-safe projection": "Projection sans secrets",
  "Account identifiers, filesystem locations, provider payloads and credential material are never returned by this screen.": "Les références de compte, emplacements de fichiers, données fournisseur et identifiants ne sont jamais renvoyés par cet écran.",
  "Configuration preference saved.": "Préférence de configuration enregistrée.",
  "Notifications are not available in this browser.": "Les notifications ne sont pas disponibles dans ce navigateur.",
  "Notification permission was not granted.": "L’autorisation de notification n’a pas été accordée.",
  "Runtime configuration refreshed.": "La configuration d’exécution a été actualisée.",
  "Authenticated network boundary and request limits.": "Périmètre réseau authentifié et limites de requête.",
  "Durable evidence, retention and retrieval behavior.": "Éléments durables, conservation et comportement de récupération.",
  "Contained model execution and provider readiness.": "Exécution cloisonnée des modèles et disponibilité des fournisseurs.",
  "Channels and external service connections.": "Canaux et connexions aux services externes.",
  "Live tools, tickets and approval-aware control plane.": "Outils en temps réel, tickets et plan de contrôle soumis aux approbations.",
  "Governance & safety": "Gouvernance et sécurité",
  "Approval, audit, backup and observation controls.": "Contrôles d’approbation, d’audit, de sauvegarde et d’observation.",
  "Extensions & automation": "Extensions et automatisation",
  "MCP, knowledge, skills and automation surfaces.": "Surfaces MCP, connaissances, compétences et automatisation.",
  "Effective runtime configuration.": "Configuration d’exécution effective.",
  "INTEGRATION": "INTÉGRATION",
  "INTELLIGENCE": "INTELLIGENCE",
  "SYSTEM": "SYSTÈME",
  "Connected": "Connecté",
  "Not attached": "Non connecté",
  "Effective · secret-safe": "Effectif · sans secrets",
  "Configure with Monique →": "Configurer avec Monique →",
  "Review the complete system configuration. Identify missing or unhealthy integrations, explain the safest next configuration change, and stage any mutation for my explicit approval.": "Examine la configuration complète du système. Identifie les intégrations manquantes ou défaillantes, explique la prochaine modification la plus sûre et prépare toute action pour mon approbation explicite.",
  "Effective capabilities, boundaries, and limits—not credentials or private coordinates.": "Fonctionnalités, limites et périmètres effectifs — sans identifiants ni coordonnées privées.",
  "SECRETS CONCEALED": "SECRETS MASQUÉS",
  "Values are allowlisted.": "Les valeurs sont explicitement autorisées.",
  "Credentials, account identifiers, filesystem locations and provider payloads are structurally absent from this API.": "Les identifiants, références de compte, emplacements de fichiers et charges utiles fournisseur sont structurellement absents de cette API.",
  "Loading effective configuration…": "Chargement de la configuration effective…",
  "REFRESH": "ACTUALISER",
  "NO VERIFIED SNAPSHOT": "AUCUN INSTANTANÉ VÉRIFIÉ",
  "YES": "OUI",
  "NO": "NON",
  "WAIT": "ATTENTE",
  "REVIEW": "À EXAMINER",
  "ACTIVE": "ACTIF",
  "CLEAR": "CLAIR",
  "AVAILABLE": "DISPONIBLE",
  "UNAVAILABLE": "INDISPONIBLE",
  "STALE": "PÉRIMÉ",
  "CURRENT": "ACTUEL",
  "operational": "opérationnel",
  "degraded": "dégradé",
  "unavailable": "indisponible",
  "ready": "prêt",
  "All operational invariants hold": "Tous les invariants opérationnels sont respectés",
  "Provider, intake, delivery certainty and reconciliation are clear.": "Le fournisseur, l’admission, la certitude de livraison et la réconciliation sont au clair.",
  "runtime health": "santé de l’exécution",
  "stale snapshot": "instantané périmé",
  "reconciliation": "réconciliation",
  "ambiguous effects": "effets ambigus",
  "provider lane": "voie fournisseur",
  "intake closed": "admission fermée",
  "Operational status refreshed.": "L’état opérationnel a été actualisé.",
  "The operational snapshot is unavailable.": "L’instantané opérationnel est indisponible.",
  "All evidence": "Tous les éléments",
  "No memory evidence matches this view.": "Aucun élément de mémoire ne correspond à cette vue.",
  "No evidence nodes to display.": "Aucun nœud d’élément à afficher.",
  "Searching canonical memory…": "Recherche dans la mémoire canonique…",
  "Loading canonical memory…": "Chargement de la mémoire canonique…",
  "Memory retrieval is unavailable.": "La récupération de la mémoire est indisponible.",
  "AI Operations connected": "AI Operations connecté",
  "Live tools are discovered from the authenticated control plane.": "Les outils en temps réel sont découverts depuis le plan de contrôle authentifié.",
  "AI Operations is not attached": "AI Operations n’est pas connecté",
  "Configure one same-origin Manage MCP server to enable live capabilities.": "Configurez un serveur MCP Manage de même origine pour activer les fonctionnalités en temps réel.",
  "AI Operations is unavailable": "AI Operations est indisponible",
  "The configured control plane did not return a valid capability catalog.": "Le plan de contrôle configuré n’a pas renvoyé de catalogue de fonctionnalités valide.",
  "AI Operations is busy": "AI Operations est occupé",
  "Another contained request is using the live tool connection. Try again shortly.": "Une autre requête cloisonnée utilise la connexion aux outils. Réessayez dans un instant.",
  "AI Operations state unknown": "État d’AI Operations inconnu",
  "Refresh to discover the current control-plane state.": "Actualisez pour connaître l’état actuel du plan de contrôle.",
  "No AI Operations tools are currently available to this dashboard.": "Aucun outil AI Operations n’est actuellement disponible dans ce tableau de bord.",
  "SAFE READ": "LECTURE SÛRE",
  "APPROVAL": "APPROBATION",
  "Live AI Operations capability.": "Fonctionnalité AI Operations en temps réel.",
  "Details required": "Détails requis",
  "Ready to plan": "Prêt à planifier",
  "Use with Monique →": "Utiliser avec Monique →",
  "Triaging": "Triage",
  "Closed": "Fermé",
  "Unknown": "Inconnu",
  "The connected ticket queue is currently empty.": "La file de tickets connectée est actuellement vide.",
  "AI Operations is connected, but it does not advertise a zero-input read-only ticket list.": "AI Operations est connecté, mais ne propose aucune liste de tickets en lecture seule sans paramètres.",
  "The ticket source needs additional scope. Ask Monique to retrieve the exact queue you need.": "La source de tickets nécessite un périmètre supplémentaire. Demandez à Monique de récupérer la file précise dont vous avez besoin.",
  "The live ticket source is temporarily unavailable.": "La source de tickets en temps réel est temporairement indisponible.",
  "Attach AI Operations to load the live ticket queue.": "Connectez AI Operations pour charger la file de tickets en temps réel.",
  "No tickets match this filter.": "Aucun ticket ne correspond à ce filtre.",
  "Clear filters": "Effacer les filtres",
  "Ask Monique about tickets": "Interroger Monique sur les tickets",
  "Unassigned": "Non attribué",
  "Details": "Détails",
  "Hide details": "Masquer les détails",
  "Ticket ID": "ID du ticket",
  "Workflow": "Flux de travail",
  "Lifecycle and workflow aligned": "Cycle et flux alignés",
  "Assignee": "Responsable",
  "Requester": "Demandeur",
  "Site": "Site",
  "Source": "Source",
  "Comments": "Commentaires",
  "Created": "Créé",
  "Updated": "Mis à jour",
  "Open ↗": "Ouvrir ↗",
  "AUTHORITY BOUNDED": "AUTORITÉ LIMITÉE",
  "NOT ATTACHED": "NON CONNECTÉ",
  "AI Operations and tickets refreshed.": "AI Operations et les tickets ont été actualisés.",
  "AI Operations unavailable": "AI Operations indisponible",
  "Ticket intake unavailable": "File de tickets indisponible",
  "AI Operations could not be refreshed.": "AI Operations n’a pas pu être actualisé.",
  "Web boundary": "Périmètre web",
  "Providers": "Fournisseurs",
  "Connectors": "Connecteurs",
  "CONFIGURED": "CONFIGURÉ",
  "OFF": "DÉSACTIVÉ",
  "Effective configuration refreshed.": "La configuration effective a été actualisée.",
  "Configuration unavailable": "Configuration indisponible",
  "Configuration projection is unavailable.": "La projection de configuration est indisponible.",
  "YOU": "VOUS",
  "OPERATOR": "OPÉRATEUR",
  "COPY": "COPIER",
  "COPIED": "COPIÉ",
  "Copy is unavailable in this browser.": "La copie est indisponible dans ce navigateur.",
  "APPROVAL REQUIRED": "APPROBATION REQUISE",
  "Review Manage action": "Examiner l’action Manage",
  "Review this action before it runs.": "Examinez cette action avant son exécution.",
  "This action can change external state.": "Cette action peut modifier un état externe.",
  "Deny": "Refuser",
  "Approve and run": "Approuver et exécuter",
  "Running approved action…": "Exécution de l’action approuvée…",
  "Recording denial…": "Enregistrement du refus…",
  "Action completed": "Action terminée",
  "Action denied": "Action refusée",
  "The approved action returned a result.": "L’action approuvée a renvoyé un résultat.",
  "The action was denied.": "L’action a été refusée.",
  "Action refused": "Action rejetée",
  "The action was not completed.": "L’action n’a pas été exécutée.",
  "Monique is working": "Monique travaille",
  "This Manage action is still awaiting your decision.": "Cette action Manage attend toujours votre décision.",
  "History unavailable": "Historique indisponible",
  "Durable chat history is unavailable.": "L’historique durable de la discussion est indisponible.",
  "Monique is finishing another contained turn. Try again in a moment.": "Monique termine un autre échange cloisonné. Réessayez dans un instant.",
  "The configured Slack read is temporarily unavailable.": "La lecture Slack configurée est temporairement indisponible.",
  "The Slack read surface is temporarily busy.": "La surface de lecture Slack est temporairement occupée.",
  "Durable memory is temporarily unavailable.": "La mémoire durable est temporairement indisponible.",
  "This turn could not be retained safely, so it was not run.": "Cet échange n’a pas pu être conservé en toute sécurité et n’a donc pas été exécuté.",
  "Manage AI Operations is temporarily unavailable. No action was run.": "Manage AI Operations est temporairement indisponible. Aucune action n’a été exécutée.",
  "That Manage action is no longer pending. Nothing was run.": "Cette action Manage n’est plus en attente. Rien n’a été exécuté.",
  "That Manage action expired. Ask Monique to prepare it again.": "Cette action Manage a expiré. Demandez à Monique de la préparer à nouveau.",
  "Manage requested another approval step, so execution stopped.": "Manage a demandé une approbation supplémentaire ; l’exécution a donc été arrêtée.",
  "Monique is working…": "Monique travaille…",
  "Turn refused": "Échange refusé",
  "Monique could not complete that turn.": "Monique n’a pas pu terminer cet échange.",
  "Wait for the current turn to finish before starting a new conversation.": "Attendez la fin de l’échange actuel avant de démarrer une nouvelle conversation.",
  "The previous durable conversation was archived. Long-term memory remains available.": "La conversation durable précédente a été archivée. La mémoire à long terme reste disponible.",
  "New durable session": "Nouvelle session durable",
  "A new durable conversation is ready.": "Une nouvelle conversation durable est prête.",
  "The current conversation was not changed.": "La conversation actuelle n’a pas été modifiée.",
  "Explain the current operational health and any risks.": "Explique l’état opérationnel actuel et les risques éventuels.",
  "Summarize the latest relevant Slack messages.": "Résume les derniers messages Slack pertinents.",
  "What do you remember that is most relevant right now? Cite memory references.": "Que retiens-tu de plus pertinent actuellement ? Cite les références de mémoire.",
  "Show me the useful actions available in Manage AI Operations and help me choose the right one.": "Présente-moi les actions utiles disponibles dans Manage AI Operations et aide-moi à choisir la bonne.",
  "Explain Monique’s current operational health and name anything that needs attention.": "Explique l’état opérationnel actuel de Monique et signale tout élément nécessitant une attention.",
  "Summarize the latest relevant Slack messages. Ask me which configured channel if the target is ambiguous.": "Résume les derniers messages Slack pertinents. Demande-moi quel canal configuré utiliser si la cible est ambiguë.",
  "What durable memory is most relevant to the current operational state? Cite its memory references.": "Quelle mémoire durable est la plus pertinente pour l’état opérationnel actuel ? Cite ses références.",
  "Show me the most useful AI Operations actions available right now and help me choose one.": "Présente-moi les actions AI Operations les plus utiles actuellement et aide-moi à en choisir une.",
  "Review the current ticket queue, summarize priorities, and recommend the next action.": "Examine la file de tickets actuelle, résume les priorités et recommande la prochaine action.",
  "Inspect the available AI Operations ticket capabilities and help me retrieve or review the right ticket queue.": "Examine les fonctionnalités de tickets AI Operations disponibles et aide-moi à récupérer ou examiner la bonne file.",
  "Canonical Host": "Hôte canonique",
  "Authentication": "Authentification",
  "Transport Security": "Sécurité du transport",
  "Bind Scope": "Périmètre d’écoute",
  "Status Refresh Seconds": "Actualisation de l’état en secondes",
  "Request Header Limit Bytes": "Limite des en-têtes de requête en octets",
  "Request Body Limit Bytes": "Limite du corps de requête en octets",
  "Worker Count": "Nombre de workers",
  "Queue Depth": "Profondeur de file",
  "Rate Limit Per Minute": "Limite de débit par minute",
  "Store": "Stockage",
  "Retrieval": "Récupération",
  "Tenant": "Espace locataire",
  "Raw Message Retention Days": "Conservation des messages bruts en jours",
  "Writable History": "Historique inscriptible",
  "Primary Configured": "Fournisseur principal configuré",
  "Conversation Configured": "Conversation configurée",
  "Egress Policy Configured": "Politique de sortie configurée",
  "Support": "Assistance",
  "Mcp": "MCP",
  "Profile Source Configured": "Source de profil configurée",
  "Ai Operations Worker Configured": "Worker AI Operations configuré",
  "Agent Tools Configured": "Outils d’agent configurés",
  "Approval Policy Configured": "Politique d’approbation configurée",
  "Memory Policy Configured": "Politique de mémoire configurée",
  "Shadow Observation Configured": "Observation parallèle configurée",
  "Backup Store Available": "Stockage de sauvegarde disponible",
  "Audit Store Available": "Stockage d’audit disponible",
  "Mcp Registry Configured": "Registre MCP configuré",
  "Local Knowledge Configured": "Connaissances locales configurées",
  "Improvement Lab Configured": "Laboratoire d’amélioration configuré",
  "Automations Store Available": "Stockage d’automatisations disponible",
  "Skills Store Available": "Stockage de compétences disponible",
  "Dashboard Authority": "Autorité du tableau de bord",
  "Console": "Console",
  "High": "Élevée",
  "Medium": "Moyenne",
  "Low": "Faible",
  "Normal": "Normale",
  "Urgent": "Urgente",
  "just now": "à l’instant",
  "unknown": "inconnu",
  "conversation": "conversation",
  "sandbox enforceable lane wired": "voie cloisonnée opérationnelle",
  "polling live": "scrutation active",
  "discovered tools / explicit approval": "outils découverts / approbation explicite",
  "contained daemon run lane": "voie d’exécution cloisonnée du démon",
  "same-origin authenticated API": "API authentifiée de même origine",
  "reviewed typed evidence": "éléments typés vérifiés",
  "configured": "configuré",
});
const localizedTextSources = new WeakMap();
const localizedAttributeSources = new WeakMap();
const localizedAttributes = ["aria-label", "placeholder", "title", "data-chat-prompt", "data-open-chat"];
let localizingUi = false;

function translatePhraseForFrench(value) {
  const source = String(value);
  if (frenchUi[source]) return frenchUi[source];
  const replacements = [
    [/^Appearance\. Current theme: (.+)$/, (match) => `Apparence. Thème actuel : ${translatePhraseForFrench(match[1])}`],
    [/^Appearance · (.+)$/, (match) => `Apparence · ${translatePhraseForFrench(match[1])}`],
    [/^Text size: (.+)\. Increase text size$/, (match) => `Taille du texte : ${translatePhraseForFrench(match[1])}. Augmenter la taille du texte`],
    [/^Updated (.+)$/, (match) => `Mis à jour ${match[1]}`],
    [/^(\d+) seconds$/, (match) => `${match[1]} secondes`],
    [/^(\d+)s ago$/, (match) => `il y a ${match[1]} s`],
    [/^(\d+)m ago$/, (match) => `il y a ${match[1]} min`],
    [/^(\d+)h ago$/, (match) => `il y a ${match[1]} h`],
    [/^(\d+) connected$/, (match) => `${match[1]} connecté${match[1] === "1" ? "" : "s"}`],
    [/^(\d+) invariants? need attention$/, (match) => `${match[1]} invariant${match[1] === "1" ? " requiert" : "s requièrent"} votre attention`],
    [/^(.+?) active$/, (match) => `${match[1]} en cours`],
    [/^(.+?) pending$/, (match) => `${match[1]} en attente`],
    [/^(.+?) of (.+?) tickets$/, (match) => `${match[1]} ticket${match[1] === "1" ? "" : "s"} sur ${match[2]}`],
    [/^(.+?) evidence records?(?: for “(.+)”)?$/, (match) => `${match[1]} enregistrement${match[1] === "1" ? "" : "s"} d’éléments${match[2] ? ` pour « ${match[2]} »` : ""}`],
    [/^Memory unavailable · (.+)$/, (match) => `Mémoire indisponible · ${match[1]}`],
    [/^Open (.+) in the record list$/, (match) => `Ouvrir ${match[1]} dans la liste des enregistrements`],
    [/^Assigned to (.+?)(?: · Updated (.+))?$/, (match) => `Attribué à ${match[1]}${match[2] ? ` · Mis à jour ${match[2]}` : ""}`],
    [/^Unassigned(?: · Updated (.+))?$/, (match) => `Non attribué${match[1] ? ` · Mis à jour ${match[1]}` : ""}`],
    [/^(.+) priority$/, (match) => `Priorité ${translatePhraseForFrench(match[1]).toLowerCase()}`],
    [/^Live source · (.+)$/, (match) => `Source en temps réel · ${match[1]}`],
    [/^Workflow · (.+)$/, (match) => `Flux de travail · ${translatePhraseForFrench(match[1])}`],
    [/^Workflow mismatch · (.+)$/, (match) => `Écart de flux · ${translatePhraseForFrench(match[1])}`],
    [/^(\S+) LIVE$/, (match) => `${match[1]} EN TEMPS RÉEL`],
    [/^LIVE · (.+)$/, (match) => `TEMPS RÉEL · ${translatePhraseForFrench(match[1])}`],
    [/^Monique is working · (.+)$/, (match) => `Monique travaille · ${match[1]}`],
    [/^(.+) · retained$/, (match) => `${translatePhraseForFrench(match[1])} · conservé`],
    [/^New chat refused · (.+)$/, (match) => `Nouvelle discussion refusée · ${match[1]}`],
    [/^The contained conversation lane refused this turn \((.+)\)\.$/, (match) => `La voie de conversation cloisonnée a refusé cet échange (${match[1]}).`],
    [/^Help me use the AI Operations capability “(.+)”\. Explain what it does, collect any required details, and stage any mutation for my approval\.$/, (match) => `Aide-moi à utiliser la fonctionnalité AI Operations « ${match[1]} ». Explique son rôle, recueille les détails nécessaires et prépare toute modification pour mon approbation.`],
    [/^Review ticket (.+): “(.+)”\. Summarize its current state and recommend the next action\.$/, (match) => `Examine le ticket ${match[1]} : « ${match[2]} ». Résume son état actuel et recommande la prochaine action.`],
    [/^Review the (.+) configuration\. Explain its current effective state, identify anything missing, and stage any safe change for my explicit approval\.$/, (match) => `Examine la configuration ${translatePhraseForFrench(match[1])}. Explique son état effectif, identifie les éléments manquants et prépare tout changement sûr pour mon approbation explicite.`],
  ];
  for (const [pattern, replacement] of replacements) {
    const match = source.match(pattern);
    if (match) return replacement(match);
  }
  return source;
}

function translatePhrase(value) {
  return currentLanguage === "fr" ? translatePhraseForFrench(value) : String(value);
}

function translateSpacingForFrench(value) {
  const match = String(value).match(/^(\s*)(.*?)(\s*)$/s);
  return `${match[1]}${translatePhraseForFrench(match[2])}${match[3]}`;
}

function translateSpacing(value) {
  return currentLanguage === "fr" ? translateSpacingForFrench(value) : String(value);
}

function localizationSkipped(node) {
  const element = node.nodeType === Node.ELEMENT_NODE ? node : node.parentElement;
  return Boolean(element?.closest("[data-i18n-skip]"));
}

function localizeTextNode(node) {
  if (localizationSkipped(node) || !node.nodeValue?.trim()) return;
  const current = node.nodeValue;
  let source = localizedTextSources.get(node);
  if (source === undefined || (current !== source && current !== translateSpacingForFrench(source))) {
    source = current;
    localizedTextSources.set(node, source);
  }
  const localized = currentLanguage === "fr" ? translateSpacing(source) : source;
  if (node.nodeValue !== localized) node.nodeValue = localized;
}

function localizeAttribute(element, attribute) {
  if (localizationSkipped(element) || !element.hasAttribute(attribute)) return;
  let sources = localizedAttributeSources.get(element);
  if (!sources) {
    sources = new Map();
    localizedAttributeSources.set(element, sources);
  }
  const current = element.getAttribute(attribute);
  let source = sources.get(attribute);
  if (source === undefined || (current !== source && current !== translatePhraseForFrench(source))) {
    source = current;
    sources.set(attribute, source);
  }
  const localized = currentLanguage === "fr" ? translatePhrase(source) : source;
  if (current !== localized) element.setAttribute(attribute, localized);
}

function localizeUi(root = document.body) {
  if (!root || localizingUi) return;
  localizingUi = true;
  try {
    const base = root.nodeType === Node.TEXT_NODE ? root.parentElement : root;
    if (!base) return;
    const walker = document.createTreeWalker(base, NodeFilter.SHOW_TEXT);
    if (root.nodeType === Node.TEXT_NODE) localizeTextNode(root);
    else while (walker.nextNode()) localizeTextNode(walker.currentNode);
    const elements = [];
    if (base.nodeType === Node.ELEMENT_NODE) elements.push(base);
    elements.push(...base.querySelectorAll("*"));
    elements.forEach((element) => localizedAttributes.forEach((attribute) => localizeAttribute(element, attribute)));
  } finally {
    localizingUi = false;
  }
}

function applyLanguage(language, persist = true) {
  currentLanguage = supportedLanguages.includes(language) ? language : "en";
  document.documentElement.lang = currentLanguage;
  document.documentElement.dataset.language = currentLanguage;
  byId("language-select").value = currentLanguage;
  if (byId("configuration-language")) byId("configuration-language").value = currentLanguage;
  const target = currentLanguage === "en" ? "fr" : "en";
  byId("language-cycle").textContent = target.toUpperCase();
  byId("language-cycle").setAttribute("aria-label", target === "fr" ? "Switch to French" : "Switch to English");
  byId("language-cycle").title = "Language";
  if (persist) savePreference("monique-language", currentLanguage);
  if (lastStatusSnapshot) renderStatus(lastStatusSnapshot);
  else {
    updateObservedAge();
    renderPulse();
  }
  if (memorySnapshot) renderSelectedMemory();
  if (operationsSnapshot) renderOperations(operationsSnapshot);
  document.querySelectorAll(".message-meta[data-created-at]").forEach(renderMessageMeta);
  localizeUi(document.body);
}

function observeLocalization() {
  const observer = new MutationObserver((mutations) => {
    if (localizingUi) return;
    mutations.forEach((mutation) => {
      if (mutation.type === "characterData") localizeUi(mutation.target);
      else if (mutation.type === "attributes") localizeUi(mutation.target);
      else mutation.addedNodes.forEach((node) => localizeUi(node));
    });
  });
  observer.observe(document.body, { subtree: true, childList: true, characterData: true, attributes: true, attributeFilter: localizedAttributes });
}
const themeNames = {
  system: "System",
  dark: "Carbon",
  light: "Paper",
  midnight: "Midnight",
  ocean: "Ocean",
  forest: "Forest",
  monokai: "Monokai",
  dracula: "Dracula",
  nord: "Nord",
  sand: "Sand",
  rose: "Rose",
  contrast: "High contrast",
};
const themeColors = {
  dark: "#0b0d10",
  light: "#f7f7f5",
  midnight: "#090a14",
  ocean: "#061116",
  forest: "#0a110d",
  monokai: "#272822",
  dracula: "#282a36",
  nord: "#2e3440",
  sand: "#f5efe5",
  rose: "#faf2f4",
  contrast: "#000000",
};
const themes = Object.keys(themeNames);
const textScaleNames = {
  compact: "Compact",
  standard: "Standard",
  comfortable: "Comfortable",
  large: "Large",
  "extra-large": "Extra large",
};
const textScales = Object.keys(textScaleNames);
const sidebarStates = ["expanded", "collapsed"];
const densityNames = { compact: "Compact", comfortable: "Comfortable", spacious: "Spacious" };
const densities = Object.keys(densityNames);
const motionModes = ["full", "reduce"];
const startupViews = ["chat", "overview", "operations", "tickets"];

function storedPreference(key, allowed, fallback) {
  try {
    const value = window.localStorage.getItem(key);
    return allowed.includes(value) ? value : fallback;
  } catch (_error) {
    return fallback;
  }
}

function savePreference(key, value) {
  try {
    window.localStorage.setItem(key, value);
  } catch (_error) {
    // Private browsing and hardened storage policies may refuse persistence.
  }
}

function resolvedTheme(theme) {
  return theme === "system"
    ? (window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark")
    : theme;
}

function applyTheme(theme, persist = true) {
  if (!themes.includes(theme)) theme = "system";
  document.documentElement.dataset.theme = theme;
  byId("theme-select").value = theme;
  if (byId("configuration-theme")) byId("configuration-theme").value = theme;
  const resolved = resolvedTheme(theme);
  byId("theme-cycle").dataset.theme = theme;
  byId("theme-cycle").setAttribute("aria-label", `Appearance. Current theme: ${themeNames[theme]}`);
  byId("theme-cycle").title = `Appearance · ${themeNames[theme]}`;
  byId("sidebar-theme-name").textContent = themeNames[theme];
  byId("theme-color").content = themeColors[resolved] || themeColors.dark;
  document.querySelectorAll("[data-theme-choice]").forEach((button) => {
    const active = button.dataset.themeChoice === theme;
    button.classList.toggle("is-active", active);
    button.setAttribute("aria-pressed", String(active));
  });
  if (persist) savePreference("monique-theme", theme);
}

function applyTextScale(scale, persist = true) {
  if (!textScales.includes(scale)) scale = "comfortable";
  document.documentElement.dataset.textScale = scale;
  byId("text-scale-cycle").dataset.scale = scale;
  byId("text-scale-cycle").setAttribute("aria-label", `Text size: ${textScaleNames[scale]}. Increase text size`);
  byId("text-scale-name").textContent = textScaleNames[scale];
  byId("text-scale-input").value = String(textScales.indexOf(scale));
  if (byId("configuration-text-scale")) byId("configuration-text-scale").value = scale;
  if (persist) savePreference("monique-text-scale", scale);
}

function applySidebar(state, persist = true) {
  if (!sidebarStates.includes(state)) state = "expanded";
  document.documentElement.dataset.sidebar = state;
  const expanded = state === "expanded";
  byId("sidebar-toggle").setAttribute("aria-expanded", String(expanded));
  byId("sidebar-collapse").setAttribute("aria-label", expanded ? "Collapse sidebar" : "Expand sidebar");
  byId("sidebar-collapse").title = expanded ? "Collapse sidebar" : "Expand sidebar";
  byId("sidebar-collapse").firstElementChild.textContent = expanded ? "‹" : "›";
  if (persist) savePreference("monique-sidebar", state);
}

function applyDensity(density, persist = true) {
  if (!densities.includes(density)) density = "comfortable";
  document.documentElement.dataset.density = density;
  if (byId("configuration-density")) byId("configuration-density").value = density;
  document.querySelectorAll("[data-density-choice]").forEach((button) => {
    const active = button.dataset.densityChoice === density;
    button.classList.toggle("is-active", active);
    button.setAttribute("aria-pressed", String(active));
  });
  if (persist) savePreference("monique-density", density);
}

function applyMotion(mode, persist = true) {
  if (!motionModes.includes(mode)) mode = "full";
  document.documentElement.dataset.motion = mode;
  byId("reduce-motion").checked = mode === "reduce";
  if (byId("configuration-motion")) byId("configuration-motion").checked = mode === "reduce";
  if (persist) savePreference("monique-motion", mode);
}

function applyStartupView(view, persist = true) {
  if (!startupViews.includes(view)) view = "chat";
  byId("startup-view").value = view;
  if (byId("configuration-startup")) byId("configuration-startup").value = view;
  if (persist) savePreference("monique-start-view", view);
}

applyTheme(storedPreference("monique-theme", themes, "system"), false);
applyTextScale(storedPreference("monique-text-scale", textScales, "comfortable"), false);
applySidebar(storedPreference("monique-sidebar", sidebarStates, "expanded"), false);
applyDensity(storedPreference("monique-density", densities, "comfortable"), false);
applyMotion(storedPreference("monique-motion", motionModes, "full"), false);
applyStartupView(storedPreference("monique-start-view", startupViews, "chat"), false);
applyLanguage(currentLanguage, false);
observeLocalization();

byId("language-select").addEventListener("change", (event) => applyLanguage(event.target.value));
byId("language-cycle").addEventListener("click", () => applyLanguage(currentLanguage === "en" ? "fr" : "en"));
byId("theme-select").addEventListener("change", (event) => applyTheme(event.target.value));
document.querySelectorAll("[data-theme-choice]").forEach((button) => button.addEventListener("click", () => applyTheme(button.dataset.themeChoice)));
byId("text-scale-cycle").addEventListener("click", () => {
  const current = document.documentElement.dataset.textScale || "comfortable";
  applyTextScale(textScales[(textScales.indexOf(current) + 1) % textScales.length]);
});
byId("text-scale-input").addEventListener("input", (event) => applyTextScale(textScales[Number(event.target.value)]));
byId("text-scale-down").addEventListener("click", () => {
  const current = textScales.indexOf(document.documentElement.dataset.textScale || "comfortable");
  applyTextScale(textScales[Math.max(0, current - 1)]);
});
byId("text-scale-up").addEventListener("click", () => {
  const current = textScales.indexOf(document.documentElement.dataset.textScale || "comfortable");
  applyTextScale(textScales[Math.min(textScales.length - 1, current + 1)]);
});
window.matchMedia("(prefers-color-scheme: light)").addEventListener("change", () => {
  if (document.documentElement.dataset.theme === "system") applyTheme("system", false);
});

function appearanceOpen(open) {
  byId("appearance-panel").hidden = !open;
  byId("theme-cycle").setAttribute("aria-expanded", String(open));
  byId("sidebar-appearance").setAttribute("aria-expanded", String(open));
  if (open) byId("appearance-close").focus();
}

function mobileSidebarOpen(open) {
  if (open) document.documentElement.dataset.mobileSidebar = "open";
  else delete document.documentElement.dataset.mobileSidebar;
  byId("sidebar-backdrop").hidden = !open;
  byId("sidebar-toggle").setAttribute("aria-expanded", String(open));
}

[byId("theme-cycle"), byId("sidebar-appearance")].forEach((button) => button.addEventListener("click", () => {
  appearanceOpen(byId("appearance-panel").hidden);
}));
byId("appearance-close").addEventListener("click", () => appearanceOpen(false));
byId("sidebar-collapse").addEventListener("click", () => {
  const current = document.documentElement.dataset.sidebar || "expanded";
  applySidebar(current === "expanded" ? "collapsed" : "expanded");
});
byId("sidebar-toggle").addEventListener("click", () => {
  if (window.matchMedia("(max-width: 760px)").matches) {
    mobileSidebarOpen(document.documentElement.dataset.mobileSidebar !== "open");
  } else {
    const current = document.documentElement.dataset.sidebar || "expanded";
    applySidebar(current === "expanded" ? "collapsed" : "expanded");
  }
});
byId("sidebar-backdrop").addEventListener("click", () => mobileSidebarOpen(false));
document.querySelectorAll("[data-density-choice]").forEach((button) => button.addEventListener("click", () => applyDensity(button.dataset.densityChoice)));
byId("reduce-motion").addEventListener("change", (event) => applyMotion(event.target.checked ? "reduce" : "full"));
byId("startup-view").addEventListener("change", (event) => applyStartupView(event.target.value));
byId("reset-appearance").addEventListener("click", () => {
  applyTheme("system");
  applyTextScale("comfortable");
  applyDensity("comfortable");
  applyMotion("full");
  applyStartupView("chat");
  toast("Appearance settings reset.");
});
document.addEventListener("pointerdown", (event) => {
  if (byId("appearance-panel").hidden) return;
  if (event.target.closest("#appearance-panel, #theme-cycle, #sidebar-appearance")) return;
  appearanceOpen(false);
});

async function api(path, options = {}) {
  const request = () => fetch(path, {
    cache: "no-store",
    credentials: "same-origin",
    ...options,
    headers: { Accept: "application/json", ...(options.headers || {}) },
  });
  let response = await request();
  // The authenticated document response mints the HttpOnly API session. Some
  // browsers can start a deferred script's first fetch before that cookie has
  // finished committing, so retry that one bootstrap race exactly once.
  if (response.status === 401) {
    await new Promise((resolve) => window.setTimeout(resolve, 50));
    response = await request();
  }
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.error || `HTTP ${response.status}`);
  return payload;
}

function toast(message, kind = "info") {
  const item = document.createElement("div");
  item.className = `toast ${kind === "error" ? "error" : ""}`;
  item.textContent = message;
  byId("toast-region").append(item);
  window.setTimeout(() => item.remove(), 4200);
}

function attention(status) {
  const issues = [];
  if (status.health !== "operational") issues.push("runtime health");
  if (status.stale) issues.push("stale snapshot");
  if ((status.reconciliation_pending || 0) > 0) issues.push("reconciliation");
  if ((status.outbox_ambiguous || 0) > 0) issues.push("ambiguous effects");
  if (status.provider_available === false) issues.push("provider lane");
  if (status.accepting_intake === false) issues.push("intake closed");
  return [...new Set(issues)];
}

function pipelineState(value, danger = false) {
  if (!Number.isSafeInteger(value)) return "WAIT";
  if (danger && value > 0) return "REVIEW";
  return value > 0 ? "ACTIVE" : "CLEAR";
}

function relativeDuration(milliseconds) {
  if (!Number.isFinite(milliseconds) || milliseconds < 0) return "unknown";
  if (milliseconds < 1000) return "just now";
  const seconds = Math.floor(milliseconds / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  return `${Math.floor(minutes / 60)}h ago`;
}

function updateObservedAge() {
  if (!Number.isSafeInteger(lastObservedMs)) {
    byId("global-observed").textContent = "No snapshot";
    byId("global-observed").removeAttribute("title");
    return;
  }
  const observed = new Date(lastObservedMs);
  byId("global-observed").textContent = `Updated ${relativeDuration(Date.now() - lastObservedMs)}`;
  byId("global-observed").title = observed.toLocaleString(localeTag());
}

function recordStatus(status) {
  if (!Number.isSafeInteger(status.observed_ms) || status.observed_ms === lastObservedMs) return;
  lastObservedMs = status.observed_ms;
  const sample = {
    at: Date.now(),
    running: safeMetric(status.running),
    inbox: safeMetric(status.inbox_pending),
    outbox: safeMetric(status.outbox_pending),
  };
  const key = `${sample.running}:${sample.inbox}:${sample.outbox}`;
  if (lastStatusKey !== null && key !== lastStatusKey) lastPulseChangeAt = sample.at;
  if (lastPulseChangeAt === null) lastPulseChangeAt = sample.at;
  lastStatusKey = key;
  statusHistory.push(sample);
  if (statusHistory.length > 30) statusHistory.shift();
  renderPulse();
}

function pulsePoints(field, maximum) {
  if (statusHistory.length === 0) return "";
  return statusHistory.map((sample, index) => {
    const x = statusHistory.length === 1 ? 0 : (index / (statusHistory.length - 1)) * 720;
    const y = 140 - (sample[field] / maximum) * 118;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(" ");
}

function renderPulse() {
  const maximum = Math.max(1, ...statusHistory.flatMap((sample) => [sample.running, sample.inbox, sample.outbox]));
  ["running", "inbox", "outbox"].forEach((field) => {
    byId(`pulse-${field}`).setAttribute("points", pulsePoints(field, maximum));
  });
  byId("pulse-samples").textContent = count(statusHistory.length);
  const windowMs = statusHistory.length > 1 ? statusHistory.at(-1).at - statusHistory[0].at : 0;
  byId("pulse-window").textContent = windowMs < 1000 ? "Just started" : `${Math.max(1, Math.round(windowMs / 1000))} seconds`;
  byId("pulse-change").textContent = lastPulseChangeAt === null ? "Waiting" : relativeDuration(Date.now() - lastPulseChangeAt);
  byId("pulse-tag").textContent = statusHistory.length > 1 ? "LIVE" : "COLLECTING";
}

function renderStatus(status) {
  lastStatusSnapshot = status;
  const health = ["operational", "degraded", "unavailable"].includes(status.health) ? status.health : "unavailable";
  document.documentElement.dataset.health = health;
  const issues = attention(status);
  const attentionKey = `${health}:${issues.join("|")}`;
  if (lastNotifiedAttentionKey !== null && attentionKey !== lastNotifiedAttentionKey && issues.length > 0
      && storedPreference("monique-notifications", ["on", "off"], "off") === "on"
      && "Notification" in window && Notification.permission === "granted") {
    new Notification("Monique · attention required", { body: issues.join(" · "), tag: "monique-operational-attention" });
  }
  lastNotifiedAttentionKey = attentionKey;
  byId("global-health").textContent = health;
  byId("generation").textContent = `GEN ${count(status.generation)}`;
  byId("footer-state").textContent = `${health.toUpperCase()} / GEN ${count(status.generation)}`;
  byId("attention-title").textContent = issues.length === 0 ? "All operational invariants hold" : `${issues.length} invariant${issues.length === 1 ? "" : "s"} need attention`;
  byId("attention-detail").textContent = issues.length === 0 ? "Provider, intake, delivery certainty and reconciliation are clear." : issues.join(" · ");
  byId("metric-running").textContent = count(status.running);
  byId("metric-inbox").textContent = count(status.inbox_pending);
  byId("metric-outbox").textContent = count(status.outbox_pending);
  byId("metric-reconciliation").textContent = count(status.reconciliation_pending);
  byId("metric-ambiguous").textContent = count(status.outbox_ambiguous);
  byId("metric-attention").textContent = count(issues.length);
  byId("runtime-daemon").textContent = words(status.state);
  byId("runtime-provider").textContent = status.provider_available === true ? "AVAILABLE" : status.provider_available === false ? "UNAVAILABLE" : "—";
  byId("runtime-intake").textContent = yesNo(status.accepting_intake);
  byId("runtime-execution").textContent = words(status.execution_state);
  byId("runtime-telegram").textContent = words(status.telegram_state);
  byId("runtime-snapshot").textContent = status.stale ? "STALE" : "CURRENT";
  byId("runtime-tag").textContent = issues.length === 0 ? "CLEAR" : "REVIEW";
  const pipeline = [
    ["inbox", status.inbox_pending, false],
    ["running", status.running, false],
    ["outbox", status.outbox_pending, false],
    ["reconcile", status.reconciliation_pending, true],
  ];
  pipeline.forEach(([name, value, danger]) => {
    byId(`pipe-${name}`).textContent = `${count(value)} ${name === "running" ? "active" : "pending"}`;
    byId(`pipe-${name}-state`).textContent = pipelineState(value, danger);
  });
  recordStatus(status);
  updateObservedAge();
}

async function refreshStatus({ announce = false } = {}) {
  const button = byId("status-refresh");
  button.disabled = true;
  try {
    renderStatus(await api("/api/status"));
    if (announce) toast("Operational status refreshed.");
  } catch (_error) {
    renderStatus({ health: "unavailable", stale: true });
    if (announce) toast("The operational snapshot is unavailable.", "error");
  } finally {
    button.disabled = false;
  }
}

function showView(name) {
  const allowed = ["overview", "chat", "operations", "tickets", "memory", "configuration"];
  if (!allowed.includes(name)) name = "overview";
  document.querySelectorAll("[data-panel]").forEach((node) => node.classList.toggle("is-visible", node.dataset.panel === name));
  document.querySelectorAll("[data-view]").forEach((node) => {
    const active = node.dataset.view === name;
    node.classList.toggle("is-active", active);
    if (active) node.setAttribute("aria-current", "page"); else node.removeAttribute("aria-current");
  });
  byId("current-view").textContent = name.toUpperCase();
  if (window.location.hash !== `#${name}`) history.replaceState(null, "", `#${name}`);
  if (name === "memory") loadMemory(memoryQuery);
  if (name === "operations" || name === "tickets") loadOperations();
  if (name === "configuration") loadConfiguration();
  if (name === "chat") loadChatHistory();
  if (window.matchMedia("(max-width: 760px)").matches) mobileSidebarOpen(false);
}

document.querySelectorAll("[data-view]").forEach((button) => button.addEventListener("click", () => showView(button.dataset.view)));
window.addEventListener("hashchange", () => showView(window.location.hash.slice(1)));
byId("status-refresh").addEventListener("click", () => refreshStatus({ announce: true }));

function selectedMemoryEntries() {
  const entries = memorySnapshot?.entries || [];
  return memoryKind === "all" ? entries : entries.filter((entry) => entry.kind === memoryKind);
}

function updateMemoryKinds(entries) {
  const select = byId("memory-kind");
  const kinds = [...new Set(entries.map((entry) => entry.kind).filter((kind) => typeof kind === "string"))].sort();
  const previous = memoryKind;
  select.replaceChildren();
  const all = document.createElement("option");
  all.value = "all";
  all.textContent = "All evidence";
  select.append(all);
  kinds.forEach((kind) => {
    const option = document.createElement("option");
    option.value = kind;
    option.textContent = label(kind);
    select.append(option);
  });
  memoryKind = kinds.includes(previous) ? previous : "all";
  select.value = memoryKind;
}

function renderMemory(view) {
  memorySnapshot = view;
  byId("memory-active").textContent = count(view.counts?.active);
  byId("memory-candidates").textContent = count(view.counts?.candidates);
  byId("memory-superseded").textContent = count(view.counts?.superseded);
  byId("memory-messages").textContent = count(view.counts?.messages);
  updateMemoryKinds(view.entries || []);
  renderSelectedMemory();
}

function renderSelectedMemory() {
  const entries = selectedMemoryEntries();
  const scope = memoryKind === "all" ? "evidence" : words(memoryKind);
  const query = memoryQuery ? ` for “${memoryQuery}”` : "";
  byId("memory-result-label").textContent = `${count(entries.length)} ${scope} record${entries.length === 1 ? "" : "s"}${query}`;
  renderMemoryList(entries);
  renderMemoryGraph(entries);
}

function memoryEmpty(message) {
  const empty = document.createElement("div");
  empty.className = "memory-empty";
  empty.textContent = message;
  return empty;
}

function renderMemoryList(entries) {
  const root = byId("memory-list");
  root.replaceChildren();
  if (entries.length === 0) {
    root.append(memoryEmpty("No memory evidence matches this view."));
    return;
  }
  entries.forEach((entry) => {
    const card = document.createElement("article");
    card.className = "memory-record";
    const ref = document.createElement("strong");
    ref.textContent = entry.reference;
    const text = document.createElement("p");
    text.setAttribute("data-i18n-skip", "");
    text.textContent = entry.content;
    const meta = document.createElement("div");
    meta.className = "record-meta";
    meta.textContent = `${words(entry.kind)} · ${entry.confidence / 10}% confidence\n${entry.visibility} · rev ${entry.revision}`;
    card.append(ref, text, meta);
    root.append(card);
  });
}

function renderMemoryGraph(entries) {
  const graph = byId("memory-graph");
  graph.replaceChildren();
  const core = document.createElement("div");
  core.className = "graph-core";
  core.textContent = "MONIQUE";
  graph.append(core);
  if (entries.length === 0) {
    const empty = memoryEmpty("No evidence nodes to display.");
    empty.classList.add("graph-empty");
    graph.append(empty);
    return;
  }
  entries.slice(0, 14).forEach((entry, index) => {
    const node = document.createElement("button");
    node.type = "button";
    node.className = `graph-node slot-${index}`;
    node.setAttribute("aria-label", `Open ${entry.reference} in the record list`);
    const reference = document.createElement("span");
    reference.textContent = `${entry.reference} / ${words(entry.kind).toUpperCase()}`;
    const content = document.createElement("strong");
    content.setAttribute("data-i18n-skip", "");
    content.textContent = entry.content;
    const metadata = document.createElement("small");
    metadata.textContent = `${entry.confidence / 10}% · ${entry.provenance} · R${entry.revision}`;
    node.append(reference, content, metadata);
    node.addEventListener("click", () => {
      document.querySelector("[data-memory-mode='list']").click();
      const match = [...byId("memory-list").children].find((card) => card.firstChild?.textContent === entry.reference);
      match?.scrollIntoView({ behavior: "smooth", block: "center" });
    });
    graph.append(node);
  });
}

async function loadMemory(query = null) {
  memoryQuery = query?.trim() || null;
  byId("memory-clear").hidden = memoryQuery === null;
  byId("memory-result-label").textContent = memoryQuery ? "Searching canonical memory…" : "Loading canonical memory…";
  try {
    const view = memoryQuery === null
      ? await api("/api/memory")
      : await api("/api/memory/search", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ query: memoryQuery }) });
    renderMemory(view);
  } catch (error) {
    byId("memory-result-label").textContent = `Memory unavailable · ${error.message}`;
    toast("Memory retrieval is unavailable.", "error");
  }
}

byId("memory-search").addEventListener("submit", (event) => {
  event.preventDefault();
  loadMemory(byId("memory-query").value);
});
byId("memory-clear").addEventListener("click", () => {
  byId("memory-query").value = "";
  loadMemory(null);
  byId("memory-query").focus();
});
byId("memory-query").addEventListener("input", (event) => {
  byId("memory-clear").hidden = event.target.value.length === 0;
});
byId("memory-kind").addEventListener("change", (event) => {
  memoryKind = event.target.value;
  renderSelectedMemory();
});
document.querySelectorAll("[data-memory-mode]").forEach((button) => button.addEventListener("click", () => {
  document.querySelectorAll("[data-memory-mode]").forEach((item) => item.classList.toggle("is-active", item === button));
  const graphMode = button.dataset.memoryMode === "graph";
  byId("memory-graph").hidden = !graphMode;
  byId("memory-list").hidden = graphMode;
}));

function operationLabel(value) {
  return String(value || "operation").replaceAll("_", " ").replaceAll("-", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function operationsMessage(health) {
  const messages = {
    attached: ["AI Operations connected", "Live tools are discovered from the authenticated control plane."],
    not_attached: ["AI Operations is not attached", "Configure one same-origin Manage MCP server to enable live capabilities."],
    unavailable: ["AI Operations is unavailable", "The configured control plane did not return a valid capability catalog."],
    busy: ["AI Operations is busy", "Another contained request is using the live tool connection. Try again shortly."],
  };
  return messages[health] || ["AI Operations state unknown", "Refresh to discover the current control-plane state."];
}

function renderOperationsCatalog(tools) {
  const root = byId("operations-tool-grid");
  root.replaceChildren();
  if (tools.length === 0) {
    const empty = document.createElement("div");
    empty.className = "integration-empty";
    empty.textContent = "No AI Operations tools are currently available to this dashboard.";
    root.append(empty);
    return;
  }
  tools.forEach((tool) => {
    const card = document.createElement("article");
    card.className = "tool-card";
    const head = document.createElement("div");
    const category = document.createElement("span");
    category.textContent = operationLabel(tool.category);
    const authority = document.createElement("i");
    authority.className = tool.authority === "read_only" ? "safe" : "approval";
    authority.textContent = tool.authority === "read_only" ? "SAFE READ" : "APPROVAL";
    head.append(category, authority);
    const title = document.createElement("strong");
    title.setAttribute("data-i18n-skip", "");
    title.textContent = operationLabel(tool.name);
    const description = document.createElement("p");
    if (tool.description) description.setAttribute("data-i18n-skip", "");
    description.textContent = tool.description || "Live AI Operations capability.";
    const footer = document.createElement("div");
    const input = document.createElement("small");
    input.textContent = tool.requires_input ? "Details required" : "Ready to plan";
    const use = document.createElement("button");
    use.type = "button";
    use.textContent = "Use with Monique →";
    use.dataset.openChat = `Help me use the AI Operations capability “${operationLabel(tool.name)}”. Explain what it does, collect any required details, and stage any mutation for my approval.`;
    footer.append(input, use);
    card.append(head, title, description, footer);
    root.append(card);
  });
}

function ticketStatusLabel(status) {
  const labels = { in_progress: "In progress", triaging: "Triaging", blocked: "Blocked", done: "Done", closed: "Closed", open: "Open", unknown: "Unknown" };
  return labels[status] || operationLabel(status);
}

function ticketMatchesStatus(ticket, filter) {
  if (filter === "all") return true;
  if (filter === "open") return ticket.status === "open" || ticket.status === "triaging";
  if (filter === "in_progress") return ticket.status === "in_progress" || ticket.workflow === "in_progress";
  if (filter === "blocked") return ticket.status === "blocked" || ticket.workflow === "blocked";
  if (filter === "urgent") return ticket.priority === "urgent";
  if (filter === "done") return ticket.status === "done" || ticket.status === "closed";
  return false;
}

function ticketTimestamp(value) {
  const timestamp = typeof value === "string" ? Date.parse(value) : NaN;
  return Number.isFinite(timestamp) ? timestamp : null;
}

function ticketRelativeTime(value) {
  const timestamp = ticketTimestamp(value);
  if (timestamp === null) return null;
  const delta = timestamp - Date.now();
  const absolute = Math.abs(delta);
  const [divisor, unit] = absolute >= 86_400_000
    ? [86_400_000, "day"]
    : absolute >= 3_600_000
      ? [3_600_000, "hour"]
      : [60_000, "minute"];
  return new Intl.RelativeTimeFormat(localeTag(), { numeric: "auto" }).format(Math.round(delta / divisor), unit);
}

function ticketDateLabel(value) {
  const timestamp = ticketTimestamp(value);
  if (timestamp === null) return value || "—";
  return new Intl.DateTimeFormat(localeTag(), { dateStyle: "medium", timeStyle: "short" }).format(timestamp);
}

function ticketPriorityRank(priority) {
  return { urgent: 0, high: 1, normal: 2, low: 3 }[priority] ?? 4;
}

function ticketReferenceLabel(value) {
  const raw = String(value || "unknown").replace(/^#/, "");
  if (raw.length <= 12) return `#${raw}`;
  return `#${raw.slice(0, 8)}…`;
}

function ticketStatusRank(ticket) {
  const status = ticket.workflow === "blocked" ? "blocked" : ticket.workflow === "in_progress" ? "in_progress" : ticket.status;
  return { blocked: 0, in_progress: 1, triaging: 2, open: 3, unknown: 4, done: 5, closed: 6 }[status] ?? 7;
}

function filteredTickets() {
  const items = operationsSnapshot?.tickets?.items || [];
  const query = ticketQuery.trim().toLocaleLowerCase(localeTag());
  const visible = items.filter((ticket) => {
    if (!ticketMatchesStatus(ticket, ticketFilter)) return false;
    if (!query) return true;
    return [ticket.id, ticket.title, ticket.tenant, ticket.site, ticket.assignee, ticket.requester, ticket.source, ticket.status, ticket.workflow]
      .filter(Boolean)
      .some((value) => String(value).toLocaleLowerCase(localeTag()).includes(query));
  });
  return visible.sort((left, right) => {
    let order = 0;
    if (ticketSort === "priority") order = ticketPriorityRank(left.priority) - ticketPriorityRank(right.priority);
    if (ticketSort === "status") order = ticketStatusRank(left) - ticketStatusRank(right);
    if (ticketSort === "created_asc") order = (ticketTimestamp(left.created_at) ?? Number.MAX_SAFE_INTEGER) - (ticketTimestamp(right.created_at) ?? Number.MAX_SAFE_INTEGER);
    if (ticketSort === "title") order = left.title.localeCompare(right.title, localeTag());
    if (ticketSort === "updated_desc") order = (ticketTimestamp(right.updated_at) ?? 0) - (ticketTimestamp(left.updated_at) ?? 0);
    return order || String(left.id).localeCompare(String(right.id), localeTag(), { numeric: true });
  });
}

function safeTicketLink(value) {
  try {
    const parsed = new URL(value);
    return parsed.protocol === "https:" && !parsed.username && !parsed.password ? parsed.href : null;
  } catch (_error) {
    return null;
  }
}

function ticketEmptyMessage(health) {
  const messages = {
    empty: "The connected ticket queue is currently empty.",
    no_read_surface: "AI Operations is connected, but it does not advertise a zero-input read-only ticket list.",
    input_required: "The ticket source needs additional scope. Ask Monique to retrieve the exact queue you need.",
    unavailable: "The live ticket source is temporarily unavailable.",
    not_attached: "Attach AI Operations to load the live ticket queue.",
  };
  return messages[health] || "No tickets match this filter.";
}

function setTicketFilter(filter) {
  ticketFilter = filter;
  document.querySelectorAll("[data-ticket-filter]").forEach((item) => {
    const active = item.dataset.ticketFilter === filter;
    item.classList.toggle("is-active", active);
    item.setAttribute("aria-pressed", String(active));
  });
  document.querySelectorAll("[data-ticket-filter-shortcut]").forEach((item) => {
    item.classList.toggle("is-active", item.dataset.ticketFilterShortcut === filter);
  });
}

function ticketDetail(labelText, value, title = null) {
  const detail = document.createElement("div");
  detail.className = "ticket-detail";
  const labelNode = document.createElement("span");
  labelNode.textContent = labelText;
  const valueNode = document.createElement("strong");
  valueNode.setAttribute("data-i18n-skip", "");
  valueNode.textContent = value || "—";
  if (title) valueNode.title = title;
  detail.append(labelNode, valueNode);
  return detail;
}

function renderTickets() {
  const tickets = operationsSnapshot?.tickets?.items || [];
  const open = tickets.filter((ticket) => ticketMatchesStatus(ticket, "open")).length;
  const progress = tickets.filter((ticket) => ticketMatchesStatus(ticket, "in_progress")).length;
  const blocked = tickets.filter((ticket) => ticketMatchesStatus(ticket, "blocked")).length;
  const urgent = tickets.filter((ticket) => ticketMatchesStatus(ticket, "urgent")).length;
  const done = tickets.filter((ticket) => ticketMatchesStatus(ticket, "done")).length;
  byId("tickets-total").textContent = count(tickets.length);
  byId("tickets-open").textContent = count(open);
  byId("tickets-progress").textContent = count(progress);
  byId("tickets-blocked").textContent = count(blocked);
  byId("tickets-urgent").textContent = count(urgent);
  [["all", tickets.length], ["open", open], ["progress", progress], ["blocked", blocked], ["urgent", urgent], ["done", done]].forEach(([name, value]) => {
    byId(`ticket-filter-${name}`).textContent = count(value);
  });
  const visible = filteredTickets();
  const health = operationsSnapshot?.tickets?.health || "not_attached";
  byId("tickets-state").textContent = health === "ready"
    ? `${visible.length.toLocaleString(localeTag())} of ${tickets.length.toLocaleString(localeTag())} tickets`
    : ticketEmptyMessage(health);
  const source = operationsSnapshot?.tickets?.source_tool;
  byId("tickets-source").textContent = source ? `Live source · ${operationLabel(source)}` : "Waiting for a live source";
  const root = byId("ticket-list");
  root.replaceChildren();
  if (visible.length === 0) {
    const empty = document.createElement("div");
    empty.className = "integration-empty ticket-empty";
    const title = document.createElement("strong");
    title.textContent = ticketEmptyMessage(health === "ready" ? "filtered" : health);
    const action = document.createElement("button");
    action.type = "button";
    if (health === "ready" && (ticketFilter !== "all" || ticketQuery)) {
      action.textContent = "Clear filters";
      action.addEventListener("click", () => {
        setTicketFilter("all");
        ticketQuery = "";
        byId("tickets-search").value = "";
        byId("tickets-search-clear").hidden = true;
        renderTickets();
      });
    } else {
      action.textContent = "Ask Monique about tickets";
      action.dataset.openChat = "Inspect the available AI Operations ticket capabilities and help me retrieve or review the right ticket queue.";
    }
    empty.append(title, action);
    root.append(empty);
    return;
  }
  visible.forEach((ticket, index) => {
    const card = document.createElement("article");
    card.className = `ticket-card priority-${ticket.priority}`;
    const row = document.createElement("div");
    row.className = "ticket-row";
    const reference = document.createElement("div");
    reference.className = "ticket-reference";
    const dot = document.createElement("i");
    dot.setAttribute("aria-label", `${operationLabel(ticket.priority)} priority`);
    const id = document.createElement("span");
    const fullReference = ticket.id.startsWith("#") ? ticket.id : `#${ticket.id}`;
    id.setAttribute("data-i18n-skip", "");
    id.textContent = ticketReferenceLabel(ticket.id);
    reference.title = fullReference;
    reference.append(dot, id);
    const body = document.createElement("div");
    body.className = "ticket-body";
    const title = document.createElement("strong");
    title.setAttribute("data-i18n-skip", "");
    title.textContent = ticket.title;
    const meta = document.createElement("small");
    const relative = ticketRelativeTime(ticket.updated_at);
    meta.textContent = [ticket.assignee ? `Assigned to ${ticket.assignee}` : "Unassigned", relative ? `Updated ${relative}` : null].filter(Boolean).join(" · ");
    if (ticket.updated_at) meta.title = ticketDateLabel(ticket.updated_at);
    const facts = document.createElement("div");
    facts.className = "ticket-facts";
    [ticket.tenant, ticket.site, ticket.requester ? `By ${ticket.requester}` : null, Number.isSafeInteger(ticket.comments) ? `${ticket.comments} comments` : null]
      .filter(Boolean)
      .slice(0, 3)
      .forEach((value) => {
        const fact = document.createElement("span");
        fact.setAttribute("data-i18n-skip", "");
        fact.textContent = value;
        facts.append(fact);
      });
    body.append(title, meta, facts);
    const lifecycle = document.createElement("div");
    lifecycle.className = "ticket-lifecycle";
    const status = document.createElement("span");
    status.className = `ticket-status status-${ticket.status}`;
    status.textContent = ticketStatusLabel(ticket.status);
    const workflow = document.createElement("small");
    workflow.className = "ticket-workflow";
    const workflowConflict = (ticket.status === "closed" || ticket.status === "done") && !["closed", "done", "unknown"].includes(ticket.workflow);
    const workflowAligned = ticket.status === ticket.workflow;
    if (workflowConflict) workflow.classList.add("is-conflict");
    workflow.textContent = workflowConflict
      ? `Workflow mismatch · ${ticketStatusLabel(ticket.workflow)}`
      : workflowAligned
        ? "Lifecycle and workflow aligned"
        : `Workflow · ${ticketStatusLabel(ticket.workflow)}`;
    lifecycle.append(status, workflow);
    const actions = document.createElement("div");
    actions.className = "ticket-actions";
    const detailId = `ticket-details-${index}`;
    const detailsButton = document.createElement("button");
    detailsButton.type = "button";
    detailsButton.textContent = "Details";
    detailsButton.setAttribute("aria-expanded", "false");
    detailsButton.setAttribute("aria-controls", detailId);
    const ask = document.createElement("button");
    ask.type = "button";
    ask.textContent = "Review";
    ask.dataset.openChat = `Review ticket ${ticket.id}: “${ticket.title}”. Summarize its current state and recommend the next action.`;
    actions.append(detailsButton, ask);
    const href = safeTicketLink(ticket.url);
    if (href) {
      const openLink = document.createElement("a");
      openLink.href = href;
      openLink.target = "_blank";
      openLink.rel = "noreferrer";
      openLink.textContent = "Open ↗";
      actions.append(openLink);
    }
    const details = document.createElement("div");
    details.className = "ticket-details";
    details.id = detailId;
    details.hidden = true;
    [
      ["Ticket ID", fullReference],
      ["Priority", operationLabel(ticket.priority)],
      ["Workflow", ticketStatusLabel(ticket.workflow)],
      ["Assignee", ticket.assignee || "Unassigned"],
      ["Requester", ticket.requester],
      ["Tenant", ticket.tenant],
      ["Site", ticket.site],
      ["Source", ticket.source],
      ["Comments", Number.isSafeInteger(ticket.comments) ? String(ticket.comments) : null],
      ["Created", ticket.created_at ? ticketDateLabel(ticket.created_at) : null, ticket.created_at],
      ["Updated", ticket.updated_at ? ticketDateLabel(ticket.updated_at) : null, ticket.updated_at],
    ].filter(([, value]) => value).forEach(([labelText, value, exact]) => details.append(ticketDetail(labelText, value, exact)));
    detailsButton.addEventListener("click", () => {
      const expanded = detailsButton.getAttribute("aria-expanded") === "true";
      detailsButton.setAttribute("aria-expanded", String(!expanded));
      detailsButton.textContent = expanded ? "Details" : "Hide details";
      details.hidden = expanded;
      card.classList.toggle("is-expanded", !expanded);
    });
    row.append(reference, body, lifecycle, actions);
    card.append(row, details);
    root.append(card);
  });
}

function renderOperations(view) {
  operationsSnapshot = view;
  const [title, detail] = operationsMessage(view.health);
  byId("operations-banner").dataset.state = view.health;
  byId("operations-health").textContent = title;
  byId("operations-detail").textContent = detail;
  byId("operations-authority").textContent = view.health === "attached" ? "AUTHORITY BOUNDED" : "NOT ATTACHED";
  byId("operations-tools").textContent = count(view.tools_total);
  byId("operations-reads").textContent = count(view.read_only_tools);
  byId("operations-actions").textContent = count(view.approval_tools);
  byId("operations-pending").textContent = count(view.pending_actions);
  byId("operations-catalog-tag").textContent = view.health === "attached" ? `${count(view.tools_total)} LIVE` : "UNAVAILABLE";
  renderOperationsCatalog(view.tools || []);
  renderTickets();
}

async function loadOperations(force = false) {
  if (operationsSnapshot && !force) return;
  [byId("operations-refresh"), byId("tickets-refresh")].forEach((button) => { button.disabled = true; });
  try {
    renderOperations(await api("/api/operations"));
    if (force) toast("AI Operations and tickets refreshed.");
  } catch (error) {
    byId("operations-banner").dataset.state = "unavailable";
    byId("operations-health").textContent = "AI Operations unavailable";
    byId("operations-detail").textContent = error.message;
    byId("tickets-state").textContent = "Ticket intake unavailable";
    toast("AI Operations could not be refreshed.", "error");
  } finally {
    [byId("operations-refresh"), byId("tickets-refresh")].forEach((button) => { button.disabled = false; });
  }
}

byId("operations-refresh").addEventListener("click", () => loadOperations(true));
byId("tickets-refresh").addEventListener("click", () => loadOperations(true));
document.querySelectorAll("[data-ticket-filter]").forEach((button) => button.addEventListener("click", () => {
  setTicketFilter(button.dataset.ticketFilter);
  renderTickets();
}));
document.querySelectorAll("[data-ticket-filter-shortcut]").forEach((button) => button.addEventListener("click", () => {
  setTicketFilter(button.dataset.ticketFilterShortcut);
  renderTickets();
}));
byId("tickets-search").addEventListener("input", (event) => {
  ticketQuery = event.target.value.slice(0, 160);
  byId("tickets-search-clear").hidden = ticketQuery.length === 0;
  renderTickets();
});
byId("tickets-search-clear").addEventListener("click", () => {
  ticketQuery = "";
  byId("tickets-search").value = "";
  byId("tickets-search-clear").hidden = true;
  byId("tickets-search").focus();
  renderTickets();
});
byId("tickets-sort").addEventListener("change", (event) => {
  ticketSort = event.target.value;
  renderTickets();
});

function label(value) {
  return String(value).replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

const configurationSectionMeta = Object.freeze({
  "Web boundary": { category: "security", description: "Authenticated network boundary and request limits." },
  Memory: { category: "ai", description: "Durable evidence, retention and retrieval behavior." },
  Providers: { category: "ai", description: "Contained model execution and provider readiness." },
  Connectors: { category: "integrations", description: "Channels and external service connections." },
  "Manage AI Operations": { category: "integrations ai", description: "Live tools, tickets and approval-aware control plane." },
  "Governance & safety": { category: "security", description: "Approval, audit, backup and observation controls." },
  "Extensions & automation": { category: "ai integrations", description: "MCP, knowledge, skills and automation surfaces." },
});

function configurePrompt(title) {
  return `Review the ${title} configuration. Explain its current effective state, identify anything missing, and stage any safe change for my explicit approval.`;
}

function renderConfigSection(title, values) {
  const metadata = configurationSectionMeta[title] || { category: "security", description: "Effective runtime configuration." };
  const card = document.createElement("article");
  card.className = "panel config-card";
  card.dataset.configCard = "";
  card.dataset.configCategory = metadata.category;
  const headingWrap = document.createElement("div");
  headingWrap.className = "config-card-heading";
  const headingText = document.createElement("div");
  const eyebrow = document.createElement("span");
  eyebrow.className = "config-eyebrow";
  eyebrow.textContent = metadata.category.includes("integrations") ? "INTEGRATION" : metadata.category === "ai" ? "INTELLIGENCE" : "SYSTEM";
  const heading = document.createElement("h2");
  heading.textContent = title;
  const description = document.createElement("p");
  description.textContent = metadata.description;
  headingText.append(eyebrow, heading, description);
  const configuredValues = Object.values(values || {}).filter((value) => typeof value === "boolean");
  const state = document.createElement("span");
  state.className = "config-scope";
  state.textContent = configuredValues.length === 0 || configuredValues.some(Boolean) ? "ACTIVE" : "OFF";
  headingWrap.append(headingText, state);
  const list = document.createElement("dl");
  list.className = "config-list";
  Object.entries(values || {}).forEach(([key, value]) => {
    const row = document.createElement("div");
    if (/(seconds|bytes|count|depth|limit)/.test(key)) row.dataset.configTechnical = "true";
    const term = document.createElement("dt");
    term.textContent = label(key);
    const detail = document.createElement("dd");
    detail.textContent = typeof value === "boolean" ? (value ? "CONFIGURED" : "OFF") : String(value ?? "—");
    if (typeof value === "boolean") detail.className = value ? "boolean-true" : "boolean-false";
    row.append(term, detail);
    list.append(row);
  });
  const footer = document.createElement("div");
  footer.className = "config-card-footer";
  const scope = document.createElement("small");
  scope.textContent = "Effective · secret-safe";
  const action = document.createElement("button");
  action.className = "config-inline-action";
  action.type = "button";
  action.textContent = "Configure with Monique →";
  action.dataset.chatPrompt = configurePrompt(title);
  footer.append(scope, action);
  card.append(headingWrap, list, footer);
  card.dataset.configSearch = `${title} ${metadata.description} ${Object.keys(values || {}).join(" ")}`.toLowerCase();
  return card;
}

function applyConfigurationFilter() {
  const cards = [...document.querySelectorAll("[data-config-card]")];
  let visible = 0;
  cards.forEach((card) => {
    const category = card.dataset.configCategory || "all";
    const categoryMatch = configurationFilter === "all" || category === "all" || category.split(" ").includes(configurationFilter);
    const haystack = `${card.dataset.configSearch || ""} ${card.textContent || ""}`.toLocaleLowerCase(localeTag());
    const queryMatch = !configurationQuery || haystack.includes(configurationQuery);
    card.hidden = !(categoryMatch && queryMatch);
    if (!card.hidden && card.closest(".config-primary") && !card.classList.contains("config-section-heading")) visible += 1;
  });
  byId("configuration-empty").hidden = visible > 0 || configurationQuery.length === 0;
}

function updateConfigurationSummary(config) {
  const connections = Object.values(config.connectors || {}).filter((value) => value === true).length;
  byId("configuration-connections-state").textContent = `${connections} connected`;
  byId("configuration-manage-state").textContent = config.manage?.configured ? "Connected" : "Not attached";
  byId("configuration-last-read").textContent = `Updated ${new Date().toLocaleTimeString(localeTag(), { hour: "2-digit", minute: "2-digit" })}`;
}

function syncManageIntegration(manage) {
  const configuredUrl = typeof manage?.console_url === "string" ? manage.console_url : null;
  let safeUrl = null;
  if (configuredUrl) {
    try {
      const parsed = new URL(configuredUrl);
      if (parsed.protocol === "https:") safeUrl = parsed.href;
    } catch (_error) {
      safeUrl = null;
    }
  }
  document.querySelectorAll("[data-manage-link]").forEach((link) => {
    if (safeUrl) {
      link.href = safeUrl;
      link.hidden = false;
    } else {
      link.removeAttribute("href");
      link.hidden = true;
    }
  });
  byId("chat-manage-state").hidden = manage?.dashboard_authority !== "discovered tools / explicit approval";
}

async function loadConfiguration(force = false) {
  const root = byId("configuration-grid");
  if (!force && root.dataset.loaded === "true") return;
  root.dataset.loaded = "false";
  try {
    const config = await api("/api/configuration");
    root.replaceChildren();
    const core = { ...config };
    delete core.schema;
    delete core.memory;
    delete core.providers;
    delete core.connectors;
    delete core.manage;
    delete core.governance;
    delete core.extensions;
    syncManageIntegration(config.manage);
    const manage = { ...config.manage };
    delete manage.console_url;
    manage.console = config.manage?.console_url ? "AVAILABLE" : "OFF";
    root.append(
      renderConfigSection("Web boundary", core),
      renderConfigSection("Memory", config.memory),
      renderConfigSection("Providers", config.providers),
      renderConfigSection("Connectors", config.connectors),
      renderConfigSection("Manage AI Operations", manage),
      renderConfigSection("Governance & safety", config.governance),
      renderConfigSection("Extensions & automation", config.extensions),
    );
    updateConfigurationSummary(config);
    applyConfigurationFilter();
    root.dataset.loaded = "true";
    if (force) toast("Runtime configuration refreshed.");
  } catch (error) {
    root.replaceChildren(renderConfigSection("Configuration unavailable", { category: error.message }));
    toast("Configuration projection is unavailable.", "error");
  }
}

byId("configuration-refresh").addEventListener("click", () => loadConfiguration(true));

const chatProfiles = ["conversation", "operational"];
const refreshRates = [5000, 10000, 30000, 60000];

function saveConfigurationPreference(message = true) {
  if (message) toast("Configuration preference saved.");
}

function applyDefaultProfile(profile, persist = true) {
  if (!chatProfiles.includes(profile)) profile = "conversation";
  byId("configuration-profile").value = profile;
  byId("chat-profile").value = profile;
  if (persist) savePreference("monique-chat-profile", profile);
}

function applyRefreshRate(value, persist = true) {
  const rate = refreshRates.includes(Number(value)) ? Number(value) : 10000;
  byId("configuration-refresh-rate").value = String(rate);
  if (persist) savePreference("monique-refresh-rate", String(rate));
  scheduleStatusRefresh(rate);
}

function applyTechnicalValues(enabled, persist = true) {
  document.documentElement.dataset.configDetails = enabled ? "detailed" : "concise";
  byId("configuration-technical-values").checked = enabled;
  if (persist) savePreference("monique-technical-values", enabled ? "on" : "off");
}

async function applyNotifications(enabled, persist = true) {
  if (!("Notification" in window)) {
    byId("configuration-notifications").checked = false;
    toast("Notifications are not available in this browser.", "error");
    return;
  }
  if (enabled && Notification.permission !== "granted") {
    const permission = await Notification.requestPermission();
    if (permission !== "granted") {
      byId("configuration-notifications").checked = false;
      if (persist) savePreference("monique-notifications", "off");
      toast("Notification permission was not granted.", "error");
      return;
    }
  }
  byId("configuration-notifications").checked = enabled;
  if (persist) savePreference("monique-notifications", enabled ? "on" : "off");
}

applyDefaultProfile(storedPreference("monique-chat-profile", chatProfiles, "conversation"), false);
applyRefreshRate(Number(storedPreference("monique-refresh-rate", refreshRates.map(String), "10000")), false);
applyTechnicalValues(storedPreference("monique-technical-values", ["on", "off"], "on") === "on", false);
byId("configuration-notifications").checked = storedPreference("monique-notifications", ["on", "off"], "off") === "on" && "Notification" in window && Notification.permission === "granted";

byId("configuration-theme").addEventListener("change", (event) => { applyTheme(event.target.value); saveConfigurationPreference(); });
byId("configuration-language").addEventListener("change", (event) => { applyLanguage(event.target.value); saveConfigurationPreference(); });
byId("configuration-text-scale").addEventListener("change", (event) => { applyTextScale(event.target.value); saveConfigurationPreference(); });
byId("configuration-density").addEventListener("change", (event) => { applyDensity(event.target.value); saveConfigurationPreference(); });
byId("configuration-startup").addEventListener("change", (event) => { applyStartupView(event.target.value); saveConfigurationPreference(); });
byId("configuration-motion").addEventListener("change", (event) => { applyMotion(event.target.checked ? "reduce" : "full"); saveConfigurationPreference(); });
byId("configuration-profile").addEventListener("change", (event) => { applyDefaultProfile(event.target.value); saveConfigurationPreference(); });
byId("configuration-refresh-rate").addEventListener("change", (event) => { applyRefreshRate(event.target.value); saveConfigurationPreference(); });
byId("configuration-technical-values").addEventListener("change", (event) => { applyTechnicalValues(event.target.checked); saveConfigurationPreference(); });
byId("configuration-notifications").addEventListener("change", (event) => applyNotifications(event.target.checked));
byId("configuration-search").addEventListener("input", (event) => {
  configurationQuery = event.target.value.trim().toLocaleLowerCase(localeTag());
  applyConfigurationFilter();
});
document.querySelectorAll("[data-config-filter]").forEach((button) => button.addEventListener("click", () => {
  configurationFilter = button.dataset.configFilter;
  document.querySelectorAll("[data-config-filter]").forEach((item) => item.classList.toggle("is-active", item === button));
  applyConfigurationFilter();
}));

function renderMessageMeta(meta) {
  const createdAt = Number(meta.dataset.createdAt);
  const durationMs = Number(meta.dataset.durationMs);
  const role = meta.dataset.role === "user" ? "user" : "assistant";
  const duration = Number.isSafeInteger(durationMs) && durationMs >= 0 ? ` · ${durationMs.toLocaleString(localeTag())}ms` : "";
  const time = new Date(createdAt).toLocaleTimeString(localeTag(), { hour: "2-digit", minute: "2-digit" });
  meta.textContent = `${role === "user" ? "OPERATOR" : "MONIQUE"} · ${time}${duration}`;
}

function safeMarkdownUrl(value) {
  const raw = String(value).trim();
  if (!raw || /[\u0000-\u001f\u007f]/.test(raw)) return null;
  try {
    const url = new URL(raw, window.location.origin);
    if (!["http:", "https:", "mailto:"].includes(url.protocol)) return null;
    return url.href;
  } catch (_error) {
    return null;
  }
}

function appendInlineMarkdown(parent, source, depth = 0) {
  const text = String(source);
  if (depth > 5) {
    parent.append(document.createTextNode(text));
    return;
  }
  let plain = "";
  const flush = () => {
    if (plain) parent.append(document.createTextNode(plain));
    plain = "";
  };
  const paired = (index, marker, tag) => {
    if (!text.startsWith(marker, index)) return null;
    const openingNext = text[index + marker.length];
    if (!openingNext || /\s/.test(openingNext)) return null;
    if (marker.startsWith("_") && /[A-Za-z0-9]/.test(text[index - 1] || "") && /[A-Za-z0-9]/.test(openingNext)) return null;
    const end = text.indexOf(marker, index + marker.length);
    if (end <= index + marker.length || /\s/.test(text[end - 1])) return null;
    flush();
    const node = document.createElement(tag);
    appendInlineMarkdown(node, text.slice(index + marker.length, end), depth + 1);
    parent.append(node);
    return end + marker.length;
  };
  for (let index = 0; index < text.length;) {
    if (text[index] === "\\" && index + 1 < text.length && /[\\`*_[\]~]/.test(text[index + 1])) {
      plain += text[index + 1];
      index += 2;
      continue;
    }
    if (text[index] === "`") {
      const marker = text.slice(index).match(/^`+/)?.[0] || "`";
      const end = text.indexOf(marker, index + marker.length);
      if (end > index + marker.length) {
        flush();
        const code = document.createElement("code");
        code.textContent = text.slice(index + marker.length, end).replace(/^ | $/g, "");
        parent.append(code);
        index = end + marker.length;
        continue;
      }
    }
    if (text[index] === "[") {
      const labelEnd = text.indexOf("](", index + 1);
      const targetEnd = labelEnd < 0 ? -1 : text.indexOf(")", labelEnd + 2);
      if (labelEnd > index + 1 && targetEnd > labelEnd + 2) {
        const href = safeMarkdownUrl(text.slice(labelEnd + 2, targetEnd));
        if (href) {
          flush();
          const link = document.createElement("a");
          link.href = href;
          link.rel = "noopener noreferrer";
          if (href.startsWith("http:") || href.startsWith("https:")) link.target = "_blank";
          appendInlineMarkdown(link, text.slice(index + 1, labelEnd), depth + 1);
          parent.append(link);
          index = targetEnd + 1;
          continue;
        }
      }
    }
    const strong = paired(index, "**", "strong") || paired(index, "__", "strong");
    if (strong) {
      index = strong;
      continue;
    }
    const strike = paired(index, "~~", "del");
    if (strike) {
      index = strike;
      continue;
    }
    const emphasis = paired(index, "*", "em") || paired(index, "_", "em");
    if (emphasis) {
      index = emphasis;
      continue;
    }
    plain += text[index];
    index += 1;
  }
  flush();
}

function appendMarkdownLines(parent, lines) {
  lines.forEach((line, index) => {
    if (index > 0) parent.append(document.createElement("br"));
    appendInlineMarkdown(parent, line);
  });
}

function markdownTableCells(line) {
  const cells = [];
  let cell = "";
  let codeFence = 0;
  let escaped = false;
  const value = String(line).trim().replace(/^\|/, "").replace(/\|$/, "");
  for (let index = 0; index < value.length; index += 1) {
    const character = value[index];
    if (escaped) {
      cell += character;
      escaped = false;
    } else if (character === "\\" && value[index + 1] === "|") {
      escaped = true;
    } else if (character === "`") {
      codeFence = codeFence === 0 ? 1 : 0;
      cell += character;
    } else if (character === "|" && codeFence === 0) {
      cells.push(cell.trim());
      cell = "";
    } else {
      cell += character;
    }
  }
  if (escaped) cell += "\\";
  cells.push(cell.trim());
  return cells;
}

function markdownTableAlignment(delimiter) {
  const value = delimiter.trim();
  if (!/^:?-{3,}:?$/.test(value)) return null;
  if (value.startsWith(":") && value.endsWith(":")) return "center";
  if (value.endsWith(":")) return "right";
  return "left";
}

function markdownBlockStart(line) {
  return /^\s*(```|~~~)/.test(line)
    || /^\s{0,3}#{1,6}\s+/.test(line)
    || /^\s{0,3}>\s?/.test(line)
    || /^\s{0,3}([-+*])\s+/.test(line)
    || /^\s{0,3}\d+[.)]\s+/.test(line)
    || /^\s{0,3}((\*\s*){3,}|(-\s*){3,}|(_\s*){3,})$/.test(line);
}

function renderMarkdown(content) {
  const fragment = document.createDocumentFragment();
  const lines = String(content).replace(/\r\n?/g, "\n").split("\n");
  let index = 0;
  while (index < lines.length) {
    const line = lines[index];
    if (!line.trim()) {
      index += 1;
      continue;
    }
    const fence = line.match(/^\s*(```|~~~)\s*([A-Za-z0-9_+-]*)\s*$/);
    if (fence) {
      const codeLines = [];
      index += 1;
      while (index < lines.length && !new RegExp(`^\\s*${fence[1]}\\s*$`).test(lines[index])) {
        codeLines.push(lines[index]);
        index += 1;
      }
      if (index < lines.length) index += 1;
      const pre = document.createElement("pre");
      const code = document.createElement("code");
      if (fence[2]) code.dataset.language = fence[2].toLowerCase();
      code.textContent = codeLines.join("\n");
      pre.append(code);
      fragment.append(pre);
      continue;
    }
    if (index + 1 < lines.length && line.includes("|")) {
      const headings = markdownTableCells(line);
      const delimiters = markdownTableCells(lines[index + 1]);
      const alignments = delimiters.map(markdownTableAlignment);
      if (headings.length > 1 && headings.length === delimiters.length && alignments.every(Boolean)) {
        const wrapper = document.createElement("div");
        wrapper.className = "markdown-table-wrap";
        const table = document.createElement("table");
        const head = document.createElement("thead");
        const headingRow = document.createElement("tr");
        headings.forEach((value, column) => {
          const cell = document.createElement("th");
          cell.className = `align-${alignments[column]}`;
          appendInlineMarkdown(cell, value);
          headingRow.append(cell);
        });
        head.append(headingRow);
        table.append(head);
        const body = document.createElement("tbody");
        index += 2;
        while (index < lines.length && lines[index].trim() && lines[index].includes("|")) {
          const values = markdownTableCells(lines[index]);
          if (values.length !== headings.length) break;
          const row = document.createElement("tr");
          values.forEach((value, column) => {
            const cell = document.createElement("td");
            cell.className = `align-${alignments[column]}`;
            appendInlineMarkdown(cell, value);
            row.append(cell);
          });
          body.append(row);
          index += 1;
        }
        table.append(body);
        wrapper.append(table);
        fragment.append(wrapper);
        continue;
      }
    }
    const heading = line.match(/^\s{0,3}(#{1,6})\s+(.+?)\s*#*$/);
    if (heading) {
      const node = document.createElement(`h${heading[1].length}`);
      appendInlineMarkdown(node, heading[2]);
      fragment.append(node);
      index += 1;
      continue;
    }
    if (/^\s{0,3}((\*\s*){3,}|(-\s*){3,}|(_\s*){3,})$/.test(line)) {
      fragment.append(document.createElement("hr"));
      index += 1;
      continue;
    }
    if (/^\s{0,3}>\s?/.test(line)) {
      const quoted = [];
      while (index < lines.length && /^\s{0,3}>\s?/.test(lines[index])) {
        quoted.push(lines[index].replace(/^\s{0,3}>\s?/, ""));
        index += 1;
      }
      const quote = document.createElement("blockquote");
      quote.append(renderMarkdown(quoted.join("\n")));
      fragment.append(quote);
      continue;
    }
    const listMatch = line.match(/^\s{0,3}([-+*]|\d+[.)])\s+(.+)$/);
    if (listMatch) {
      const ordered = /^\d/.test(listMatch[1]);
      const list = document.createElement(ordered ? "ol" : "ul");
      while (index < lines.length) {
        const item = lines[index].match(/^\s{0,3}([-+*]|\d+[.)])\s+(.+)$/);
        if (!item || /^\d/.test(item[1]) !== ordered) break;
        const child = document.createElement("li");
        const task = !ordered ? item[2].match(/^\[([ xX])\]\s+(.+)$/) : null;
        if (task) {
          child.className = "task-item";
          const check = document.createElement("span");
          check.className = "task-check";
          check.setAttribute("aria-hidden", "true");
          check.textContent = task[1].toLowerCase() === "x" ? "✓" : "";
          child.append(check);
          appendInlineMarkdown(child, task[2]);
        } else {
          appendInlineMarkdown(child, item[2]);
        }
        list.append(child);
        index += 1;
      }
      fragment.append(list);
      continue;
    }
    const paragraph = [line];
    index += 1;
    while (index < lines.length && lines[index].trim() && !markdownBlockStart(lines[index])) {
      paragraph.push(lines[index]);
      index += 1;
    }
    const node = document.createElement("p");
    appendMarkdownLines(node, paragraph);
    fragment.append(node);
  }
  return fragment;
}

function appendMessage(role, content, createdAt = Date.now(), details = {}) {
  byId("chat-empty")?.remove();
  const item = document.createElement("article");
  item.className = `message ${role === "user" ? "user" : "assistant"}${details.error ? " error" : ""}`;
  const avatar = document.createElement("span");
  avatar.className = "message-avatar";
  avatar.textContent = role === "user" ? "YOU" : "M";
  const body = document.createElement("div");
  body.className = "message-content";
  const markdown = document.createElement("div");
  markdown.className = "message-markdown";
  if (!details.error && !details.localized) markdown.setAttribute("data-i18n-skip", "");
  markdown.append(renderMarkdown(content));
  body.append(markdown);
  if (role !== "user" && details.action) body.append(createActionCard(details.action));
  const meta = document.createElement("div");
  meta.className = "message-meta";
  meta.dataset.createdAt = String(createdAt);
  meta.dataset.role = role === "user" ? "user" : "assistant";
  if (Number.isSafeInteger(details.durationMs)) meta.dataset.durationMs = String(details.durationMs);
  renderMessageMeta(meta);
  body.append(meta);
  if (role !== "user") {
    const tools = document.createElement("div");
    tools.className = "message-tools";
    (details.sources || []).forEach((source) => {
      const chip = document.createElement("span");
      chip.className = "source-chip";
      chip.textContent = `LIVE · ${words(source)}`;
      tools.append(chip);
    });
    const copy = document.createElement("button");
    copy.type = "button";
    copy.className = "copy-message";
    copy.textContent = "COPY";
    copy.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(String(content));
        copy.textContent = "COPIED";
        window.setTimeout(() => { copy.textContent = "COPY"; }, 1800);
      } catch (_error) {
        toast("Copy is unavailable in this browser.", "error");
      }
    });
    tools.append(copy);
    body.append(tools);
  }
  if (role === "user") item.append(body, avatar); else item.append(avatar, body);
  byId("chat-thread").append(item);
  item.scrollIntoView({ block: "end" });
  return item;
}

function createActionCard(action) {
  const card = document.createElement("section");
  card.className = "action-card";
  card.dataset.actionId = String(action.id || "");
  const eyebrow = document.createElement("span");
  eyebrow.textContent = "APPROVAL REQUIRED";
  const title = document.createElement("strong");
  if (action.title) title.setAttribute("data-i18n-skip", "");
  title.textContent = action.title ? String(action.title) : "Review Manage action";
  const detail = document.createElement("p");
  if (action.detail) detail.setAttribute("data-i18n-skip", "");
  detail.textContent = action.detail ? String(action.detail) : "Review this action before it runs.";
  const impact = document.createElement("small");
  if (action.impact) impact.setAttribute("data-i18n-skip", "");
  impact.textContent = action.impact ? String(action.impact) : "This action can change external state.";
  const controls = document.createElement("div");
  controls.className = "action-controls";
  const deny = document.createElement("button");
  deny.type = "button";
  deny.className = "action-deny";
  deny.textContent = "Deny";
  const approve = document.createElement("button");
  approve.type = "button";
  approve.className = "action-approve";
  approve.textContent = "Approve and run";
  [deny, approve].forEach((button) => button.addEventListener("click", () => {
    resolveChatAction(card, button === approve ? "approve" : "deny");
  }));
  controls.append(deny, approve);
  card.append(eyebrow, title, detail, impact, controls);
  return card;
}

async function resolveChatAction(card, decision) {
  if (chatBusy || card.dataset.state) return;
  chatBusy = true;
  card.dataset.state = "working";
  card.querySelectorAll("button").forEach((button) => { button.disabled = true; });
  const pending = appendPendingMessage();
  byId("chat-state").textContent = decision === "approve" ? "Running approved action…" : "Recording denial…";
  try {
    const answer = await api("/api/chat/action", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action_id: card.dataset.actionId, decision }),
    });
    pending.remove();
    card.dataset.state = decision === "approve" ? "approved" : "denied";
    const sources = Array.isArray(answer.live_sources) ? answer.live_sources : [];
    appendMessage("assistant", answer.answer, Date.now(), { sources, durationMs: answer.duration_ms, action: answer.action });
    byId("chat-source-count").textContent = count(sources.length);
    byId("chat-latency").textContent = Number.isSafeInteger(answer.duration_ms) ? `${answer.duration_ms.toLocaleString(localeTag())} ms` : "—";
    byId("chat-state").textContent = decision === "approve" ? "Action completed" : "Action denied";
    toast(decision === "approve" ? "The approved action returned a result." : "The action was denied.");
  } catch (error) {
    pending.remove();
    card.removeAttribute("data-state");
    card.querySelectorAll("button").forEach((button) => { button.disabled = false; });
    appendMessage("assistant", humanChatError(error.message), Date.now(), { error: true });
    byId("chat-state").textContent = "Action refused";
    toast("The action was not completed.", "error");
  } finally {
    chatBusy = false;
  }
}

function appendPendingMessage() {
  byId("chat-empty")?.remove();
  const item = document.createElement("article");
  item.className = "message assistant pending";
  const avatar = document.createElement("span");
  avatar.className = "message-avatar";
  avatar.textContent = "M";
  const body = document.createElement("div");
  body.className = "message-content";
  const dots = document.createElement("span");
  dots.className = "thinking-dots";
  dots.setAttribute("aria-label", "Monique is working");
  dots.append(document.createElement("i"), document.createElement("i"), document.createElement("i"));
  body.append(dots);
  item.append(avatar, body);
  byId("chat-thread").append(item);
  item.scrollIntoView({ block: "end" });
  return item;
}

function createWelcome(title = "How can I help?", text = "Ask naturally. I can use reviewed memory, live sources, and prepare actions for your approval.") {
  const empty = document.createElement("div");
  empty.className = "empty-state";
  empty.id = "chat-empty";
  const mark = document.createElement("span");
  mark.textContent = "M";
  const heading = document.createElement("h2");
  heading.textContent = title;
  const copy = document.createElement("p");
  copy.textContent = text;
  const starters = document.createElement("div");
  starters.className = "starter-grid";
  [
    ["Explain system health", "Review live status and surface risks", "Explain the current operational health and any risks."],
    ["Catch me up", "Read recent configured Slack context", "Summarize the latest relevant Slack messages."],
    ["Explore memory", "Use reviewed durable evidence", "What do you remember that is most relevant right now? Cite memory references."],
    ["Work in Manage", "Prepare a reviewable AI Operations action", "Show me the useful actions available in Manage AI Operations and help me choose the right one."],
  ].forEach(([caption, description, prompt]) => {
    const button = document.createElement("button");
    button.type = "button";
    button.dataset.chatPrompt = prompt;
    const label = document.createElement("strong");
    label.textContent = caption;
    const detail = document.createElement("small");
    detail.textContent = description;
    button.append(label, detail);
    starters.append(button);
  });
  empty.append(mark, heading, copy, starters);
  return empty;
}

async function loadChatHistory() {
  const thread = byId("chat-thread");
  if (thread.dataset.loaded === "true") return;
  try {
    const history = await api("/api/chat/history");
    if ((history.messages || []).length > 0) {
      thread.replaceChildren();
      history.messages.forEach((message) => appendMessage(message.role, message.content, message.created_at_ms));
    }
    (history.pending_actions || []).forEach((action) => {
      appendMessage("assistant", "This Manage action is still awaiting your decision.", Date.now(), { action, localized: true });
    });
    thread.dataset.loaded = "true";
  } catch (_error) {
    byId("chat-state").textContent = "History unavailable";
    toast("Durable chat history is unavailable.", "error");
  }
}

function humanChatError(category) {
  const messages = {
    chat_lane_busy: "Monique is finishing another contained turn. Try again in a moment.",
    slack_read_unavailable: "The configured Slack read is temporarily unavailable.",
    slack_tool_unavailable: "The Slack read surface is temporarily busy.",
    memory_unavailable: "Durable memory is temporarily unavailable.",
    memory_write_refused: "This turn could not be retained safely, so it was not run.",
    manage_tool_unavailable: "Manage AI Operations is temporarily unavailable. No action was run.",
    manage_action_not_pending: "That Manage action is no longer pending. Nothing was run.",
    manage_action_expired: "That Manage action expired. Ask Monique to prepare it again.",
    manage_action_additional_approval_refused: "Manage requested another approval step, so execution stopped.",
  };
  return messages[category] || `The contained conversation lane refused this turn (${category}).`;
}

byId("chat-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (chatBusy) return;
  const input = byId("chat-input");
  const message = input.value.trim();
  if (!message) return;
  chatBusy = true;
  appendMessage("user", message);
  input.value = "";
  byId("chat-count").textContent = "0";
  byId("chat-send").disabled = true;
  const pending = appendPendingMessage();
  const started = performance.now();
  const timer = window.setInterval(() => {
    byId("chat-state").textContent = `Monique is working · ${Math.max(1, Math.round((performance.now() - started) / 1000))}s`;
  }, 1000);
  byId("chat-state").textContent = "Monique is working…";
  try {
    const answer = await api("/api/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message, profile: byId("chat-profile").value }),
    });
    pending.remove();
    const sources = Array.isArray(answer.live_sources) ? answer.live_sources : [];
    appendMessage("assistant", answer.answer, Date.now(), { sources, durationMs: answer.duration_ms, action: answer.action });
    byId("chat-memory-count").textContent = count(answer.memory_evidence);
    byId("chat-source-count").textContent = count(sources.length);
    byId("chat-latency").textContent = Number.isSafeInteger(answer.duration_ms) ? `${answer.duration_ms.toLocaleString(localeTag())} ms` : `${Math.round(performance.now() - started).toLocaleString(localeTag())} ms`;
    byId("chat-state").textContent = `${words(answer.profile)} · retained`;
  } catch (error) {
    pending.remove();
    appendMessage("assistant", humanChatError(error.message), Date.now(), { error: true });
    byId("chat-state").textContent = "Turn refused";
    toast("Monique could not complete that turn.", "error");
  } finally {
    window.clearInterval(timer);
    chatBusy = false;
    byId("chat-send").disabled = false;
    input.focus();
  }
});

byId("chat-input").addEventListener("keydown", (event) => {
  if (event.key === "Enter" && !event.shiftKey) {
    event.preventDefault();
    byId("chat-form").requestSubmit();
  }
});
byId("chat-input").addEventListener("input", (event) => {
  byId("chat-count").textContent = event.target.value.length.toLocaleString(localeTag());
});

function resetNewChatButton() {
  window.clearTimeout(newChatTimer);
  newChatArmed = false;
  byId("new-chat").textContent = "New conversation";
  byId("new-chat").removeAttribute("data-armed");
  byId("sidebar-new-chat-label").textContent = "New conversation";
  byId("sidebar-new-chat").removeAttribute("data-armed");
}

byId("new-chat").addEventListener("click", async () => {
  if (chatBusy) {
    toast("Wait for the current turn to finish before starting a new conversation.");
    return;
  }
  if (!newChatArmed) {
    newChatArmed = true;
    byId("new-chat").textContent = "Confirm new conversation";
    byId("new-chat").dataset.armed = "true";
    byId("sidebar-new-chat-label").textContent = "Confirm new conversation";
    byId("sidebar-new-chat").dataset.armed = "true";
    newChatTimer = window.setTimeout(resetNewChatButton, 5000);
    return;
  }
  byId("new-chat").disabled = true;
  try {
    await api("/api/chat/new", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
    byId("chat-thread").replaceChildren(createWelcome("New conversation", "The previous durable conversation was archived. Long-term memory remains available."));
    byId("chat-state").textContent = "New durable session";
    byId("chat-memory-count").textContent = "—";
    byId("chat-source-count").textContent = "0";
    byId("chat-latency").textContent = "—";
    toast("A new durable conversation is ready.");
  } catch (error) {
    byId("chat-state").textContent = `New chat refused · ${error.message}`;
    toast("The current conversation was not changed.", "error");
  } finally {
    byId("new-chat").disabled = false;
    resetNewChatButton();
  }
});

byId("sidebar-new-chat").addEventListener("click", () => {
  showView("chat");
  byId("new-chat").click();
});

function seedChatPrompt(prompt) {
  showView("chat");
  const input = byId("chat-input");
  input.value = prompt;
  byId("chat-count").textContent = prompt.length.toLocaleString(localeTag());
  input.focus();
}

document.addEventListener("click", (event) => {
  const prompt = event.target.closest("[data-chat-prompt]")?.dataset.chatPrompt;
  if (prompt) seedChatPrompt(prompt);
  const overviewPrompt = event.target.closest("[data-open-chat]")?.dataset.openChat;
  if (overviewPrompt) seedChatPrompt(overviewPrompt);
});

document.addEventListener("keydown", (event) => {
  const editing = event.target.matches("input, textarea, select, [contenteditable='true']");
  if (!editing && event.key === "/") {
    event.preventDefault();
    showView("chat");
    byId("chat-input").focus();
  } else if (!editing && event.key.toLowerCase() === "r") {
    event.preventDefault();
    refreshStatus({ announce: true });
  } else if (!editing && event.key.toLowerCase() === "n") {
    event.preventDefault();
    showView("chat");
    byId("new-chat").click();
  } else if (event.key === "Escape" && newChatArmed) {
    resetNewChatButton();
  } else if (event.key === "Escape" && !byId("appearance-panel").hidden) {
    appearanceOpen(false);
    byId("theme-cycle").focus();
  } else if (event.key === "Escape" && document.documentElement.dataset.mobileSidebar === "open") {
    mobileSidebarOpen(false);
    byId("sidebar-toggle").focus();
  }
});

refreshStatus();
loadConfiguration();
showView(window.location.hash.slice(1) || storedPreference("monique-start-view", startupViews, "chat"));
function scheduleStatusRefresh(delay = 10000) {
  if (statusRefreshTimer !== null) window.clearTimeout(statusRefreshTimer);
  statusRefreshTimer = window.setTimeout(async () => {
    if (!document.hidden) await refreshStatus();
    scheduleStatusRefresh(Number(byId("configuration-refresh-rate").value));
  }, delay);
}
scheduleStatusRefresh(Number(byId("configuration-refresh-rate").value));
window.setInterval(updateObservedAge, 1_000);
window.setInterval(renderPulse, 1_000);
document.addEventListener("visibilitychange", () => { if (!document.hidden) refreshStatus(); });

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
let memoryStatus = "all";
let memorySensitivity = "all";
let memorySort = "updated_desc";
let memoryMode = storedPreference("monique-memory-view", ["graph", "list", "timeline"], "graph");
let selectedMemoryReference = null;
let memoryQuery = null;
let operationsSnapshot = null;
let processesSnapshot = null;
let platformSnapshot = null;
let cockpitSnapshot = null;
let platformSelectedSession = null;
let platformHistoryCursor = null;
let platformMutation = null;
let platformBusy = false;
let platformExactRevision = null;
let cockpitState = globalThis.AutomoniquePlatformCockpit.initialState(
  globalThis.AutomoniquePlatformCockpit.parseDeepLink(window.location.hash),
);
let cockpitPresentation = null;
let cockpitTaskWorkspaceId = null;
const cockpitControlStorageKey = "automonique-cockpit-control-v1";
let cockpitControlHandle = (() => {
  try {
    return globalThis.AutomoniquePlatformCockpit.parseControlHandle(localStorage.getItem(cockpitControlStorageKey));
  } catch (_error) {
    return null;
  }
})();
let cockpitControlBusy = false;
let processFilter = "all";
const expandedProcesses = new Set();
let ticketFilter = "all";
let ticketSurface = "all";
let ticketQuery = "";
let ticketSort = "updated_desc";
let lastObservedMs = null;
let lastStatusKey = null;
let lastPulseChangeAt = null;
let chatBusy = false;
const BrowserSpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
const voiceInputSupported = typeof BrowserSpeechRecognition === "function";
const voiceOutputSupported = "speechSynthesis" in window && typeof window.SpeechSynthesisUtterance === "function";
let voiceRecognition = null;
let voiceListening = false;
let voiceShouldListen = false;
let voiceDraft = "";
let voiceTranscript = "";
let voiceRepliesEnabled = storedPreference("monique-voice-replies", ["on", "off"], "off") === "on";
let activeSpeechButton = null;
let activeSpeechUtterance = null;
let activeSpeechStatus = null;
let newChatArmed = false;
let newChatTimer = null;
let lastStatusSnapshot = null;
let configurationFilter = "all";
let configurationQuery = "";
let agentAccountsPollTimer = null;
let statusRefreshTimer = null;
let lastNotifiedAttentionKey = null;
const frenchUi = Object.freeze({
  "Skip to workspace": "Aller à l’espace de travail",
  "Primary navigation": "Navigation principale",
  "Open retained sessions": "Ouvrir les sessions conservées",
  "Collapse sidebar": "Réduire la barre latérale",
  "Expand sidebar": "Déployer la barre latérale",
  "Toggle sidebar": "Afficher ou masquer la barre latérale",
  "Close navigation": "Fermer la navigation",
  "New conversation": "Nouvelle conversation",
  "Confirm new conversation": "Confirmer la nouvelle conversation",
  "Retained sessions": "Sessions conservées",
  "RETAINED SESSIONS": "SESSIONS CONSERVÉES",
  "Recovery": "Récupération",
  "Recovery tools": "Outils de récupération",
  "Generic chat": "Discussion générique",
  "Generic recovery chat": "Discussion générique de récupération",
  "GENERIC RECOVERY CHAT": "DISCUSSION GÉNÉRIQUE DE RÉCUPÉRATION",
  "RECOVERY": "RÉCUPÉRATION",
  "Workspace": "Espace de travail",
  "Operations sections": "Sections opérationnelles",
  "Overview": "Vue d’ensemble",
  "OVERVIEW": "VUE D’ENSEMBLE",
  "Chat": "Discussion",
  "CHAT": "DISCUSSION",
  "Tickets": "Tickets",
  "TICKETS": "TICKETS",
  "Work queues": "Files de travail",
  "WORK QUEUES": "FILES DE TRAVAIL",
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
  "Generic recovery assistant": "Assistante générique de récupération",
  "SECONDARY / RECOVERY": "SECONDAIRE / RÉCUPÉRATION",
  "This assistant is not attached to an authority-qualified Platform session. Use it when retained session recovery is unavailable, then return to the retained cockpit for ongoing work.": "Cette assistante n’est pas rattachée à une session Platform qualifiée par une autorité. Utilisez-la lorsque la récupération d’une session conservée est indisponible, puis revenez au cockpit conservé pour poursuivre le travail.",
  "Return to retained sessions": "Revenir aux sessions conservées",
  "RECOVERY ASSISTANT": "ASSISTANTE DE RÉCUPÉRATION",
  "Use recovery assistant": "Utiliser l’assistante de récupération",
  "Generic help · no session context →": "Aide générique · sans contexte de session →",
  "GENERIC RECOVERY ASSISTANT": "ASSISTANTE GÉNÉRIQUE DE RÉCUPÉRATION",
  "Configuration recovery": "Récupération de configuration",
  "Credentials remain outside this browser. This generic assistant is not attached to a retained session; any mutation still requires explicit approval.": "Les identifiants restent hors de ce navigateur. Cette assistante générique n’est pas rattachée à une session conservée ; toute modification exige toujours une approbation explicite.",
  "AUTOMONIQUE.PLATFORM / AUTHORITY-QUALIFIED": "AUTOMONIQUE.PLATFORM / AUTORITÉ QUALIFIÉE",
  "PRIMARY CONVERSATION SURFACE": "SURFACE DE CONVERSATION PRINCIPALE",
  "Continue work in its durable Platform session, with exact authority, revision, approval, and receipt context preserved across every follow-up.": "Poursuivez le travail dans sa session Platform durable, en préservant le contexte exact d’autorité, de révision, d’approbation et de reçu à chaque suivi.",
  "Conversation context": "Contexte de conversation",
  "memory": "mémoire",
  "live": "temps réel",
  "last turn": "dernier échange",
  "Live sources": "Sources en temps réel",
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
  "Turn on spoken replies": "Activer les réponses vocales",
  "Turn off spoken replies": "Désactiver les réponses vocales",
  "Voice replies are on": "Les réponses vocales sont activées",
  "Voice replies are off": "Les réponses vocales sont désactivées",
  "Voice replies are unavailable in this browser": "Les réponses vocales ne sont pas disponibles dans ce navigateur",
  "Start voice input": "Démarrer la saisie vocale",
  "Stop voice input": "Arrêter la saisie vocale",
  "Voice input is unavailable in this browser": "La saisie vocale n’est pas disponible dans ce navigateur",
  "Voice input needs microphone permission.": "La saisie vocale nécessite l’autorisation d’utiliser le microphone.",
  "No microphone was found.": "Aucun microphone n’a été détecté.",
  "I did not hear anything. Try again.": "Je n’ai rien entendu. Réessayez.",
  "Voice recognition is temporarily unavailable.": "La reconnaissance vocale est temporairement indisponible.",
  "Listening… tap MIC to stop": "Écoute… appuyez sur MIC pour arrêter",
  "Voice input ready": "Saisie vocale prête",
  "Speaking…": "Lecture vocale…",
  "Read reply aloud": "Lire la réponse à voix haute",
  "Stop reading reply": "Arrêter la lecture de la réponse",
  "VOICE OFF": "VOIX OFF",
  "VOICE ON": "VOIX ON",
  "VOICE N/A": "VOIX N/D",
  "LISTEN": "ÉCOUTER",
  "STOP": "ARRÊTER",
  "Monique can make mistakes. Durable memory and live sources are labeled when they support an answer.": "Monique peut se tromper. La mémoire durable et les sources en temps réel sont signalées lorsqu’elles étayent une réponse.",
  "Monique can make mistakes. Durable memory and live sources are labeled when they support an answer. Voice uses your browser’s speech service and starts only when you use a voice control.": "Monique peut se tromper. La mémoire durable et les sources en temps réel sont signalées lorsqu’elles étayent une réponse. La voix utilise le service vocal de votre navigateur et ne démarre que lorsque vous utilisez une commande vocale.",
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
  "DELETED": "SUPPRIMÉS",
  "REVIEW DUE": "À RÉEXAMINER",
  "MESSAGES": "MESSAGES",
  "Canonical memory counts": "Compteurs de mémoire canonique",
  "Memory view": "Vue de la mémoire",
  "Evidence graph": "Graphe des éléments",
  "Records": "Enregistrements",
  "Timeline": "Chronologie",
  "Kind": "Type",
  "All evidence": "Tous les éléments",
  "All statuses": "Tous les états",
  "Sensitivity": "Sensibilité",
  "All levels": "Tous les niveaux",
  "Sort": "Tri",
  "Highest confidence": "Confiance la plus élevée",
  "Review date": "Date de réexamen",
  "Reference": "Référence",
  "Reset filters": "Réinitialiser les filtres",
  "Select evidence": "Sélectionnez un élément",
  "Choose a graph node, record, or timeline event to inspect its provenance and review state.": "Choisissez un nœud, un enregistrement ou un événement pour examiner sa provenance et son état de révision.",
  "Evidence details": "Détails de l’élément",
  "Confidence": "Confiance",
  "Visibility": "Visibilité",
  "Provenance": "Provenance",
  "Revision": "Révision",
  "Updated": "Mis à jour",
  "Next review": "Prochain réexamen",
  "No review scheduled": "Aucun réexamen planifié",
  "Review due": "Réexamen requis",
  "Copy content": "Copier le contenu",
  "Ask Monique": "Demander à Monique",
  "Memory content copied.": "Contenu de la mémoire copié.",
  "Clipboard access is unavailable.": "L’accès au presse-papiers est indisponible.",
  "active": "actif",
  "candidate": "proposition",
  "superseded": "remplacé",
  "deleted": "supprimé",
  "personal": "personnel",
  "private": "privé",
  "user profile": "profil utilisateur",
  "No memory evidence matches this view.": "Aucun élément de mémoire ne correspond à cette vue.",
  "No evidence nodes to display.": "Aucun nœud à afficher.",
  "No timeline events to display.": "Aucun événement à afficher dans la chronologie.",
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
  "Agent authentication": "Authentification des agents",
  "Execution access without credential exposure": "Accès d’exécution sans exposition des identifiants",
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
  "Verified execution access for connected agent surfaces.": "Accès d’exécution vérifié pour les surfaces d’agent connectées.",
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
  "See every active and recent agent process, inspect its live output, and open the exact run in Manage. Every mutation remains staged for explicit approval.": "Consultez chaque processus d’agent actif ou récent, inspectez sa sortie en direct et ouvrez l’exécution exacte dans Manage. Chaque modification reste soumise à une approbation explicite.",
  "EXECUTION MONITOR": "SUIVI DES EXÉCUTIONS",
  "Agent processes": "Processus des agents",
  "Queued is Manage control-plane state. Only Running means an agent is executing.": "En attente décrit l’état du plan de contrôle Manage. Seul En cours signifie qu’un agent s’exécute.",
  "Queued in Manage": "En attente dans Manage",
  "Awaiting worker claim": "En attente de prise en charge",
  "Active agent execution": "Exécution active de l’agent",
  "Completed agent execution": "Exécution de l’agent terminée",
  "Failed agent execution": "Échec de l’exécution de l’agent",
  "Cancelled agent execution": "Exécution de l’agent annulée",
  "No active session reported": "Aucune session active signalée",
  "Live session reported": "Session active signalée",
  "Waiting for worker snapshot": "En attente de l’instantané du worker",
  "Agent process counts": "Nombre de processus d’agents",
  "RUNNING": "EN COURS",
  "QUEUED": "EN ATTENTE",
  "COMPLETED": "TERMINÉS",
  "FAILED": "ÉCHECS",
  "executing now": "en cours d’exécution",
  "waiting for a worker": "en attente d’un worker",
  "visible recent history": "historique récent visible",
  "requires review or retry": "à examiner ou relancer",
  "Loading the selected worker and its execution harness…": "Chargement du worker sélectionné et de son environnement d’exécution…",
  "Filter agent processes": "Filtrer les processus d’agents",
  "All": "Tous",
  "Active": "Actifs",
  "Queued": "En attente",
  "Completed": "Terminés",
  "Connecting to the worker…": "Connexion au worker…",
  "Process": "Processus",
  "Execution": "Exécution",
  "Timing": "Chronologie",
  "State": "État",
  "Loading active and recent agent processes…": "Chargement des processus d’agents actifs et récents…",
  "No processes match this filter.": "Aucun processus ne correspond à ce filtre.",
  "No worker process snapshot is available yet.": "Aucun instantané des processus du worker n’est encore disponible.",
  "Process visibility refreshed.": "La visibilité des processus a été actualisée.",
  "Process visibility is unavailable.": "La visibilité des processus est indisponible.",
  "ONLINE": "EN LIGNE",
  "BUSY": "OCCUPÉ",
  "OFFLINE": "HORS LIGNE",
  "UNKNOWN": "INCONNU",
  "Worker": "Worker",
  "Harness": "Environnement",
  "Model": "Modèle",
  "Authentication": "Authentification",
  "Capacity": "Capacité",
  "Approval recorded": "Approbation enregistrée",
  "No approval recorded": "Aucune approbation enregistrée",
  "Assigned to this worker": "Attribué à ce worker",
  "Unassigned from this worker": "Non attribué à ce worker",
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
  "AI Operation ↗": "Opération IA ↗",
  "Live agent output": "Sortie de l’agent en direct",
  "The worker has not published output for this process yet.": "Le worker n’a pas encore publié de sortie pour ce processus.",
  "TRUNCATED": "TRONQUÉ",
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
  "AI Operations ticket worker": "Worker de tickets AI Operations",
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
  "Provider Configured": "Fournisseur configuré",
  "Provider": "Fournisseur",
  "Worker Configured": "Worker configuré",
  "Account Count": "Nombre de comptes",
  "Authenticated Accounts": "Comptes authentifiés",
  "Worker Provider": "Fournisseur du worker",
  "Selected Account": "Compte sélectionné",
  "Surface": "Surface",
  "Method": "Méthode",
  "Evidence": "Élément de preuve",
  "Observed At Ms": "Observé le",
  "Last Verified At Ms": "Dernière vérification",
  "Remediation": "Correction",
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
  "Authenticated": "Authentifié",
  "Configured Unverified": "Configuré, non vérifié",
  "Authenticating": "Authentification en cours",
  "Awaiting Sign-in": "Connexion en attente",
  "Verifying": "Vérification",
  "Expired": "Expiré",
  "Signed Out": "Déconnecté",
  "Not Configured": "Non configuré",
  "Failed": "Échec",
  "Cancelled": "Annulé",
  "ChatGPT": "ChatGPT",
  "Claude.ai": "Claude.ai",
  "Native subscription": "Abonnement natif",
  "API key": "Clé API",
  "Access token": "Jeton d’accès",
  "Execution Succeeded": "Exécution réussie",
  "Credentials Changed": "Identifiants modifiés",
  "Local Session Present": "Session locale présente",
  "Local Session Missing": "Session locale absente",
  "Refresh Token Rejected": "Jeton de renouvellement rejeté",
  "Provider Configuration Missing": "Configuration fournisseur absente",
  "Account Selection Missing": "Sélection de compte absente",
  "none": "aucun",
  "Health Record Missing": "État d’authentification absent",
  "Health Record Unavailable": "État d’authentification indisponible",
  "Health Record Invalid": "État d’authentification invalide",
  "No action required.": "Aucune action requise.",
  "Run one contained agent task to verify remote provider access.": "Exécutez une tâche d’agent cloisonnée pour vérifier l’accès distant au fournisseur.",
  "Reauthenticate the Codex worker, refresh this screen, then relaunch blocked work.": "Réauthentifiez le worker Codex, actualisez cet écran, puis relancez le travail bloqué.",
  "Configure an execution provider before enabling agent work.": "Configurez un fournisseur d’exécution avant d’activer le travail des agents.",
  "Inspect the worker and its private authentication health record.": "Examinez le worker et son état privé d’authentification.",
  "NATIVE SUBSCRIPTIONS": "ABONNEMENTS NATIFS",
  "Agent accounts": "Comptes d’agents",
  "Connect isolated Codex CLI and Claude Code accounts with their native subscription sign-in.": "Connectez des comptes Codex CLI et Claude Code isolés avec l’authentification native de leur abonnement.",
  "NO API KEYS": "SANS CLÉS API",
  "Add Codex account": "Ajouter un compte Codex",
  "Add Claude account": "Ajouter un compte Claude",
  "Loading native accounts…": "Chargement des comptes natifs…",
  "Each account has a private provider profile. Switching the worker is explicit; Monique never rotates across subscriptions automatically.": "Chaque compte dispose d’un profil fournisseur privé. Le changement de compte du worker est explicite ; Monique ne bascule jamais automatiquement entre les abonnements.",
  "Only local account aliases and opaque references are shown. Provider identity, filesystem locations, raw payloads and credential material are never returned.": "Seuls les alias locaux et références opaques sont affichés. L’identité fournisseur, les emplacements de fichiers, les données brutes et les identifiants ne sont jamais renvoyés.",
  "Choose a local alias for this subscription account.": "Choisissez un alias local pour ce compte d’abonnement.",
  "Native sign-in": "Authentification native",
  "Native sign-in started.": "Authentification native démarrée.",
  "Native sign-in cancelled.": "Authentification native annulée.",
  "Subscription account authenticated.": "Compte d’abonnement authentifié.",
  "Sign-in did not complete.": "L’authentification n’a pas abouti.",
  "Complete sign-in with the provider, then return here.": "Terminez l’authentification auprès du fournisseur, puis revenez ici.",
  "Continue with ChatGPT ↗": "Continuer avec ChatGPT ↗",
  "Continue with Claude.ai ↗": "Continuer avec Claude.ai ↗",
  "Cancel": "Annuler",
  "ACTIVE WORKER": "WORKER ACTIF",
  "Use for worker": "Utiliser pour le worker",
  "Verify": "Vérifier",
  "Sign in again": "Se reconnecter",
  "Sign out": "Se déconnecter",
  "Remove": "Supprimer",
  "Worker account selected.": "Compte du worker sélectionné.",
  "Account status refreshed.": "État du compte actualisé.",
  "Account signed out.": "Compte déconnecté.",
  "Account removed.": "Compte supprimé.",
  "Sign out this native subscription account?": "Déconnecter ce compte d’abonnement natif ?",
  "Remove this local account profile and its native credentials?": "Supprimer ce profil de compte local et ses identifiants natifs ?",
  "No native subscription account is configured yet.": "Aucun compte d’abonnement natif n’est encore configuré.",
  "Native account management is unavailable.": "La gestion des comptes natifs est indisponible.",
  "Complete native sign-in before selecting this account.": "Terminez l’authentification native avant de sélectionner ce compte.",
  "Select another worker account before removing this one.": "Sélectionnez un autre compte de worker avant de supprimer celui-ci.",
  "Confirmation is required for this account change.": "Une confirmation est requise pour modifier ce compte.",
  "Native provider sign-in could not be started.": "L’authentification native du fournisseur n’a pas pu démarrer.",
  "Paste authorization code if Claude asks for it": "Collez le code d’autorisation si Claude le demande",
  "Submit authorization code": "Envoyer le code d’autorisation",
  "Authorization code submitted.": "Code d’autorisation envoyé.",
  "Verify the selected native subscription account before relaunching work.": "Vérifiez le compte d’abonnement natif sélectionné avant de relancer le travail.",
  "Complete the native provider sign-in in your browser.": "Terminez l’authentification native du fournisseur dans votre navigateur.",
  "Reauthenticate the selected provider account, then relaunch blocked work.": "Réauthentifiez le compte fournisseur sélectionné, puis relancez le travail bloqué.",
  "Add a native Codex or Claude account and explicitly select it for the worker.": "Ajoutez un compte Codex ou Claude natif et sélectionnez-le explicitement pour le worker.",
  "Pair a phone": "Associer un téléphone",
  "Close pairing": "Fermer l’association",
  "An invite is single use and lives five minutes. Create it with the phone already in your hand.": "Une invitation est à usage unique et vit cinq minutes. Créez-la avec le téléphone déjà en main.",
  "Sessions this phone may attach to": "Sessions auxquelles ce téléphone peut se rattacher",
  "Every listed session is selected. A phone can only reach the sessions named here.": "Toutes les sessions listées sont sélectionnées. Un téléphone n’atteint que les sessions nommées ici.",
  "Create invite": "Créer l’invitation",
  "Copy invite": "Copier l’invitation",
  "Pairing QR code": "QR code d’association",
  "Scan it in the app, or use Copy invite and paste it there instead.": "Scannez-le dans l’application, ou utilisez Copier l’invitation et collez-la à la place.",
  "This invite has expired. Create another.": "Cette invitation a expiré. Créez-en une autre.",
  "Creating the invite…": "Création de l’invitation…",
  "Invite copied. Paste it in the app.": "Invitation copiée. Collez-la dans l’application.",
  "The invite could not be copied.": "L’invitation n’a pas pu être copiée.",
  "The invite could not be created.": "L’invitation n’a pas pu être créée.",
  "The invite could not be read.": "L’invitation n’a pas pu être lue.",
  "The invite was refused. Check the operator credential and try again.": "L’invitation a été refusée. Vérifiez l’identifiant opérateur et réessayez.",
  "No session exists yet, so an invite would reach nothing. Run a task first.": "Aucune session n’existe encore : une invitation n’atteindrait rien. Lancez d’abord une tâche.",
  "The session list is unavailable, so the invite could not be scoped.": "La liste des sessions est indisponible : l’invitation n’a pas pu être cadrée.",
  "Select at least one session. A phone can only reach the sessions named here.": "Sélectionnez au moins une session. Un téléphone n’atteint que les sessions nommées ici.",
  "The QR encoder did not load. Use Copy invite instead.": "L’encodeur QR n’a pas été chargé. Utilisez plutôt Copier l’invitation.",
  "LIFECYCLE ACTIONS": "ACTIONS DU CYCLE DE VIE",
  "Create or resume a workspace": "Créer ou reprendre un espace de travail",
  "Task input remains local while lifecycle actions are unavailable": "La tâche reste locale tant que les actions du cycle de vie sont indisponibles",
  "Create unavailable": "Création indisponible",
  "Resume unavailable": "Reprise indisponible",
  "Task create and resume remain unavailable. Local host setup and checkout support typed preview and receipt operations.": "La création et la reprise de tâche restent indisponibles. La configuration d’hôte local et le checkout prennent en charge des opérations typées d’aperçu et de reçu.",
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
    [/^Expires in (\d+) seconds$/, (match) => `Expire dans ${match[1]} secondes`],
    [/^(\d+)s ago$/, (match) => `il y a ${match[1]} s`],
    [/^(\d+)m ago$/, (match) => `il y a ${match[1]} min`],
    [/^(\d+)h ago$/, (match) => `il y a ${match[1]} h`],
    [/^(\d+) connected$/, (match) => `${match[1]} connecté${match[1] === "1" ? "" : "s"}`],
    [/^(\d+) invariants? need attention$/, (match) => `${match[1]} invariant${match[1] === "1" ? " requiert" : "s requièrent"} votre attention`],
    [/^(.+?) active$/, (match) => `${match[1]} en cours`],
    [/^(.+?) pending$/, (match) => `${match[1]} en attente`],
    [/^(.+?) of (.+?) tickets$/, (match) => `${match[1]} ticket${match[1] === "1" ? "" : "s"} sur ${match[2]}`],
    [/^(.+?) of (.+?) processes$/, (match) => `${match[1]} processus sur ${match[2]}`],
    [/^Review due · (.+)$/, (match) => `Réexamen requis · ${match[1]}`],
    [/^Observed (.+)$/, (match) => `Observé ${match[1]}`],
    [/^(.+?) of (.+?) slots active$/, (match) => `${match[1]} emplacement${match[1] === "1" ? "" : "s"} actif${match[1] === "1" ? "" : "s"} sur ${match[2]}`],
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
  if (processesSnapshot) renderProcesses(processesSnapshot);
  document.querySelectorAll(".message-meta[data-created-at]").forEach(renderMessageMeta);
  if (voiceRecognition) voiceRecognition.lang = localeTag();
  if (activeSpeechUtterance) stopSpeaking();
  updateVoiceOutputButton();
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
const startupViews = ["sessions", "overview", "operations", "tickets", "chat"];

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
  if (!startupViews.includes(view)) view = "sessions";
  byId("startup-view").value = view;
  if (byId("configuration-startup")) byId("configuration-startup").value = view;
  if (persist) savePreference("monique-start-view", view);
}

applyTheme(storedPreference("monique-theme", themes, "system"), false);
applyTextScale(storedPreference("monique-text-scale", textScales, "comfortable"), false);
applySidebar(storedPreference("monique-sidebar", sidebarStates, "expanded"), false);
applyDensity(storedPreference("monique-density", densities, "comfortable"), false);
applyMotion(storedPreference("monique-motion", motionModes, "full"), false);
applyStartupView(storedPreference("monique-start-view", startupViews, "sessions"), false);
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
  const items = [];
  const add = (key, title, detail, href = null) => {
    if (!items.some((item) => item.key === key)) items.push({ key, title, detail, href });
  };
  if (status.health !== "operational") add("runtime", "Runtime health", `Daemon status is ${status.health || "unavailable"}.`);
  if (status.stale) add("stale", "Stale daemon snapshot", "The dashboard has not received a current daemon status snapshot.");
  if ((status.reconciliation_pending || 0) > 0) add("reconciliation", "Reconciliation required", `${count(status.reconciliation_pending)} daemon run or delivery outcome(s) need reconciliation.`);
  if ((status.outbox_ambiguous || 0) > 0) add("ambiguous", "Ambiguous deliveries", `${count(status.outbox_ambiguous)} outbox effect(s) have an uncertain delivery outcome.`);
  if (status.provider_available === false) add("provider", "Provider lane unavailable", "The daemon reports no available provider lane.");
  if (status.accepting_intake === false) add("intake", "Intake closed", "The daemon is not accepting new work.");
  if (processesSnapshot?.health === "stale") add("manage-stale", "Stale Manage process snapshot", "Manage process state is older than the dashboard freshness window.");
  const manageJobs = Array.isArray(processesSnapshot?.jobs) && ["ready", "degraded"].includes(processesSnapshot.health) ? processesSnapshot.jobs : [];
  manageJobs.filter((job) => job.status === "failed").slice(0, 5).forEach((job) => {
    add(
      `manage:${job.id}`,
      `Manage job ${shortProcessReference(job.id)} failed`,
      "Manage control-plane state; inspect its issue or process record for authoritative delivery evidence.",
      safeTicketLink(job.manage_url) || safeTicketLink(job.issue_url),
    );
  });
  return items;
}

function renderAttention(status) {
  const items = attention(status);
  const attentionKey = `${status.health}:${items.map((item) => item.key).join("|")}`;
  if (lastNotifiedAttentionKey !== null && attentionKey !== lastNotifiedAttentionKey && items.length > 0
      && storedPreference("monique-notifications", ["on", "off"], "off") === "on"
      && "Notification" in window && Notification.permission === "granted") {
    new Notification("Monique · attention required", { body: items.map((item) => item.title).join(" · "), tag: "monique-operational-attention" });
  }
  lastNotifiedAttentionKey = attentionKey;
  byId("attention-title").textContent = items.length === 0 ? "All operational invariants hold" : `${items.length} item${items.length === 1 ? "" : "s"} need attention`;
  byId("attention-detail").textContent = items.length === 0 ? "Provider, intake, delivery certainty and reconciliation are clear." : items.map((item) => item.title).join(" · ");
  byId("metric-attention").textContent = count(items.length);
  const list = byId("attention-list");
  list.replaceChildren();
  items.forEach((item) => {
    const row = document.createElement("li");
    const title = document.createElement("strong");
    title.textContent = item.title;
    const detail = document.createElement("span");
    detail.textContent = item.detail;
    row.append(title, detail);
    if (item.href) {
      const link = document.createElement("a");
      link.href = item.href;
      link.target = "_blank";
      link.rel = "noreferrer";
      link.textContent = "Inspect ↗";
      row.append(link);
    }
    list.append(row);
  });
  const toggle = byId("attention-toggle");
  toggle.disabled = items.length === 0;
  if (items.length === 0) {
    toggle.setAttribute("aria-expanded", "false");
    toggle.textContent = "Details";
    list.hidden = true;
  }
  return items;
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
  const issues = renderAttention(status);
  byId("global-health").textContent = health;
  byId("generation").textContent = `GEN ${count(status.generation)}`;
  byId("footer-state").textContent = `${health.toUpperCase()} / GEN ${count(status.generation)}`;
  byId("metric-running").textContent = count(status.running);
  byId("metric-inbox").textContent = count(status.inbox_pending);
  byId("metric-outbox").textContent = count(status.outbox_pending);
  byId("metric-reconciliation").textContent = count(status.reconciliation_pending);
  byId("metric-ambiguous").textContent = count(status.outbox_ambiguous);
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
  const allowed = ["overview", "sessions", "chat", "operations", "tickets", "memory", "configuration"];
  const link = globalThis.AutomoniquePlatformCockpit.parseDeepLink(typeof name === "string" && name.startsWith("#") ? name : `#${name || ""}`);
  name = allowed.includes(link.view) ? link.view : "sessions";
  if (link.workspace || link.session || link.pane) {
    cockpitState = globalThis.AutomoniquePlatformCockpit.initialState(link);
    if (link.session) platformSelectedSession = link.session;
  }
  document.querySelectorAll("[data-panel]").forEach((node) => node.classList.toggle("is-visible", node.dataset.panel === name));
  document.querySelectorAll("[data-view]").forEach((node) => {
    const active = node.dataset.view === name;
    node.classList.toggle("is-active", active);
    if (active) node.setAttribute("aria-current", "page"); else node.removeAttribute("aria-current");
  });
  byId("current-view").textContent = name === "tickets" ? "WORK QUEUES" : name.toUpperCase();
  const linkedSessions = name === "sessions" && (link.workspace || link.session || link.pane || link.file);
  const targetHash = linkedSessions ? globalThis.AutomoniquePlatformCockpit.buildDeepLink(link) : `#${name}`;
  if (window.location.hash !== targetHash) history.replaceState(null, "", targetHash);
  if (name === "memory") loadMemory(memoryQuery);
  if (name === "operations" || name === "tickets") loadOperations();
  if (name === "sessions") loadPlatform();
  if (name === "operations") loadProcesses();
  if (name === "configuration") loadConfiguration();
  if (name === "chat") loadChatHistory();
  if (window.matchMedia("(max-width: 760px)").matches) mobileSidebarOpen(false);
}

document.querySelectorAll("[data-view]").forEach((button) => button.addEventListener("click", () => showView(button.dataset.view)));
window.addEventListener("hashchange", () => showView(window.location.hash));
byId("status-refresh").addEventListener("click", () => refreshStatus({ announce: true }));

function selectedMemoryEntries() {
  const entries = memorySnapshot?.entries || [];
  return entries
    .filter((entry) => memoryKind === "all" || entry.kind === memoryKind)
    .filter((entry) => memoryStatus === "all" || entry.status === memoryStatus)
    .filter((entry) => memorySensitivity === "all" || entry.sensitivity === memorySensitivity)
    .sort((left, right) => {
      if (memorySort === "confidence_desc") return right.confidence - left.confidence || right.updated_at_ms - left.updated_at_ms;
      if (memorySort === "review_asc") return (left.review_at_ms ?? Number.MAX_SAFE_INTEGER) - (right.review_at_ms ?? Number.MAX_SAFE_INTEGER) || right.updated_at_ms - left.updated_at_ms;
      if (memorySort === "reference") return left.reference.localeCompare(right.reference, localeTag(), { numeric: true });
      return right.updated_at_ms - left.updated_at_ms || left.reference.localeCompare(right.reference, localeTag(), { numeric: true });
    });
}

function updateMemoryFacet(id, entries, field, allLabel, previous) {
  const select = byId(id);
  const values = [...new Set(entries.map((entry) => entry[field]).filter((value) => typeof value === "string"))].sort();
  select.replaceChildren();
  const all = document.createElement("option");
  all.value = "all";
  all.textContent = allLabel;
  select.append(all);
  values.forEach((value) => {
    const option = document.createElement("option");
    option.value = value;
    option.textContent = label(value);
    select.append(option);
  });
  const selected = values.includes(previous) ? previous : "all";
  select.value = selected;
  return selected;
}

function memoryDateLabel(value) {
  if (!Number.isSafeInteger(value) || value <= 0) return "—";
  return new Intl.DateTimeFormat(localeTag(), { dateStyle: "medium", timeStyle: "short" }).format(value);
}

function memoryReviewLabel(value) {
  if (!Number.isSafeInteger(value) || value <= 0) return "No review scheduled";
  return value <= Date.now() ? `Review due · ${memoryDateLabel(value)}` : memoryDateLabel(value);
}

function setMemoryMode(mode) {
  memoryMode = ["graph", "list", "timeline"].includes(mode) ? mode : "graph";
  savePreference("monique-memory-view", memoryMode);
  document.querySelectorAll("[data-memory-mode]").forEach((item) => {
    const active = item.dataset.memoryMode === memoryMode;
    item.classList.toggle("is-active", active);
    item.setAttribute("aria-pressed", String(active));
  });
  byId("memory-graph").hidden = memoryMode !== "graph";
  byId("memory-list").hidden = memoryMode !== "list";
  byId("memory-timeline").hidden = memoryMode !== "timeline";
}

function renderMemory(view) {
  memorySnapshot = view;
  const entries = view.entries || [];
  byId("memory-active").textContent = count(view.counts?.active);
  byId("memory-candidates").textContent = count(view.counts?.candidates);
  byId("memory-superseded").textContent = count(view.counts?.superseded);
  byId("memory-deleted").textContent = count(view.counts?.deleted);
  byId("memory-review-due").textContent = count(entries.filter((entry) => Number.isSafeInteger(entry.review_at_ms) && entry.review_at_ms <= Date.now()).length);
  byId("memory-messages").textContent = count(view.counts?.messages);
  memoryKind = updateMemoryFacet("memory-kind", entries, "kind", "All evidence", memoryKind);
  memoryStatus = updateMemoryFacet("memory-status", entries, "status", "All statuses", memoryStatus);
  memorySensitivity = updateMemoryFacet("memory-sensitivity", entries, "sensitivity", "All levels", memorySensitivity);
  if (!entries.some((entry) => entry.reference === selectedMemoryReference)) selectedMemoryReference = entries[0]?.reference || null;
  setMemoryMode(memoryMode);
  renderSelectedMemory();
}

function renderSelectedMemory() {
  const entries = selectedMemoryEntries();
  if (!entries.some((entry) => entry.reference === selectedMemoryReference)) selectedMemoryReference = entries[0]?.reference || null;
  const scope = memoryKind === "all" ? "evidence" : words(memoryKind);
  const query = memoryQuery ? ` for “${memoryQuery}”` : "";
  byId("memory-result-label").textContent = `${count(entries.length)} ${scope} record${entries.length === 1 ? "" : "s"}${query}`;
  renderMemoryList(entries);
  renderMemoryGraph(entries);
  renderMemoryTimeline(entries);
  renderMemoryInspector(entries.find((entry) => entry.reference === selectedMemoryReference) || null);
  byId("memory-reset").disabled = memoryKind === "all" && memoryStatus === "all" && memorySensitivity === "all" && memorySort === "updated_desc";
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
    const card = document.createElement("button");
    card.type = "button";
    card.className = "memory-record";
    card.classList.toggle("is-selected", entry.reference === selectedMemoryReference);
    card.setAttribute("aria-pressed", String(entry.reference === selectedMemoryReference));
    const ref = document.createElement("strong");
    ref.textContent = entry.reference;
    const text = document.createElement("p");
    text.setAttribute("data-i18n-skip", "");
    text.textContent = entry.content;
    const meta = document.createElement("div");
    meta.className = "record-meta";
    meta.textContent = `${words(entry.status)} · ${entry.confidence / 10}% confidence\n${memoryDateLabel(entry.updated_at_ms)}`;
    card.append(ref, text, meta);
    card.addEventListener("click", () => {
      selectedMemoryReference = entry.reference;
      renderSelectedMemory();
    });
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
    node.classList.toggle("is-selected", entry.reference === selectedMemoryReference);
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
      selectedMemoryReference = entry.reference;
      renderSelectedMemory();
    });
    graph.append(node);
  });
}

function renderMemoryTimeline(entries) {
  const root = byId("memory-timeline");
  root.replaceChildren();
  if (entries.length === 0) {
    root.append(memoryEmpty("No timeline events to display."));
    return;
  }
  [...entries].sort((left, right) => right.updated_at_ms - left.updated_at_ms).forEach((entry) => {
    const item = document.createElement("button");
    item.type = "button";
    item.className = "memory-timeline-item";
    item.classList.toggle("is-selected", entry.reference === selectedMemoryReference);
    const marker = document.createElement("i");
    marker.setAttribute("aria-hidden", "true");
    const date = document.createElement("time");
    date.dateTime = Number.isSafeInteger(entry.updated_at_ms) ? new Date(entry.updated_at_ms).toISOString() : "";
    date.textContent = memoryDateLabel(entry.updated_at_ms);
    const body = document.createElement("div");
    const heading = document.createElement("strong");
    heading.textContent = entry.reference;
    const content = document.createElement("p");
    content.setAttribute("data-i18n-skip", "");
    content.textContent = entry.content;
    const meta = document.createElement("small");
    meta.textContent = `${words(entry.kind)} · ${words(entry.status)} · R${entry.revision}`;
    body.append(heading, content, meta);
    item.append(marker, date, body);
    item.addEventListener("click", () => {
      selectedMemoryReference = entry.reference;
      renderSelectedMemory();
    });
    root.append(item);
  });
}

function memoryInspectorFact(labelText, value) {
  const row = document.createElement("div");
  const term = document.createElement("dt");
  term.textContent = labelText;
  const detail = document.createElement("dd");
  detail.setAttribute("data-i18n-skip", "");
  detail.textContent = value || "—";
  row.append(term, detail);
  return row;
}

function renderMemoryInspector(entry) {
  const root = byId("memory-inspector");
  root.replaceChildren();
  if (!entry) {
    const empty = document.createElement("div");
    empty.className = "memory-inspector-empty";
    const icon = document.createElement("span");
    icon.textContent = "◇";
    const title = document.createElement("strong");
    title.textContent = "Select evidence";
    const detail = document.createElement("p");
    detail.textContent = "Choose a graph node, record, or timeline event to inspect its provenance and review state.";
    empty.append(icon, title, detail);
    root.append(empty);
    return;
  }
  const head = document.createElement("div");
  head.className = "memory-inspector-head";
  const headingCopy = document.createElement("div");
  const eyebrow = document.createElement("span");
  eyebrow.textContent = "Evidence details";
  const title = document.createElement("h2");
  title.setAttribute("data-i18n-skip", "");
  title.textContent = entry.reference;
  headingCopy.append(eyebrow, title);
  const status = document.createElement("i");
  status.textContent = words(entry.status).toUpperCase();
  status.dataset.state = entry.status;
  head.append(headingCopy, status);
  const content = document.createElement("p");
  content.className = "memory-inspector-content";
  content.setAttribute("data-i18n-skip", "");
  content.textContent = entry.content;
  const confidence = document.createElement("div");
  confidence.className = "memory-confidence";
  const confidenceLabel = document.createElement("div");
  const confidenceName = document.createElement("span");
  confidenceName.textContent = "Confidence";
  const confidenceValue = document.createElement("strong");
  confidenceValue.textContent = `${entry.confidence / 10}%`;
  confidenceLabel.append(confidenceName, confidenceValue);
  const meter = document.createElement("meter");
  meter.min = 0;
  meter.max = 100;
  meter.value = entry.confidence / 10;
  meter.textContent = `${entry.confidence / 10}%`;
  confidence.append(confidenceLabel, meter);
  const facts = document.createElement("dl");
  facts.className = "memory-inspector-facts";
  [
    ["Kind", words(entry.kind)],
    ["Status", words(entry.status)],
    ["Sensitivity", words(entry.sensitivity)],
    ["Visibility", words(entry.visibility)],
    ["Provenance", entry.provenance],
    ["Revision", `R${entry.revision}`],
    ["Updated", memoryDateLabel(entry.updated_at_ms)],
    ["Next review", memoryReviewLabel(entry.review_at_ms)],
  ].forEach(([labelText, value]) => facts.append(memoryInspectorFact(labelText, value)));
  const actions = document.createElement("div");
  actions.className = "memory-inspector-actions";
  const copy = document.createElement("button");
  copy.type = "button";
  copy.className = "button secondary";
  copy.textContent = "Copy content";
  copy.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(entry.content);
      toast("Memory content copied.");
    } catch (_error) {
      toast("Clipboard access is unavailable.", "error");
    }
  });
  const ask = document.createElement("button");
  ask.type = "button";
  ask.className = "button secondary";
  ask.textContent = "Use recovery assistant";
  ask.dataset.openChat = `Review memory evidence ${entry.reference}. Explain what it establishes, its provenance and confidence, whether it needs review, and how it should influence current work.`;
  actions.append(copy, ask);
  root.append(head, content, confidence, facts, actions);
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
byId("memory-status").addEventListener("change", (event) => {
  memoryStatus = event.target.value;
  renderSelectedMemory();
});
byId("memory-sensitivity").addEventListener("change", (event) => {
  memorySensitivity = event.target.value;
  renderSelectedMemory();
});
byId("memory-sort").addEventListener("change", (event) => {
  memorySort = event.target.value;
  renderSelectedMemory();
});
byId("memory-reset").addEventListener("click", () => {
  memoryKind = "all";
  memoryStatus = "all";
  memorySensitivity = "all";
  memorySort = "updated_desc";
  byId("memory-kind").value = memoryKind;
  byId("memory-status").value = memoryStatus;
  byId("memory-sensitivity").value = memorySensitivity;
  byId("memory-sort").value = memorySort;
  renderSelectedMemory();
});
document.querySelectorAll("[data-memory-mode]").forEach((button) => button.addEventListener("click", () => {
  setMemoryMode(button.dataset.memoryMode);
}));

function operationLabel(value) {
  return String(value || "operation").replaceAll("_", " ").replaceAll("-", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function operationsMessage(health) {
  const messages = {
    attached: ["Operational services connected", "Live capabilities are discovered independently from Support and Manage."],
    degraded: ["Operational services partially available", "At least one configured service is connected while another needs attention."],
    not_attached: ["Operational services are not attached", "Configure the Support and Manage MCP servers to enable their relevant capabilities."],
    unavailable: ["Operational services are unavailable", "The configured services did not return a valid capability catalog."],
    busy: ["Operational services are busy", "Another contained request is using the live tool connections. Try again shortly."],
  };
  return messages[health] || ["AI Operations state unknown", "Refresh to discover the current control-plane state."];
}

function processStatusLabel(status) {
  const labels = { pending: "Queued in Manage", running: "Running", done: "Completed", failed: "Failed", cancelled: "Cancelled", unknown: "Unknown" };
  return labels[status] || operationLabel(status);
}

function processMatches(job, filter) {
  if (filter === "all") return true;
  if (filter === "active") return job.status === "running";
  if (filter === "queued") return job.status === "pending";
  if (filter === "completed") return job.status === "done";
  if (filter === "failed") return job.status === "failed";
  return false;
}

function shortProcessReference(value) {
  const text = String(value || "unknown");
  return text.length <= 16 ? text : `${text.slice(0, 12)}…`;
}

function processIssueReference(job) {
  const href = safeTicketLink(job.issue_url);
  if (href) {
    const parsed = new URL(href);
    const match = parsed.pathname.match(/^\/([^/]+)\/([^/]+)\/issues\/([1-9][0-9]*)$/);
    if (match) return { label: `${match[2]}#${match[3]}`, href };
  }
  return { label: job.issue_id ? `Ticket ${shortProcessReference(job.issue_id)}` : shortProcessReference(job.id), href: null };
}

function processTimeLabel(value) {
  const timestamp = ticketTimestamp(value);
  if (timestamp === null) return "—";
  return ticketRelativeTime(value) || ticketDateLabel(value);
}

function processDetail(labelText, value, title = null) {
  const detail = document.createElement("div");
  detail.className = "process-detail";
  const labelNode = document.createElement("span");
  labelNode.textContent = labelText;
  const valueNode = document.createElement("strong");
  valueNode.setAttribute("data-i18n-skip", "");
  valueNode.textContent = value || "—";
  if (title) valueNode.title = title;
  detail.append(labelNode, valueNode);
  return detail;
}

function renderProcessWorker(worker, health) {
  const root = byId("process-worker");
  root.replaceChildren();
  if (!worker) {
    const empty = document.createElement("div");
    empty.className = "integration-empty process-empty";
    empty.textContent = "No worker process snapshot is available yet.";
    root.append(empty);
    return;
  }
  root.dataset.state = health;
  const identity = document.createElement("div");
  identity.className = "process-worker-identity";
  const orb = document.createElement("i");
  orb.setAttribute("aria-hidden", "true");
  const copy = document.createElement("div");
  const name = document.createElement("strong");
  name.setAttribute("data-i18n-skip", "");
  name.textContent = worker.name || "Selected worker";
  const detail = document.createElement("small");
  detail.textContent = worker.status_detail || `${worker.provider} · ${worker.runtime}`;
  copy.append(name, detail);
  identity.append(orb, copy);
  const status = document.createElement("span");
  status.className = `process-worker-status status-${worker.status}`;
  status.textContent = worker.status.toUpperCase();
  const facts = document.createElement("div");
  facts.className = "process-worker-facts";
  [
    ["Harness", [worker.agent, worker.binary, worker.cli_version].filter(Boolean).join(" · ")],
    ["Model", worker.model],
    ["Authentication", `${worker.provider} · ${processStatusLabel(worker.auth_status)}`],
    ["Capacity", `${count(worker.active_jobs)} of ${count(worker.concurrency)} slots active`],
    ["Updated", processTimeLabel(worker.last_seen_at), worker.last_seen_at],
  ].forEach(([labelText, value, exact]) => facts.append(processDetail(labelText, value, exact)));
  root.append(identity, status, facts);
}

function setProcessFilter(filter) {
  processFilter = ["all", "active", "queued", "failed", "completed"].includes(filter) ? filter : "all";
  document.querySelectorAll("[data-process-filter]").forEach((button) => {
    const active = button.dataset.processFilter === processFilter;
    button.classList.toggle("is-active", active);
    button.setAttribute("aria-pressed", String(active));
  });
}

function processHierarchy(jobs) {
  const indexed = new Map(jobs.map((job) => [job.id, job]));
  const children = new Map();
  jobs.forEach((job) => {
    if (!job.parent_id || !indexed.has(job.parent_id) || job.parent_id === job.id) return;
    if (!children.has(job.parent_id)) children.set(job.parent_id, []);
    children.get(job.parent_id).push(job);
  });
  const ordered = [];
  const visited = new Set();
  const visit = (job, depth) => {
    if (visited.has(job.id)) return;
    visited.add(job.id);
    ordered.push({ job, depth: Math.min(depth, 4) });
    (children.get(job.id) || []).forEach((child) => visit(child, depth + 1));
  };
  jobs.filter((job) => !job.parent_id || !indexed.has(job.parent_id) || job.parent_id === job.id).forEach((job) => visit(job, 0));
  jobs.forEach((job) => visit(job, 0));
  return ordered;
}

function renderProcesses(view) {
  processesSnapshot = view;
  const jobs = Array.isArray(view.jobs) ? view.jobs : [];
  if (lastStatusSnapshot) renderAttention(lastStatusSnapshot);
  const health = String(view.health || "unavailable");
  byId("processes-health").textContent = health.toUpperCase();
  byId("processes-health").dataset.state = health;
  const observed = Number.isSafeInteger(view.observed_at_ms) ? new Date(view.observed_at_ms).toISOString() : null;
  byId("process-observed").textContent = observed ? `Observed ${processTimeLabel(observed)}` : "Waiting for worker snapshot";
  byId("process-observed").title = observed ? ticketDateLabel(observed) : "";
  byId("process-running").textContent = count(view.stats?.running);
  byId("process-queued").textContent = count(view.stats?.queued);
  byId("process-completed").textContent = count(view.stats?.completed);
  byId("process-failed").textContent = count(view.stats?.failed);
  renderProcessWorker(view.worker, health);
  const filterCounts = {
    all: jobs.length,
    active: jobs.filter((job) => processMatches(job, "active")).length,
    queued: jobs.filter((job) => processMatches(job, "queued")).length,
    failed: jobs.filter((job) => processMatches(job, "failed")).length,
    completed: jobs.filter((job) => processMatches(job, "completed")).length,
  };
  Object.entries(filterCounts).forEach(([name, value]) => { byId(`process-filter-${name}`).textContent = count(value); });
  const visible = processHierarchy(jobs).filter(({ job }) => processMatches(job, processFilter));
  byId("process-result-state").textContent = `${visible.length.toLocaleString(localeTag())} of ${jobs.length.toLocaleString(localeTag())} processes`;
  const root = byId("process-list");
  root.replaceChildren();
  if (visible.length === 0) {
    const empty = document.createElement("div");
    empty.className = "integration-empty process-empty";
    empty.textContent = health === "unavailable" ? "No worker process snapshot is available yet." : "No processes match this filter.";
    root.append(empty);
    return;
  }
  visible.forEach(({ job, depth }, index) => {
    const card = document.createElement("article");
    card.className = `process-card status-${job.status}`;
    if (depth > 0) {
      card.classList.add("is-child", `depth-${depth}`);
    }
    const row = document.createElement("div");
    row.className = "process-row";
    const reference = document.createElement("div");
    reference.className = "process-reference";
    const dot = document.createElement("i");
    dot.setAttribute("aria-hidden", "true");
    const referenceCopy = document.createElement("div");
    const referenceTitle = document.createElement("strong");
    referenceTitle.setAttribute("data-i18n-skip", "");
    const issueReference = processIssueReference(job);
    referenceTitle.textContent = issueReference.label;
    const referenceId = document.createElement("small");
    referenceId.setAttribute("data-i18n-skip", "");
    referenceId.textContent = shortProcessReference(job.id);
    referenceId.title = job.id;
    referenceCopy.append(referenceTitle, referenceId);
    reference.append(dot, referenceCopy);
    const execution = document.createElement("div");
    execution.className = "process-execution";
    const executionTitle = document.createElement("strong");
    const executionName = [operationLabel(job.provider), operationLabel(job.runtime)].filter((value) => value !== "Unknown").join(" · ");
    const executionState = {
      pending: "Awaiting worker claim",
      running: "Active agent execution",
      done: "Completed agent execution",
      failed: "Failed agent execution",
      cancelled: "Cancelled agent execution",
    }[job.status] || "Agent execution";
    executionTitle.textContent = executionName || executionState;
    const facts = document.createElement("div");
    facts.className = "process-facts";
    [job.kind ? operationLabel(job.kind) : null, job.parent_id ? "Observed child process" : null, operationLabel(job.source), job.assigned_to_worker ? "Assigned to this worker" : "Unassigned from this worker", job.approved ? "Approval recorded" : "No approval recorded", job.status === "running" && job.session_id ? "Live session reported" : job.status === "pending" ? "No active session reported" : null]
      .filter(Boolean)
      .forEach((value) => {
        const fact = document.createElement("span");
        fact.textContent = value;
        facts.append(fact);
      });
    execution.append(executionTitle, facts);
    const timing = document.createElement("div");
    timing.className = "process-timing";
    const updated = document.createElement("strong");
    updated.textContent = processTimeLabel(job.updated_at);
    if (job.updated_at) updated.title = ticketDateLabel(job.updated_at);
    const created = document.createElement("small");
    created.textContent = job.created_at ? `Created ${processTimeLabel(job.created_at)}` : "Created —";
    if (job.created_at) created.title = ticketDateLabel(job.created_at);
    timing.append(updated, created);
    const lifecycle = document.createElement("div");
    lifecycle.className = "process-lifecycle";
    const status = document.createElement("span");
    status.className = `process-status status-${job.status}`;
    status.textContent = processStatusLabel(job.status);
    const detailsButton = document.createElement("button");
    detailsButton.type = "button";
    detailsButton.textContent = "Details";
    const detailsId = `process-details-${index}`;
    detailsButton.setAttribute("aria-controls", detailsId);
    detailsButton.setAttribute("aria-expanded", "false");
    lifecycle.append(status, detailsButton);
    if (issueReference.href) {
      const issueLink = document.createElement("a");
      issueLink.href = issueReference.href;
      issueLink.target = "_blank";
      issueLink.rel = "noreferrer";
      issueLink.textContent = "GitHub ↗";
      lifecycle.append(issueLink);
    }
    const manageHref = safeTicketLink(job.manage_url);
    if (manageHref) {
      const manageLink = document.createElement("a");
      manageLink.href = manageHref;
      manageLink.target = "_blank";
      manageLink.rel = "noreferrer";
      manageLink.textContent = "Manage ↗";
      lifecycle.append(manageLink);
    }
    const details = document.createElement("div");
    details.className = "process-details";
    details.id = detailsId;
    details.hidden = true;
    [
      ["Process", job.id],
      ["Kind", job.kind ? operationLabel(job.kind) : null],
      ["Parent", job.parent_id],
      ["Issue", job.issue_id],
      ["Session", job.session_id],
      ["Site", job.site_id],
      ["Provider", operationLabel(job.provider)],
      ["Runtime", operationLabel(job.runtime)],
      ["Decisions", String(job.decision_count)],
      ["Created", job.created_at ? ticketDateLabel(job.created_at) : null, job.created_at],
      ["Updated", job.updated_at ? ticketDateLabel(job.updated_at) : null, job.updated_at],
    ].filter(([, value]) => value).forEach(([labelText, value, exact]) => details.append(processDetail(labelText, value, exact)));
    const output = document.createElement("section");
    output.className = "process-output";
    output.setAttribute("aria-label", "Live agent output");
    const outputHead = document.createElement("div");
    const outputTitle = document.createElement("strong");
    outputTitle.textContent = "Live agent output";
    const outputCount = document.createElement("small");
    const outputLines = Array.isArray(job.output) ? job.output : [];
    outputCount.textContent = `${outputLines.length.toLocaleString(localeTag())} events`;
    outputHead.append(outputTitle, outputCount);
    const outputLog = document.createElement("div");
    outputLog.className = "process-output-log";
    outputLog.setAttribute("role", "log");
    if (outputLines.length === 0) {
      const emptyOutput = document.createElement("p");
      emptyOutput.textContent = "The worker has not published output for this process yet.";
      outputLog.append(emptyOutput);
    } else {
      outputLines.forEach((line) => {
        const entry = document.createElement("article");
        const meta = document.createElement("div");
        const kind = document.createElement("span");
        kind.textContent = operationLabel(line.kind);
        const at = document.createElement("time");
        const timestamp = Number.isSafeInteger(line.at_ms) ? new Date(line.at_ms).toISOString() : null;
        at.textContent = timestamp ? processTimeLabel(timestamp) : "—";
        if (timestamp) {
          at.dateTime = timestamp;
          at.title = ticketDateLabel(timestamp);
        }
        meta.append(kind, at);
        if (line.truncated) {
          const truncated = document.createElement("i");
          truncated.textContent = "TRUNCATED";
          meta.append(truncated);
        }
        const text = document.createElement("pre");
        text.setAttribute("data-i18n-skip", "");
        text.textContent = line.text;
        entry.append(meta, text);
        outputLog.append(entry);
      });
    }
    output.append(outputHead, outputLog);
    details.append(output);
    const initiallyExpanded = expandedProcesses.has(job.id);
    detailsButton.setAttribute("aria-expanded", String(initiallyExpanded));
    detailsButton.textContent = initiallyExpanded ? "Hide details" : "Details";
    details.hidden = !initiallyExpanded;
    card.classList.toggle("is-expanded", initiallyExpanded);
    detailsButton.addEventListener("click", () => {
      const expanded = detailsButton.getAttribute("aria-expanded") === "true";
      detailsButton.setAttribute("aria-expanded", String(!expanded));
      detailsButton.textContent = expanded ? "Details" : "Hide details";
      details.hidden = expanded;
      card.classList.toggle("is-expanded", !expanded);
      if (expanded) expandedProcesses.delete(job.id);
      else expandedProcesses.add(job.id);
    });
    row.append(reference, execution, timing, lifecycle);
    card.append(row, details);
    root.append(card);
  });
}

async function loadProcesses({ announce = false } = {}) {
  const button = byId("processes-refresh");
  button.disabled = true;
  try {
    renderProcesses(await api("/api/processes"));
    if (announce) toast("Process visibility refreshed.");
  } catch (_error) {
    renderProcesses({ health: "unavailable", observed_at_ms: Date.now(), stats: {}, worker: null, jobs: [] });
    if (announce) toast("Process visibility is unavailable.", "error");
  } finally {
    button.disabled = false;
  }
}

function cockpitReplaceNamedList(id, values, emptyMessage) {
  const root = byId(id);
  root.replaceChildren();
  if (values.length === 0) {
    const empty = document.createElement("div");
    empty.className = "cockpit-unavailable";
    empty.textContent = emptyMessage;
    root.append(empty);
    return;
  }
  values.forEach((value) => {
    const item = document.createElement("span");
    item.className = "cockpit-compact-option";
    item.textContent = value.label;
    item.title = value.id;
    root.append(item);
  });
}

function cockpitSignal(id, label, signal) {
  const root = byId(id);
  root.replaceChildren();
  const source = document.createElement("small");
  source.textContent = label;
  const state = document.createElement("strong");
  state.textContent = signal ? words(signal.state) : "Unavailable";
  const detail = document.createElement("span");
  detail.textContent = signal
    ? `${signal.reference ? `${signal.reference} · ` : ""}${words(signal.freshness)} · ${signal.unread === null ? "unread unknown" : `${count(signal.unread)} unread`}`
    : "Freshness unknown · unread unknown";
  root.dataset.freshness = signal?.freshness || "unknown";
  root.append(source, state, detail);
}

function renderCockpitReadModels(readModels) {
  const values = [
    ["cockpit-files-state", readModels.files, (value) => `${count(value.length)} bounded file${value.length === 1 ? "" : "s"}`],
    ["cockpit-review-state", readModels.review, () => "Structured review available"],
    ["cockpit-checks-state", readModels.checks, (value) => `${count(value.length)} structured check${value.length === 1 ? "" : "s"}`],
    ["cockpit-delivery-state", readModels.delivery, () => "Structured delivery available"],
  ];
  values.forEach(([id, value, available]) => {
    const node = byId(id);
    node.textContent = value === null ? "Unavailable" : available(value);
    node.dataset.available = String(value !== null);
  });
}

function renderCockpitReceipt(receipt) {
  const root = byId("cockpit-action-receipt");
  root.dataset.state = receipt.state;
  root.hidden = receipt.state === "idle";
  if (receipt.state === "idle") return;
  const descriptions = {
    pending: "Action receipt is pending. Reconcile by receipt identity; do not replay.",
    refused: "Action was refused. Review the exact reason before preparing another preview.",
    ambiguous: "Outcome is ambiguous. Lookup by receipt identity without replay.",
    completed: "Action receipt is terminal. Refresh the exact workspace revision before another action.",
  };
  root.textContent = `${words(receipt.state)} · ${receipt.message || descriptions[receipt.state] || "Structured receipt state"}`;
}

function updateCockpitLink(workspace, sessionId = null) {
  const current = globalThis.AutomoniquePlatformCockpit.parseDeepLink(window.location.hash);
  const switchingWorkspace = Boolean(workspace && current.workspace && current.workspace !== workspace.id);
  const hash = globalThis.AutomoniquePlatformCockpit.buildDeepLink({
    ...(!switchingWorkspace ? current : {}),
    workspace: workspace?.id || current.workspace,
    session: workspace ? (sessionId || workspace.session_id) : (sessionId || current.session),
  });
  history.replaceState(null, "", hash);
}

function selectCockpitWorkspace(workspace) {
  cockpitState = globalThis.AutomoniquePlatformCockpit.reduce(cockpitState, { type: "select_workspace", workspace: workspace.id });
  updateCockpitLink(workspace);
  loadPlatform();
}

function renderHostedCockpit(view) {
  const link = globalThis.AutomoniquePlatformCockpit.parseDeepLink(window.location.hash);
  const selection = {
    workspace: cockpitState.selection.workspace || link.workspace,
    session: cockpitState.selection.session || link.session || platformSelectedSession,
  };
  cockpitPresentation = globalThis.AutomoniquePlatformCockpit.derivePresentation(view, selection);
  const capability = byId("cockpit-capability-state");
  capability.dataset.mode = cockpitPresentation.mode;
  capability.replaceChildren();
  const capabilityTitle = document.createElement("strong");
  capabilityTitle.textContent = cockpitPresentation.mode === "v2" ? "Structured workspace context" : cockpitPresentation.mode === "partial" ? "Partial workspace capability" : "Platform v1 retained-session mode";
  const capabilityDetail = document.createElement("span");
  capabilityDetail.textContent = cockpitPresentation.stale
    ? "Snapshot is stale. Workspace actions are read-only until a fresh exact capability arrives."
    : cockpitPresentation.degradation || "Structured projects, hosts, workspaces, status signals, and read models are available.";
  capability.append(capabilityTitle, capabilityDetail);

  byId("cockpit-project-count").textContent = count(cockpitPresentation.projects.length);
  byId("cockpit-host-count").textContent = count(cockpitPresentation.hosts.length);
  byId("cockpit-workspace-count").textContent = count(cockpitPresentation.workspaces.length);
  cockpitReplaceNamedList("cockpit-project-list", cockpitPresentation.projects, "Structured project context unavailable.");
  cockpitReplaceNamedList("cockpit-host-list", cockpitPresentation.hosts, "Structured host context unavailable.");

  const workspaceRoot = byId("cockpit-workspace-list");
  workspaceRoot.replaceChildren();
  const filtered = cockpitPresentation.workspaces.filter((workspace) => !cockpitPresentation.attentionAvailable || cockpitState.attentionFilter === "all" || workspace.attention === cockpitState.attentionFilter);
  if (filtered.length === 0) {
    const empty = document.createElement("div");
    empty.className = "cockpit-unavailable";
    empty.textContent = cockpitPresentation.workspaces.length === 0 ? "No structured workspaces advertised." : "No workspaces match this attention state.";
    workspaceRoot.append(empty);
  }
  filtered.forEach((workspace) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "cockpit-workspace-option";
    button.setAttribute("role", "option");
    button.setAttribute("aria-selected", String(cockpitPresentation.selectedWorkspace?.id === workspace.id));
    button.classList.toggle("is-selected", cockpitPresentation.selectedWorkspace?.id === workspace.id);
    const labelNode = document.createElement("strong");
    labelNode.textContent = workspace.label;
    const context = document.createElement("span");
    context.textContent = `${workspace.branch || "branch unavailable"} · ${workspace.attention ? words(workspace.attention) : "attention unavailable"}`;
    button.append(labelNode, context);
    button.addEventListener("click", () => selectCockpitWorkspace(workspace));
    workspaceRoot.append(button);
  });

  Object.entries({ needs_you: "cockpit-needs-you-count", working: "cockpit-working-count", blocked: "cockpit-blocked-count", done: "cockpit-done-count" })
    .forEach(([state, id]) => { byId(id).textContent = count(cockpitPresentation.attention[state]); });
  document.querySelectorAll("[data-cockpit-attention]").forEach((button) => {
    button.disabled = button.dataset.cockpitAttention !== "all" && !cockpitPresentation.attentionAvailable;
    const active = cockpitPresentation.attentionAvailable
      ? button.dataset.cockpitAttention === cockpitState.attentionFilter
      : button.dataset.cockpitAttention === "all";
    button.classList.toggle("is-active", active);
    button.setAttribute("aria-pressed", String(active));
  });

  const workspace = cockpitPresentation.selectedWorkspace;
  byId("cockpit-workspace-coordinate").textContent = workspace ? workspace.id : "NO STRUCTURED WORKSPACE";
  byId("cockpit-workspace-title").textContent = workspace?.label || "Retained session mode";
  byId("cockpit-workspace-branch").textContent = workspace?.branch ? `Branch ${workspace.branch}` : "Branch unavailable · no inference from conversation summaries";
  cockpitSignal("cockpit-external-signal", "EXTERNAL WORK", workspace?.external_work);
  cockpitSignal("cockpit-agent-signal", "INTERNAL AGENT", workspace?.internal_agent);

  const create = byId("cockpit-create-preview");
  const resume = byId("cockpit-resume-preview");
  const unresolvedControl = Boolean(cockpitControlHandle) || cockpitControlBusy;
  create.disabled = cockpitPresentation.create.available !== true || unresolvedControl;
  resume.disabled = cockpitPresentation.resume.available !== true || unresolvedControl;
  create.textContent = cockpitPresentation.create.available ? "Prepare create" : "Create unavailable";
  resume.textContent = cockpitPresentation.resume.available ? "Prepare resume" : "Resume unavailable";
  const localLifecycle = globalThis.AutomoniquePlatformCockpit.lifecycleStatus(cockpitPresentation.localLifecycle);
  const lifecycleReason = byId("cockpit-action-reason");
  lifecycleReason.dataset.localLifecycle = localLifecycle.state;
  lifecycleReason.textContent = localLifecycle.message;
  if (workspace?.id !== cockpitTaskWorkspaceId) {
    byId("cockpit-task-input").value = cockpitPresentation.create.task_id || cockpitPresentation.resume.task_id || "";
    cockpitTaskWorkspaceId = workspace?.id || null;
  }
  byId("cockpit-task-input").disabled = !(cockpitPresentation.create.available || cockpitPresentation.resume.available);
  byId("cockpit-base-selector").disabled = !cockpitPresentation.create.available || unresolvedControl;
  byId("cockpit-branch-selector").disabled = !cockpitPresentation.create.available || unresolvedControl;

  const copy = byId("cockpit-copy-link");
  copy.disabled = !workspace;
  byId("cockpit-inspector-workspace").textContent = workspace?.id || "No workspace selected";
  byId("cockpit-inspector-session").textContent = link.session || workspace?.session_id || "—";
  byId("cockpit-inspector-pane").textContent = link.pane || "—";
  byId("cockpit-inspector-anchor").textContent = link.file ? `${link.file} · ${link.hunk} · ${link.side}:${link.line}` : "—";

  renderCockpitReadModels(cockpitPresentation.readModels);
  renderCockpitReceipt(cockpitState.receipt.state === "idle" ? cockpitPresentation.receipt : cockpitState.receipt);
  const reviewLink = globalThis.AutomoniquePlatformCockpit.parseDeepLink(window.location.hash);
  const exactAnchor = reviewLink.file && reviewLink.hunk && reviewLink.side && reviewLink.line;
  const addComment = cockpitPresentation.reviewActions.addComment;
  const approveReview = cockpitPresentation.reviewActions.approveReview;
  byId("cockpit-add-comment").disabled = !addComment.available || !exactAnchor || unresolvedControl;
  byId("cockpit-approve-review").disabled = !approveReview.available || unresolvedControl;
  byId("cockpit-add-comment").textContent = addComment.available ? "Add exact comment" : "Add comment unavailable";
  byId("cockpit-approve-review").textContent = approveReview.available ? "Approve review" : "Approve unavailable";
  byId("cockpit-review-comment").disabled = !addComment.available || unresolvedControl;
  byId("cockpit-review-action-reason").textContent = unresolvedControl
    ? "An unresolved durable receipt is lookup-only. New writes are disabled."
    : !exactAnchor
      ? "Add comment requires an exact file, hunk, side, and line deep link."
      : "Only local add-comment and approve-review are enabled; git, CI, and pull-request families remain unavailable.";
  const activity = byId("cockpit-activity-list");
  activity.replaceChildren();
  if (cockpitPresentation.activities.length === 0) {
    const item = document.createElement("li");
    const title = document.createElement("strong");
    title.textContent = "No structured activity";
    const detail = document.createElement("span");
    detail.textContent = "Retained history remains in Conversation.";
    item.append(title, detail);
    activity.append(item);
  } else {
    cockpitPresentation.activities.forEach((entry) => {
      const item = document.createElement("li");
      const title = document.createElement("strong");
      title.textContent = entry.label;
      const detail = document.createElement("span");
      detail.textContent = `${entry.at} · ${entry.source || entry.kind}`;
      if (entry.deep_link) {
        const link = document.createElement("a");
        link.href = entry.deep_link;
        link.textContent = "Open exact context";
        item.append(title, detail, link);
      } else {
        item.append(title, detail);
      }
      activity.append(item);
    });
  }
}

function renderPlatform(view) {
  const retained = view?.retained_v1 && typeof view.retained_v1 === "object" ? view.retained_v1 : {};
  cockpitSnapshot = view?.schema === "automonique.dashboard.cockpit/v2" ? view : null;
  renderHostedCockpit(view);
  renderRetainedPlatform(retained);
}

function renderRetainedPlatform(retained) {
  const sessions = Array.isArray(retained.sessions) ? retained.sessions : [];
  const inventory = retained.inventory || {};
  platformSnapshot = retained;
  byId("platform-sessions").textContent = count(sessions.length);
  byId("platform-health").textContent = words(retained.health || "unavailable").toUpperCase();
  byId("platform-health").dataset.state = retained.health || "unavailable";
  byId("platform-cursor").textContent = retained.sessions_cursor
    ? `${words(retained.sessions_cursor.authority)} / ${retained.sessions_cursor.topic} / seq ${String(retained.sessions_cursor.sequence)}`
    : inventory.state === "refused"
      ? "Session inventory refused"
      : "No session cursor";
  const root = byId("platform-session-list");
  root.replaceChildren();
  if (sessions.length === 0) {
    const empty = document.createElement("div");
    empty.className = "integration-empty";
    empty.textContent = inventory.state === "refused"
      ? `Session listing unavailable: ${inventory.explanation || "refused by the platform authority"}.`
      : "No retained sessions are currently visible.";
    root.append(empty);
    return;
  }
  sessions.forEach((session) => {
    const record = session.session || {};
    const coordinate = record.resource || {};
    const button = document.createElement("button");
    button.type = "button";
    button.className = "platform-session-option";
    button.classList.toggle("is-selected", coordinate.id === platformSelectedSession);
    button.disabled = session.attachable !== true;
    button.dataset.sessionId = coordinate.id || "";
    const title = document.createElement("strong");
    title.setAttribute("data-i18n-skip", "");
    title.textContent = coordinate.id || "Unnamed session";
    const summary = document.createElement("span");
    summary.setAttribute("data-i18n-skip", "");
    summary.textContent = record.summary || "No bounded summary";
    const posture = document.createElement("small");
    posture.textContent = `${words(record.freshness || "unknown")} · ${session.run ? "run present" : "idle"} · ${session.controllable ? "control available" : "observe only"}`;
    button.append(title, summary, posture);
    button.addEventListener("click", () => selectPlatformSession(coordinate.id));
    root.append(button);
  });
  if (platformSelectedSession && !sessions.some((session) => session.session?.resource?.id === platformSelectedSession)) {
    platformExactRevision = null;
    byId("platform-session-empty").hidden = true;
    byId("platform-session-detail").hidden = false;
    byId("platform-session-status").textContent = "Selected session is no longer visible in the fresh authority listing.";
    settlePlatformFence(null);
  }
}

function platformSelectedSessionVisible() {
  const sessions = Array.isArray(platformSnapshot?.sessions) ? platformSnapshot.sessions : [];
  return sessions.some((session) => session.session?.resource?.id === platformSelectedSession);
}

function platformPost(payload) {
  return api("/api/platform/session", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

function validPlatformDecimal(value, allowZero = true) {
  return globalThis.AutomoniquePlatformCockpit.validDecimal(value, allowZero);
}

function platformDecimalGreater(left, right) {
  return globalThis.AutomoniquePlatformCockpit.decimalGreater(left, right);
}

function readPlatformMutation() {
  try {
    const value = JSON.parse(sessionStorage.getItem("monique-platform-reconciliation") || "null");
    if (!value || typeof value.sessionId !== "string" || typeof value.idempotencyKey !== "string") return null;
    if (value.expectedRevision !== null && !validPlatformDecimal(value.expectedRevision, false)) return null;
    return value;
  } catch (_error) {
    return null;
  }
}

function storePlatformMutation(value) {
  platformMutation = value;
  try {
    if (value) sessionStorage.setItem("monique-platform-reconciliation", JSON.stringify(value));
    else sessionStorage.removeItem("monique-platform-reconciliation");
  } catch (_error) {
    // Private browsing may disable storage. The in-memory fence still applies.
  }
}

function platformCommandRevision(command) {
  return command?.state === "ready" && validPlatformDecimal(command.session?.revision, false)
    ? command.session.revision
    : null;
}

function renderPlatformHistory(history, replace = false) {
  const root = byId("platform-history");
  if (replace) root.replaceChildren();
  if (!history || history.state === "refused") {
    if (replace) {
      const item = document.createElement("div");
      item.className = "platform-history-notice";
      item.textContent = `History refused: ${history?.explanation || "no explanation"}.`;
      root.append(item);
    }
    byId("platform-history-more").hidden = true;
    return;
  }
  if (history.state === "resync_required") {
    root.replaceChildren();
    const item = document.createElement("div");
    item.className = "platform-history-notice";
    item.textContent = `History retention changed (${history.snapshot_from}–${history.snapshot_to}). Replacing with a fresh snapshot…`;
    root.append(item);
    byId("platform-history-more").hidden = true;
    window.setTimeout(() => openPlatformSession(platformSelectedSession), 0);
    return;
  }
  if (history.state !== "page") return;
  platformHistoryCursor = history.terminal_cursor;
  const events = Array.isArray(history.events) ? history.events : [];
  events.forEach((event) => {
    const item = document.createElement("article");
    item.className = `platform-history-event is-${event.kind || "unknown"}`;
    item.dataset.cursor = event.cursor || "";
    const head = document.createElement("div");
    const kind = document.createElement("strong");
    kind.textContent = event.kind === "message" ? words(event.role || "message") : words(event.kind || "event");
    const cursor = document.createElement("small");
    cursor.textContent = `#${event.cursor || "—"}`;
    head.append(kind, cursor);
    const content = document.createElement("p");
    content.setAttribute("data-i18n-skip", "");
    if (event.kind === "message") content.textContent = event.text || "";
    else if (event.kind === "tool_state") content.textContent = `${event.label || "Tool step"}: ${words(event.state)}`;
    else if (event.kind === "run_state") content.textContent = `Run ${words(event.state)}`;
    else content.textContent = `Sanitized ${words(event.source || "unknown event")}`;
    item.append(head, content);
    root.append(item);
  });
  byId("platform-history-more").hidden = history.has_more !== true;
  root.scrollTop = root.scrollHeight;
}

function renderPlatformReceipt(view) {
  const root = byId("platform-receipt");
  root.hidden = false;
  root.dataset.state = view.state;
  if (view.state === "ambiguous") {
    root.textContent = "Outcome uncertain. Reconciling this idempotency key without replaying the follow-up.";
    return;
  }
  if (view.state === "refused") {
    root.textContent = `Refused (${words(view.outcome)}): ${view.explanation}`;
    return;
  }
  const receipt = view.receipt || {};
  root.textContent = `Receipt ${receipt.id || "—"}: ${words(receipt.outcome || "unknown")} · ${words(receipt.lifecycle || "unknown")}.`;
}

function settlePlatformFence(command) {
  if (command !== undefined && command !== null) platformExactRevision = platformCommandRevision(command);
  const revision = platformExactRevision;
  if (platformMutation?.expectedRevision && revision && platformDecimalGreater(revision, platformMutation.expectedRevision)) {
    storePlatformMutation(null);
    byId("platform-receipt").hidden = true;
  }
  const blocked = platformBusy || platformMutation !== null || revision === null;
  byId("platform-follow-up").disabled = blocked;
  byId("platform-send").disabled = blocked;
  byId("platform-composer-note").textContent = platformMutation
    ? "This mutation is fenced until its receipt is reconciled and a newer session revision is observed."
    : revision
      ? `Exact session revision ${revision}.`
      : "Follow-up unavailable until command state supplies an exact revision.";
}

async function openPlatformSession(sessionId) {
  if (!sessionId || platformBusy) return;
  platformBusy = true;
  byId("platform-session-empty").hidden = true;
  byId("platform-session-detail").hidden = false;
  byId("platform-session-status").textContent = "Attaching as observer…";
  settlePlatformFence(null);
  try {
    const view = await platformPost({ action: "open", session_id: sessionId });
    if (view.state === "refused") {
      renderPlatformReceipt(view);
      byId("platform-session-status").textContent = `Attach refused · ${words(view.outcome)}`;
      return;
    }
    if (view.state !== "open") throw new Error("Unexpected retained-session response");
    const record = view.session?.session || {};
    const coordinate = record.resource || {};
    byId("platform-session-coordinate").textContent = `${coordinate.authority || "automonique"} / ${coordinate.kind || "session"} / ${coordinate.id || sessionId}`;
    byId("platform-session-summary").textContent = record.summary || "No bounded summary";
    byId("platform-session-posture").textContent = `${words(record.freshness || "unknown")} · Observer · control not claimed${view.control?.available ? " · control available to claim elsewhere" : ""}`;
    const approvals = view.command?.state === "ready" && Array.isArray(view.command.pending_approvals) ? view.command.pending_approvals.length : 0;
    const run = view.command?.state === "ready" && view.command.run ? "run present" : "no active run target";
    byId("platform-session-status").textContent = `Attached · ${run} · ${approvals} pending approval${approvals === 1 ? "" : "s"}`;
    renderPlatformHistory(view.history, true);
    settlePlatformFence(view.command);
  } catch (error) {
    byId("platform-session-status").textContent = `Session unavailable: ${error.message}`;
  } finally {
    platformBusy = false;
    settlePlatformFence(null);
  }
}

async function selectPlatformSession(sessionId) {
  if (!sessionId || sessionId === platformSelectedSession) return openPlatformSession(sessionId);
  const previous = platformSelectedSession;
  platformSelectedSession = sessionId;
  cockpitState = globalThis.AutomoniquePlatformCockpit.reduce(cockpitState, { type: "select_session", session: sessionId });
  const matchingWorkspace = cockpitPresentation?.workspaces.find((workspace) => workspace.session_ids.includes(sessionId)) || null;
  if (matchingWorkspace) {
    cockpitState = globalThis.AutomoniquePlatformCockpit.reduce(cockpitState, { type: "select_workspace", workspace: matchingWorkspace.id });
  }
  platformHistoryCursor = null;
  platformExactRevision = null;
  try { sessionStorage.setItem("monique-platform-session", sessionId); } catch (_error) { /* memory-only fallback */ }
  updateCockpitLink(matchingWorkspace || cockpitPresentation?.selectedWorkspace, sessionId);
  renderHostedCockpit(cockpitSnapshot || {});
  renderRetainedPlatform(platformSnapshot || {});
  if (previous) platformPost({ action: "detach", session_id: previous }).catch(() => {});
  await openPlatformSession(sessionId);
}

async function pagePlatformHistory() {
  if (!platformSelectedSession || !validPlatformDecimal(platformHistoryCursor)) return;
  const view = await platformPost({ action: "page", session_id: platformSelectedSession, after: platformHistoryCursor });
  if (view.state === "page") renderPlatformHistory(view.history, false);
  else if (view.state === "refused") renderPlatformReceipt(view);
}

async function reconcilePlatformMutation() {
  if (!platformMutation || platformBusy) return;
  platformBusy = true;
  settlePlatformFence(null);
  let refreshSession = false;
  try {
    const view = await platformPost({
      action: "reconcile",
      session_id: platformMutation.sessionId,
      idempotency_key: platformMutation.idempotencyKey,
    });
    renderPlatformReceipt(view);
    if (view.state === "receipt") {
      const directive = globalThis.AutomoniquePlatformCockpit.receiptDirective(view);
      if (directive === "reconcile") return;
      if (directive === "settled") {
        storePlatformMutation(null);
      } else {
        platformMutation.expectedRevision = platformMutation.expectedRevision || "0";
        storePlatformMutation(platformMutation);
        refreshSession = true;
      }
    }
  } catch (_error) {
    renderPlatformReceipt({ state: "ambiguous" });
  } finally {
    platformBusy = false;
    settlePlatformFence(null);
    if (refreshSession && platformSelectedSession) await openPlatformSession(platformSelectedSession);
  }
}

async function sendPlatformFollowUp(event) {
  event.preventDefault();
  if (platformBusy || platformMutation || !platformSelectedSession) return;
  const text = byId("platform-follow-up").value.trim();
  const revisionText = byId("platform-composer-note").textContent.match(/[0-9]+/)?.[0];
  if (!text || !validPlatformDecimal(revisionText, false)) return;
  const idempotencyKey = crypto.randomUUID();
  storePlatformMutation({ sessionId: platformSelectedSession, idempotencyKey, expectedRevision: revisionText });
  platformBusy = true;
  settlePlatformFence(null);
  try {
    const view = await platformPost({ action: "follow_up", session_id: platformSelectedSession, expected_revision: revisionText, idempotency_key: idempotencyKey, text });
    renderPlatformReceipt(view);
    if (view.state === "refused") storePlatformMutation(null);
    else if (view.state === "receipt") {
      byId("platform-follow-up").value = "";
      if (globalThis.AutomoniquePlatformCockpit.receiptDirective(view) === "settled") storePlatformMutation(null);
    }
  } catch (_error) {
    renderPlatformReceipt({ state: "ambiguous" });
  } finally {
    platformBusy = false;
    settlePlatformFence(null);
  }
}

async function detachPlatformSession() {
  if (!platformSelectedSession) return;
  const sessionId = platformSelectedSession;
  try { await platformPost({ action: "detach", session_id: sessionId }); } catch (_error) { /* selection can still close locally */ }
  platformSelectedSession = null;
  platformHistoryCursor = null;
  platformExactRevision = null;
  try { sessionStorage.removeItem("monique-platform-session"); } catch (_error) { /* memory-only fallback */ }
  history.replaceState(null, "", globalThis.AutomoniquePlatformCockpit.buildDeepLink({
    view: "sessions",
    workspace: cockpitPresentation?.selectedWorkspace?.id,
  }));
  byId("platform-session-detail").hidden = true;
  byId("platform-session-empty").hidden = false;
  renderRetainedPlatform(platformSnapshot || {});
}

async function loadPlatform({ announce = false } = {}) {
  const button = byId("platform-refresh");
  button.disabled = true;
  try {
    const link = globalThis.AutomoniquePlatformCockpit.parseDeepLink(window.location.hash);
    const workspaceId = cockpitState.selection.workspace || link.workspace;
    renderPlatform(await api("/api/platform/cockpit", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: "read", ...(workspaceId ? { workspace_id: workspaceId } : {}) }),
    }));
    if (cockpitControlHandle) await reconcileCockpitControl();
    if (platformMutation) await reconcilePlatformMutation();
    else if (platformSelectedSession && platformSelectedSessionVisible() && byId("platform-session-detail").hidden) await openPlatformSession(platformSelectedSession);
    else if (platformSelectedSession && platformSelectedSessionVisible() && !platformBusy) await pagePlatformHistory();
    if (announce) toast("Shared platform projection refreshed.");
  } catch (_error) {
    renderPlatform({
      schema: "automonique.dashboard.cockpit/v2",
      mode: "v1",
      degradation: { category: "platform_cockpit_unavailable" },
      retained_v1: { health: "unavailable", capabilities: {}, resources: [], sessions: [] },
      projects: [], hosts: [], workspaces: [], selected: {}, actions: {},
    });
    if (announce) toast("The shared platform projection is unavailable.", "error");
  } finally {
    button.disabled = false;
  }
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
    category.textContent = `${operationLabel(tool.surface)} · ${operationLabel(tool.category)}`;
    category.title = `Configured server: ${tool.server}`;
    const authority = document.createElement("i");
    authority.className = tool.authority === "read_only" ? "safe" : "approval";
    authority.textContent = tool.authority === "read_only" ? "SAFE READ" : "APPROVAL";
    head.append(category, authority);
    const title = document.createElement("strong");
    title.setAttribute("data-i18n-skip", "");
    title.textContent = operationLabel(tool.name);
    const description = document.createElement("p");
    if (tool.description) description.setAttribute("data-i18n-skip", "");
    description.textContent = tool.description || "Live connected-service capability.";
    const footer = document.createElement("div");
    const input = document.createElement("small");
    input.textContent = tool.requires_input ? "Details required" : "Ready to plan";
    const use = document.createElement("button");
    use.type = "button";
    use.textContent = "Use with Monique →";
    use.dataset.openChat = `Help me use the ${operationLabel(tool.surface)} capability “${operationLabel(tool.name)}”. Explain what it does, collect any required details, and stage any mutation for my approval.`;
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
    if (ticketSurface !== "all" && ticket.integration !== ticketSurface) return false;
    if (!ticketMatchesStatus(ticket, ticketFilter)) return false;
    if (!query) return true;
    return [ticket.id, ticket.title, ticket.integration, ticket.integration_server, ticket.tenant, ticket.site, ticket.assignee, ticket.requester, ticket.source, ticket.status, ticket.workflow]
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

function setTicketSurface(surface) {
  ticketSurface = ["all", "support", "manage"].includes(surface) ? surface : "all";
  document.querySelectorAll("[data-ticket-surface]").forEach((item) => {
    const active = item.dataset.ticketSurface === ticketSurface;
    item.classList.toggle("is-active", active);
    item.setAttribute("aria-pressed", String(active));
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
    empty: "The connected work queues are currently empty.",
    no_read_surface: "The services are connected, but they do not advertise a zero-input read-only queue.",
    input_required: "A work source needs additional scope. Ask Monique to retrieve the exact queue you need.",
    unavailable: "The live work sources are temporarily unavailable.",
    degraded: "One work source is unavailable; available items are shown below.",
    not_attached: "Attach Support and Manage to load their work queues.",
  };
  return messages[health] || "No work items match this filter.";
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
  const support = tickets.filter((ticket) => ticket.integration === "support").length;
  const manage = tickets.filter((ticket) => ticket.integration === "manage").length;
  byId("ticket-source-all").textContent = count(tickets.length);
  byId("ticket-source-support").textContent = count(support);
  byId("ticket-source-manage").textContent = count(manage);
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
  byId("tickets-state").textContent = ["ready", "degraded"].includes(health)
    ? `${visible.length.toLocaleString(localeTag())} of ${tickets.length.toLocaleString(localeTag())} work items`
    : ticketEmptyMessage(health);
  const sources = operationsSnapshot?.tickets?.sources || [];
  byId("tickets-source").textContent = sources.length
    ? sources.map((source) => `${operationLabel(source.surface)}: ${operationLabel(source.health)}`).join(" · ")
    : "Waiting for live sources";
  const root = byId("ticket-list");
  root.replaceChildren();
  if (visible.length === 0) {
    const empty = document.createElement("div");
    empty.className = "integration-empty ticket-empty";
    const title = document.createElement("strong");
    title.textContent = ticketEmptyMessage(health === "ready" ? "filtered" : health);
    const action = document.createElement("button");
    action.type = "button";
    if (["ready", "degraded"].includes(health) && (ticketSurface !== "all" || ticketFilter !== "all" || ticketQuery)) {
      action.textContent = "Clear filters";
      action.addEventListener("click", () => {
        setTicketSurface("all");
        setTicketFilter("all");
        ticketQuery = "";
        byId("tickets-search").value = "";
        byId("tickets-search-clear").hidden = true;
        renderTickets();
      });
    } else {
      action.textContent = "Use recovery assistant";
      action.dataset.openChat = "Inspect the available Support and Manage capabilities and help me retrieve or review the right work queue.";
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
    [ticket.integration ? operationLabel(ticket.integration) : null, ticket.tenant, ticket.site, ticket.requester ? `By ${ticket.requester}` : null, Number.isSafeInteger(ticket.comments) ? `${ticket.comments} comments` : null]
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
    ask.dataset.openChat = `Review this ${ticket.integration || "work"} item ${ticket.id}: “${ticket.title}”. Summarize its current state and recommend the next action without conflating Support, Manage, or GitHub state.`;
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
      ["Integration", ticket.integration ? operationLabel(ticket.integration) : null],
      ["Configured server", ticket.integration_server],
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
  byId("operations-authority").textContent = ["attached", "degraded"].includes(view.health) ? "AUTHORITY BOUNDED" : "NOT ATTACHED";
  byId("operations-tools").textContent = count(view.tools_total);
  byId("operations-reads").textContent = count(view.read_only_tools);
  byId("operations-actions").textContent = count(view.approval_tools);
  byId("operations-pending").textContent = count(view.pending_actions);
  byId("operations-catalog-tag").textContent = ["attached", "degraded"].includes(view.health) ? `${count(view.tools_total)} LIVE` : "UNAVAILABLE";
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
    byId("tickets-state").textContent = "Work queues unavailable";
    toast("AI Operations could not be refreshed.", "error");
  } finally {
    [byId("operations-refresh"), byId("tickets-refresh")].forEach((button) => { button.disabled = false; });
  }
}

byId("operations-refresh").addEventListener("click", () => {
  loadOperations(true);
  loadProcesses({ announce: true });
});
byId("processes-refresh").addEventListener("click", () => loadProcesses({ announce: true }));
byId("platform-refresh").addEventListener("click", () => loadPlatform({ announce: true }));
byId("platform-history-more").addEventListener("click", () => pagePlatformHistory());
byId("platform-session-detach").addEventListener("click", () => detachPlatformSession());
byId("platform-composer").addEventListener("submit", sendPlatformFollowUp);
document.querySelectorAll("[data-cockpit-attention]").forEach((button) => button.addEventListener("click", () => {
  cockpitState = globalThis.AutomoniquePlatformCockpit.reduce(cockpitState, { type: "filter_attention", attention: button.dataset.cockpitAttention });
  document.querySelectorAll("[data-cockpit-attention]").forEach((item) => {
    item.classList.toggle("is-active", item === button);
    item.setAttribute("aria-pressed", String(item === button));
  });
  renderHostedCockpit(cockpitSnapshot || {});
}));
byId("cockpit-workspace-list").addEventListener("keydown", (event) => {
  if (!["ArrowUp", "ArrowDown", "Home", "End"].includes(event.key)) return;
  const options = [...byId("cockpit-workspace-list").querySelectorAll(".cockpit-workspace-option:not(:disabled)")];
  if (options.length === 0) return;
  const current = options.indexOf(event.target);
  event.preventDefault();
  const next = event.key === "Home" ? 0
    : event.key === "End" ? options.length - 1
      : (Math.max(current, 0) + (event.key === "ArrowDown" ? 1 : -1) + options.length) % options.length;
  options[next].focus();
});
document.querySelectorAll("[data-cockpit-surface]").forEach((button) => button.addEventListener("click", () => {
  cockpitState = globalThis.AutomoniquePlatformCockpit.reduce(cockpitState, { type: "show_surface", surface: button.dataset.cockpitSurface });
  document.querySelectorAll("[data-cockpit-surface]").forEach((item) => {
    const active = item.dataset.cockpitSurface === cockpitState.surface;
    item.classList.toggle("is-active", active);
    item.setAttribute("aria-selected", String(active));
    item.tabIndex = active ? 0 : -1;
    const panel = byId(item.getAttribute("aria-controls"));
    panel.hidden = !active;
    panel.classList.toggle("is-active", active);
  });
}));
document.querySelector(".cockpit-surface-tabs").addEventListener("keydown", (event) => {
  if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
  const tabs = [...document.querySelectorAll("[data-cockpit-surface]")];
  const current = tabs.indexOf(event.target);
  if (current < 0) return;
  event.preventDefault();
  const next = event.key === "Home" ? 0
    : event.key === "End" ? tabs.length - 1
      : (current + (event.key === "ArrowRight" ? 1 : -1) + tabs.length) % tabs.length;
  tabs[next].click();
  tabs[next].focus();
});
function previewCockpitAction(action) {
  const capability = cockpitPresentation?.[action];
  if (!capability?.available || cockpitControlHandle || cockpitControlBusy) return;
  const baseSelector = byId("cockpit-base-selector").value.trim();
  const branchSelector = byId("cockpit-branch-selector").value.trim();
  if (action === "create" && (!baseSelector || !branchSelector)) {
    toast("Exact base and branch selectors are required before preview.", "error");
    return;
  }
  const preview = Object.freeze({
    action,
    project_id: capability.project_id,
    workspace_id: capability.workspace_id,
    exact_revision: capability.exact_revision,
    task_id: capability.task_id,
    external_work: capability.external_work,
    base_selector: action === "create" ? baseSelector : null,
    branch_selector: action === "create" ? branchSelector : null,
  });
  cockpitState = globalThis.AutomoniquePlatformCockpit.reduce(cockpitState, { type: "preview", action, capability });
  const root = byId("cockpit-action-preview");
  root.hidden = false;
  root.replaceChildren();
  const title = document.createElement("strong");
  title.textContent = `${words(action)} preview · no mutation sent`;
  const details = document.createElement("span");
  details.textContent = `${preview.project_id} · ${preview.workspace_id} · exact revision ${preview.exact_revision}`;
  const task = document.createElement("p");
  task.textContent = `Bound task ${preview.task_id || "unavailable"}. The durable intent identity will be stored before transmission.`;
  const external = document.createElement("p");
  external.textContent = action === "create"
    ? `External work ${preview.external_work.provider} · ${preview.external_work.authority} · ${preview.external_work.scope} · ${preview.external_work.key}`
    : "No external-work identity is added by resume.";
  const selectors = document.createElement("p");
  selectors.textContent = action === "create"
    ? `Exact base ${preview.base_selector} · exact branch ${preview.branch_selector}`
    : `Exact existing workspace ${preview.workspace_id}`;
  const confirm = document.createElement("button");
  confirm.type = "button";
  confirm.className = "button primary";
  confirm.textContent = `Confirm ${action}`;
  confirm.addEventListener("click", () => submitCockpitIntent(preview));
  root.append(title, details, task, external, selectors, confirm);
}

function newCockpitReceiptId(prefix) {
  return `${prefix}-${crypto.randomUUID()}`;
}

function persistCockpitControl(handle) {
  const serialized = globalThis.AutomoniquePlatformCockpit.serializeControlHandle(handle);
  if (!serialized) return false;
  try {
    localStorage.setItem(cockpitControlStorageKey, serialized);
    cockpitControlHandle = handle;
    return true;
  } catch (_error) {
    return false;
  }
}

function clearCockpitControl() {
  try {
    localStorage.removeItem(cockpitControlStorageKey);
  } catch (_error) {
    // The in-memory handle still settles; storage was already unavailable.
  }
  cockpitControlHandle = null;
}

function cockpitReceiptState(response, handle) {
  if (response?.state === "refused") {
    return { state: "refused", id: handle.receipt_id, outcome: response.category, message: response.explanation || response.category };
  }
  if (response?.state === "missing") {
    return { state: "ambiguous", id: handle.receipt_id, outcome: "unknown", message: "No durable receipt is visible yet. Lookup remains safe; the write will not be replayed." };
  }
  if (handle.family === "workspace_intent" && response?.state === "receipt") {
    const kind = response?.outcome?.kind;
    if (["accepted", "unknown"].includes(kind)) {
      return { state: "pending", id: handle.receipt_id, outcome: kind, message: "Workspace intent is durable and still requires receipt lookup." };
    }
    return { state: "completed", id: handle.receipt_id, outcome: kind, message: `Workspace intent settled as ${kind || "unknown"}.` };
  }
  if (handle.family === "review_action" && response?.state === "receipt") {
    const directive = globalThis.AutomoniquePlatformCockpit.receiptDirective(response);
    if (directive === "reconcile") return { state: "pending", id: handle.receipt_id, outcome: response?.receipt?.outcome, message: "Review action is durable and still requires receipt lookup." };
    return { state: response?.receipt?.outcome === "completed" ? "completed" : "refused", id: handle.receipt_id, outcome: response?.receipt?.outcome, message: `Review action settled as ${response?.receipt?.outcome || "unknown"}.` };
  }
  return { state: "ambiguous", id: handle.receipt_id, outcome: "unknown", message: "The response was not a recognized durable receipt. Lookup remains safe." };
}

function applyCockpitControlResponse(response, handle) {
  const receipt = cockpitReceiptState(response, handle);
  cockpitState = globalThis.AutomoniquePlatformCockpit.reduce(cockpitState, { type: "receipt", receipt });
  if (["completed", "refused"].includes(receipt.state)) clearCockpitControl();
  renderHostedCockpit(cockpitSnapshot || {});
}

async function submitCockpitIntent(preview) {
  if (!preview || cockpitControlHandle || cockpitControlBusy) return;
  const action = preview.action;
  const intentId = newCockpitReceiptId("cockpit-intent");
  const handle = globalThis.AutomoniquePlatformCockpit.prepareControlHandle({
    available: true,
    family: "workspace_intent",
    project_id: preview.project_id,
    workspace_id: preview.workspace_id,
  }, action, intentId);
  if (!handle || !persistCockpitControl(handle)) {
    toast("The durable intent identity could not be stored; nothing was sent.", "error");
    return;
  }
  cockpitControlBusy = true;
  renderHostedCockpit(cockpitSnapshot || {});
  const body = action === "create" ? {
    action: "submit_workspace_create",
    project_id: preview.project_id,
    workspace_id: preview.workspace_id,
    expected_revision: preview.exact_revision,
    intent_id: intentId,
    task_id: preview.task_id,
    external_work: preview.external_work,
    base_selector: preview.base_selector,
    branch_selector: preview.branch_selector,
  } : {
    action: "submit_workspace_resume",
    project_id: preview.project_id,
    workspace_id: preview.workspace_id,
    expected_revision: preview.exact_revision,
    intent_id: intentId,
    task_id: preview.task_id,
  };
  try {
    applyCockpitControlResponse(await api("/api/platform/cockpit", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }), handle);
  } catch (_error) {
    cockpitState = globalThis.AutomoniquePlatformCockpit.reduce(cockpitState, { type: "receipt", receipt: {
      state: "ambiguous", id: intentId, outcome: "unknown", message: "Transmission was ambiguous. Only receipt lookup is allowed now.",
    } });
  } finally {
    cockpitControlBusy = false;
    renderHostedCockpit(cockpitSnapshot || {});
  }
}

async function submitCockpitReview(action) {
  const capability = cockpitPresentation?.reviewActions?.[action];
  if (!capability?.available || cockpitControlHandle || cockpitControlBusy) return;
  const idempotencyKey = newCockpitReceiptId("cockpit-review");
  const handle = globalThis.AutomoniquePlatformCockpit.prepareControlHandle(capability, action, idempotencyKey);
  if (!handle || !persistCockpitControl(handle)) {
    toast("The durable review receipt identity could not be stored; nothing was sent.", "error");
    return;
  }
  const link = globalThis.AutomoniquePlatformCockpit.parseDeepLink(window.location.hash);
  const body = action === "addComment" ? {
    action: "add_comment",
    project_id: capability.project_id,
    workspace_id: capability.workspace_id,
    expected_revision: capability.exact_revision,
    comment_id: newCockpitReceiptId("cockpit-comment"),
    file_id: link.file,
    hunk_id: link.hunk,
    side: link.side,
    line: Number(link.line),
    body: byId("cockpit-review-comment").value.trim(),
    idempotency_key: idempotencyKey,
  } : {
    action: "approve_review",
    project_id: capability.project_id,
    workspace_id: capability.workspace_id,
    expected_revision: capability.exact_revision,
    expected_review_revision: capability.exact_review_revision,
    idempotency_key: idempotencyKey,
  };
  if (action === "addComment" && !body.body) {
    clearCockpitControl();
    toast("A bounded comment body is required.", "error");
    return;
  }
  cockpitControlBusy = true;
  renderHostedCockpit(cockpitSnapshot || {});
  try {
    applyCockpitControlResponse(await api("/api/platform/cockpit", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }), handle);
  } catch (_error) {
    cockpitState = globalThis.AutomoniquePlatformCockpit.reduce(cockpitState, { type: "receipt", receipt: {
      state: "ambiguous", id: idempotencyKey, outcome: "unknown", message: "Transmission was ambiguous. Only receipt lookup is allowed now.",
    } });
  } finally {
    cockpitControlBusy = false;
    renderHostedCockpit(cockpitSnapshot || {});
  }
}

async function reconcileCockpitControl() {
  const handle = cockpitControlHandle;
  if (!handle || cockpitControlBusy) return;
  cockpitControlBusy = true;
  try {
    const body = handle.family === "workspace_intent" ? {
      action: "get_workspace_intent",
      project_id: handle.project_id,
      workspace_id: handle.workspace_id,
      intent_id: handle.receipt_id,
    } : {
      action: "get_review_receipt",
      project_id: handle.project_id,
      workspace_id: handle.workspace_id,
      idempotency_key: handle.receipt_id,
    };
    applyCockpitControlResponse(await api("/api/platform/cockpit", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }), handle);
  } catch (_error) {
    cockpitState = globalThis.AutomoniquePlatformCockpit.reduce(cockpitState, { type: "receipt", receipt: {
      state: "ambiguous", id: handle.receipt_id, outcome: "unknown", message: "Receipt lookup is unavailable. The write will not be replayed.",
    } });
  } finally {
    cockpitControlBusy = false;
    renderHostedCockpit(cockpitSnapshot || {});
  }
}
byId("cockpit-create-preview").addEventListener("click", () => previewCockpitAction("create"));
byId("cockpit-resume-preview").addEventListener("click", () => previewCockpitAction("resume"));
byId("cockpit-review-controls").addEventListener("submit", (event) => {
  event.preventDefault();
  submitCockpitReview("addComment");
});
byId("cockpit-approve-review").addEventListener("click", () => submitCockpitReview("approveReview"));
byId("cockpit-copy-link").addEventListener("click", async () => {
  const workspace = cockpitPresentation?.selectedWorkspace;
  if (!workspace) return;
  const current = globalThis.AutomoniquePlatformCockpit.parseDeepLink(window.location.hash);
  const link = `${window.location.origin}${window.location.pathname}${globalThis.AutomoniquePlatformCockpit.buildDeepLink({
    ...(current.workspace === workspace.id ? current : {}),
    view: "sessions",
    workspace: workspace.id,
    session: current.session || workspace.session_id || platformSelectedSession,
  })}`;
  try {
    await navigator.clipboard.writeText(link);
    toast("Exact workspace link copied.");
  } catch (_error) {
    toast("The browser did not allow clipboard access.", "error");
  }
});
byId("attention-toggle").addEventListener("click", () => {
  const button = byId("attention-toggle");
  const expanded = button.getAttribute("aria-expanded") === "true";
  button.setAttribute("aria-expanded", String(!expanded));
  button.textContent = expanded ? "Details" : "Hide details";
  byId("attention-list").hidden = expanded;
});
document.querySelectorAll("[data-process-filter]").forEach((button) => button.addEventListener("click", () => {
  setProcessFilter(button.dataset.processFilter);
  if (processesSnapshot) renderProcesses(processesSnapshot);
}));
byId("tickets-refresh").addEventListener("click", () => loadOperations(true));
document.querySelectorAll("[data-ticket-surface]").forEach((button) => button.addEventListener("click", () => {
  setTicketSurface(button.dataset.ticketSurface);
  renderTickets();
}));
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
  "Agent authentication": { category: "ai security", description: "Verified execution access for connected agent surfaces." },
  Providers: { category: "ai", description: "Contained model execution and provider readiness." },
  Connectors: { category: "integrations", description: "Channels and external service connections." },
  "Manage AI Operations": { category: "integrations ai", description: "Live tools, tickets and approval-aware control plane." },
  "Governance & safety": { category: "security", description: "Approval, audit, backup and observation controls." },
  "Extensions & automation": { category: "ai integrations", description: "MCP, knowledge, skills and automation surfaces." },
});

function configurePrompt(title) {
  return `Review the ${title} configuration. Explain its current effective state, identify anything missing, and stage any safe change for my explicit approval.`;
}

function authenticationLabel(status) {
  const labels = {
    authenticated: "Authenticated",
    configured_unverified: "Configured Unverified",
    authenticating: "Authenticating",
    awaiting_user: "Awaiting Sign-in",
    verifying: "Verifying",
    expired: "Expired",
    signed_out: "Signed Out",
    unavailable: "Unavailable",
    not_configured: "Not Configured",
    failed: "Failed",
    cancelled: "Cancelled",
  };
  return labels[status] || "Unavailable";
}

function configurationValue(key, value) {
  if (typeof value === "boolean") return value ? "CONFIGURED" : "OFF";
  if (value === null || value === undefined) return "—";
  if (key.endsWith("_at_ms") && Number.isSafeInteger(value) && value > 0) {
    return new Intl.DateTimeFormat(localeTag(), { dateStyle: "medium", timeStyle: "short" }).format(value);
  }
  if (key === "status") return authenticationLabel(value);
  if (key === "method") {
    return { chatgpt: "ChatGPT", claude_ai: "Claude.ai", native_subscription: "Native subscription", api_key: "API key", access_token: "Access token", unknown: "Unknown" }[value] || "Unknown";
  }
  if (key === "evidence") return label(value);
  return String(value);
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
  if (title === "Agent authentication") {
    state.textContent = authenticationLabel(values.status);
    state.dataset.state = values.status || "unavailable";
  } else {
    state.textContent = configuredValues.length === 0 || configuredValues.some(Boolean) ? "ACTIVE" : "OFF";
  }
  headingWrap.append(headingText, state);
  const list = document.createElement("dl");
  list.className = "config-list";
  Object.entries(values || {}).forEach(([key, value]) => {
    const row = document.createElement("div");
    if (/(seconds|bytes|count|depth|limit)/.test(key)) row.dataset.configTechnical = "true";
    const term = document.createElement("dt");
    term.textContent = label(key);
    const detail = document.createElement("dd");
    detail.textContent = configurationValue(key, value);
    if (typeof value === "boolean") detail.className = value ? "boolean-true" : "boolean-false";
    if (title === "Agent authentication" && key === "status") {
      detail.className = value === "authenticated" ? "auth-good" : value === "configured_unverified" ? "auth-warning" : "auth-danger";
    }
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
  card.dataset.configSearch = `${title} ${metadata.description} ${Object.keys(values || {}).join(" ")} ${Object.values(values || {}).join(" ")}`.toLowerCase();
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
  const authStatus = config.agent_authentication?.status || "unavailable";
  byId("configuration-auth-summary").dataset.state = authStatus;
  byId("configuration-auth-state").textContent = authenticationLabel(authStatus);
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

function safeAgentAuthorizationUrl(session) {
  if (typeof session?.authorization_url !== "string") return null;
  try {
    const url = new URL(session.authorization_url);
    if (url.protocol !== "https:" || url.username || url.password) return null;
    if (session.provider === "codex" && url.hostname === "auth.openai.com" && url.pathname === "/codex/device" && !url.search) return url.href;
    if (session.provider === "claude" && url.hostname === "claude.com" && url.pathname === "/cai/oauth/authorize" && url.search) return url.href;
  } catch (_error) {
    return null;
  }
  return null;
}

function agentProviderName(provider) {
  return provider === "claude" ? "Claude Code" : "Codex CLI";
}

function agentAccountButton(text, action, disabled = false) {
  const button = document.createElement("button");
  button.type = "button";
  button.textContent = translatePhrase(text);
  button.disabled = disabled;
  button.addEventListener("click", action);
  return button;
}

async function mutateAgentAccounts(payload, successMessage) {
  try {
    const view = await api("/api/agent-accounts/action", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    renderAgentAccounts(view);
    if (successMessage) toast(successMessage);
    byId("configuration-grid").dataset.loaded = "false";
    return view;
  } catch (error) {
    const messages = {
      account_not_authenticated: "Complete native sign-in before selecting this account.",
      selected_account_cannot_be_removed: "Select another worker account before removing this one.",
      confirmation_required: "Confirmation is required for this account change.",
      native_login_unavailable: "Native provider sign-in could not be started.",
      account_limit_reached: "The local native-account limit has been reached.",
    };
    toast(messages[error.message] || `Agent account action failed (${error.message}).`, "error");
    return null;
  }
}

async function startAgentLogin(provider, account = null) {
  const proposed = account?.label || `${agentProviderName(provider)} ${new Date().toLocaleDateString(localeTag(), { month: "short", day: "numeric" })}`;
  const alias = window.prompt(translatePhrase("Choose a local alias for this subscription account."), proposed);
  if (alias === null || !alias.trim()) return;
  await mutateAgentAccounts({ action: "start_login", provider, label: alias.trim(), account_id: account?.id || null }, "Native sign-in started.");
  scheduleAgentAccountsPoll(true);
}

function renderAgentLoginSession(session) {
  const card = document.createElement("div");
  card.className = "agent-login-card";
  const head = document.createElement("div");
  head.className = "agent-account-head";
  const identity = document.createElement("div");
  identity.className = "agent-account-identity";
  const title = document.createElement("strong");
  title.textContent = `${agentProviderName(session.provider)} · ${translatePhrase("Native sign-in")}`;
  const detail = document.createElement("small");
  detail.textContent = session.status === "authenticated" ? translatePhrase("Subscription account authenticated.") : session.status === "failed" || session.status === "cancelled" ? translatePhrase("Sign-in did not complete.") : translatePhrase("Complete sign-in with the provider, then return here.");
  identity.append(title, detail);
  const status = document.createElement("span");
  status.className = "agent-account-status";
  status.dataset.state = session.status;
  status.textContent = authenticationLabel(session.status);
  head.append(identity, status);
  const instructions = document.createElement("div");
  instructions.className = "agent-login-instructions";
  const authorizationUrl = safeAgentAuthorizationUrl(session);
  if (authorizationUrl) {
    const link = document.createElement("a");
    link.className = "agent-login-link";
    link.href = authorizationUrl;
    link.target = "_blank";
    link.rel = "noopener noreferrer";
    link.textContent = translatePhrase(session.provider === "claude" ? "Continue with Claude.ai ↗" : "Continue with ChatGPT ↗");
    instructions.append(link);
  }
  if (typeof session.user_code === "string") {
    const code = document.createElement("code");
    code.className = "agent-login-code";
    code.dataset.i18nSkip = "";
    code.textContent = session.user_code;
    instructions.append(code);
  }
  if (session.accepts_authorization_code === true) {
    const codeInput = document.createElement("input");
    codeInput.className = "agent-authorization-input";
    codeInput.type = "text";
    codeInput.autocomplete = "off";
    codeInput.spellcheck = false;
    codeInput.maxLength = 4096;
    codeInput.placeholder = translatePhrase("Paste authorization code if Claude asks for it");
    const submit = agentAccountButton("Submit authorization code", async () => {
      const code = codeInput.value.trim();
      if (!code) return;
      submit.disabled = true;
      const view = await mutateAgentAccounts({ action: "submit_authorization_code", session_id: session.id, code }, "Authorization code submitted.");
      codeInput.value = "";
      if (!view) submit.disabled = false;
    });
    instructions.append(codeInput, submit);
  }
  if (!["authenticated", "failed", "cancelled"].includes(session.status)) {
    instructions.append(agentAccountButton("Cancel", () => mutateAgentAccounts({ action: "cancel_login", session_id: session.id }, "Native sign-in cancelled.")));
  }
  card.append(head);
  if (instructions.childNodes.length) card.append(instructions);
  return card;
}

function renderAgentAccount(account) {
  const card = document.createElement("div");
  card.className = "agent-account-card";
  const head = document.createElement("div");
  head.className = "agent-account-head";
  const identity = document.createElement("div");
  identity.className = "agent-account-identity";
  const labelNode = document.createElement("strong");
  labelNode.dataset.i18nSkip = "";
  labelNode.textContent = account.label;
  const provider = document.createElement("small");
  provider.textContent = `${account.provider_name} · ${account.method === "claude_ai" ? "Claude.ai" : "ChatGPT"}${account.worker_selected ? ` · ${translatePhrase("ACTIVE WORKER")}` : ""}`;
  identity.append(labelNode, provider);
  const status = document.createElement("span");
  status.className = "agent-account-status";
  status.dataset.state = account.status;
  status.textContent = authenticationLabel(account.status);
  head.append(identity, status);
  const meta = document.createElement("div");
  meta.className = "agent-account-meta";
  meta.textContent = `${translatePhrase("Evidence")}: ${label(account.evidence)}${account.last_verified_at_ms ? ` · ${new Intl.DateTimeFormat(localeTag(), { dateStyle: "medium", timeStyle: "short" }).format(account.last_verified_at_ms)}` : ""}`;
  const actions = document.createElement("div");
  actions.className = "agent-account-buttons";
  actions.append(
    agentAccountButton("Use for worker", () => mutateAgentAccounts({ action: "select", account_id: account.id }, "Worker account selected."), account.worker_selected || !["authenticated", "configured_unverified"].includes(account.status)),
    agentAccountButton("Verify", () => mutateAgentAccounts({ action: "refresh", account_id: account.id }, "Account status refreshed.")),
    agentAccountButton("Sign in again", () => startAgentLogin(account.provider, account)),
    agentAccountButton("Sign out", () => {
      if (window.confirm(translatePhrase("Sign out this native subscription account?"))) mutateAgentAccounts({ action: "logout", account_id: account.id, confirm: true }, "Account signed out.");
    }),
    agentAccountButton("Remove", () => {
      if (window.confirm(translatePhrase("Remove this local account profile and its native credentials?"))) mutateAgentAccounts({ action: "remove", account_id: account.id, confirm: true }, "Account removed.");
    }, account.worker_selected),
  );
  card.append(head, meta, actions);
  return card;
}

function renderAgentAccounts(view) {
  const sessionsRoot = byId("agent-login-sessions");
  const accountsRoot = byId("agent-account-list");
  sessionsRoot.replaceChildren(...(view.login_sessions || []).map(renderAgentLoginSession));
  const accounts = Array.isArray(view.accounts) ? view.accounts : [];
  const providers = Array.isArray(view.providers) ? view.providers : [];
  const maximum = Number.isSafeInteger(view.max_accounts) && view.max_accounts > 0 ? view.max_accounts : null;
  const atCapacity = maximum !== null && accounts.length >= maximum;
  const capacity = byId("agent-account-capacity");
  if (capacity) capacity.textContent = maximum === null ? `${accounts.length} accounts` : `${accounts.length} / ${maximum} accounts`;
  document.querySelectorAll("[data-add-agent-provider]").forEach((button) => {
    const provider = providers.find((item) => item?.id === button.dataset.addAgentProvider);
    button.disabled = atCapacity || provider?.available !== true;
  });
  if (accounts.length) {
    accountsRoot.replaceChildren(...accounts.map(renderAgentAccount));
  } else {
    const empty = document.createElement("div");
    empty.className = "agent-account-empty";
    empty.textContent = translatePhrase("No native subscription account is configured yet.");
    accountsRoot.replaceChildren(empty);
  }
  const activeLogin = (view.login_sessions || []).some((session) => !["authenticated", "failed", "cancelled"].includes(session.status));
  if (activeLogin) scheduleAgentAccountsPoll();
}

function scheduleAgentAccountsPoll(immediate = false) {
  if (agentAccountsPollTimer !== null) window.clearTimeout(agentAccountsPollTimer);
  agentAccountsPollTimer = window.setTimeout(() => loadAgentAccounts(true), immediate ? 100 : 2000);
}

async function loadAgentAccounts(polling = false) {
  try {
    const view = await api("/api/agent-accounts");
    renderAgentAccounts(view);
  } catch (error) {
    if (!polling) {
      const empty = document.createElement("div");
      empty.className = "agent-account-empty";
      empty.textContent = translatePhrase("Native account management is unavailable.");
      byId("agent-account-list").replaceChildren(empty);
    }
  }
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
    delete core.agent_authentication;
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
      renderConfigSection("Agent authentication", config.agent_authentication),
      renderConfigSection("Providers", config.providers),
      renderConfigSection("Connectors", config.connectors),
      renderConfigSection("Manage AI Operations", manage),
      renderConfigSection("Governance & safety", config.governance),
      renderConfigSection("Extensions & automation", config.extensions),
    );
    updateConfigurationSummary(config);
    await loadAgentAccounts();
    applyConfigurationFilter();
    root.dataset.loaded = "true";
    if (force) toast("Runtime configuration refreshed.");
  } catch (error) {
    root.replaceChildren(renderConfigSection("Configuration unavailable", { category: error.message }));
    toast("Configuration projection is unavailable.", "error");
  }
}

byId("configuration-refresh").addEventListener("click", () => loadConfiguration(true));
document.querySelectorAll("[data-add-agent-provider]").forEach((button) => button.addEventListener("click", () => startAgentLogin(button.dataset.addAgentProvider)));

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
    const sources = details.sources || [];
    if (sources.length > 0) {
      const sourceList = document.createElement("div");
      sourceList.className = "message-sources";
      sourceList.setAttribute("role", "list");
      sourceList.setAttribute("aria-label", "Live sources");
      const sourceLabel = document.createElement("span");
      sourceLabel.className = "source-group-label";
      sourceLabel.textContent = "LIVE";
      sourceLabel.setAttribute("aria-hidden", "true");
      sourceList.append(sourceLabel);
      sources.forEach((source) => {
        const sourceName = words(source);
        const chip = document.createElement("span");
        chip.className = "source-chip";
        chip.setAttribute("role", "listitem");
        chip.setAttribute("aria-label", `Live source · ${sourceName}`);
        chip.title = sourceName;
        const name = document.createElement("span");
        name.className = "source-chip-name";
        name.textContent = sourceName;
        chip.append(name);
        sourceList.append(chip);
      });
      tools.append(sourceList);
    }
    const actions = document.createElement("div");
    actions.className = "message-actions";
    if (voiceOutputSupported) {
      const speak = document.createElement("button");
      speak.type = "button";
      speak.className = "speak-message";
      speak.textContent = "LISTEN";
      speak.setAttribute("aria-label", "Read reply aloud");
      speak.addEventListener("click", () => {
        if (activeSpeechButton === speak) stopSpeaking();
        else speakText(markdown.innerText || markdown.textContent, speak);
      });
      actions.append(speak);
    }
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
    actions.append(copy);
    tools.append(actions);
    body.append(tools);
  }
  if (role === "user") item.append(body, avatar); else item.append(avatar, body);
  byId("chat-thread").append(item);
  item.scrollIntoView({ block: "end" });
  if (role !== "user" && details.speak && voiceRepliesEnabled) {
    window.setTimeout(() => speakText(markdown.innerText || markdown.textContent), 0);
  }
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
    appendMessage("assistant", answer.answer, Date.now(), { sources, durationMs: answer.duration_ms, action: answer.action, speak: true });
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
    permission_request_not_pending: "That permission request is no longer pending. Nothing was run.",
    permission_request_expired: "That permission request expired. Ask Monique to prepare it again.",
    permission_request_capacity: "Too many permission requests are awaiting decisions. Resolve one and try again.",
    permission_request_unavailable: "Monique could not retain the permission request safely. Nothing further was run.",
    shared_assistant_unavailable: "Monique’s shared approval lane is temporarily unavailable. Nothing further was run.",
  };
  return messages[category] || `The contained conversation lane refused this turn (${category}).`;
}

function setVoiceInputButton(listening) {
  voiceListening = listening;
  const button = byId("voice-input");
  if (!button) return;
  button.setAttribute("aria-pressed", String(listening));
  button.setAttribute("aria-label", listening ? "Stop voice input" : "Start voice input");
  button.title = listening ? "Stop voice input" : "Start voice input";
  button.textContent = listening ? "STOP" : "MIC";
}

function updateVoiceOutputButton() {
  const button = byId("voice-output");
  if (!button) return;
  button.disabled = !voiceOutputSupported;
  if (!voiceOutputSupported) {
    button.setAttribute("aria-pressed", "false");
    button.setAttribute("aria-label", "Voice replies are unavailable in this browser");
    button.title = "Voice replies are unavailable in this browser";
    button.textContent = "VOICE N/A";
    return;
  }
  button.setAttribute("aria-pressed", String(voiceRepliesEnabled));
  button.setAttribute("aria-label", voiceRepliesEnabled ? "Turn off spoken replies" : "Turn on spoken replies");
  button.title = voiceRepliesEnabled ? "Voice replies are on" : "Voice replies are off";
  button.textContent = voiceRepliesEnabled ? "VOICE ON" : "VOICE OFF";
}

function resetSpeakButton(button) {
  if (!button) return;
  button.classList.remove("is-speaking");
  button.textContent = "LISTEN";
  button.setAttribute("aria-label", "Read reply aloud");
}

function stopSpeaking() {
  const button = activeSpeechButton;
  const status = activeSpeechStatus;
  const wasSpeaking = activeSpeechUtterance !== null;
  activeSpeechButton = null;
  activeSpeechUtterance = null;
  activeSpeechStatus = null;
  if (voiceOutputSupported) window.speechSynthesis.cancel();
  resetSpeakButton(button);
  if (wasSpeaking && byId("chat-state")) byId("chat-state").textContent = status || "Ready";
}

function speakText(text, button = null) {
  const spokenText = String(text || "").trim();
  if (!voiceOutputSupported || !spokenText) return;
  stopSpeaking();
  const utterance = new window.SpeechSynthesisUtterance(spokenText);
  utterance.lang = localeTag();
  const language = utterance.lang.toLowerCase();
  const voice = window.speechSynthesis.getVoices().find((candidate) => candidate.lang.toLowerCase() === language)
    || window.speechSynthesis.getVoices().find((candidate) => candidate.lang.toLowerCase().startsWith(language.slice(0, 2)));
  if (voice) utterance.voice = voice;
  activeSpeechButton = button;
  activeSpeechUtterance = utterance;
  activeSpeechStatus = byId("chat-state").textContent;
  if (button) {
    button.classList.add("is-speaking");
    button.textContent = "STOP";
    button.setAttribute("aria-label", "Stop reading reply");
  }
  utterance.onstart = () => {
    if (activeSpeechUtterance === utterance) byId("chat-state").textContent = "Speaking…";
  };
  const finish = () => {
    if (activeSpeechUtterance !== utterance) return;
    const finishedButton = activeSpeechButton;
    const finishedStatus = activeSpeechStatus;
    activeSpeechButton = null;
    activeSpeechUtterance = null;
    activeSpeechStatus = null;
    resetSpeakButton(finishedButton);
    byId("chat-state").textContent = finishedStatus || "Ready";
  };
  utterance.onend = finish;
  utterance.onerror = finish;
  window.speechSynthesis.speak(utterance);
}

function renderVoiceTranscript(interim = "") {
  const input = byId("chat-input");
  const value = [voiceDraft.trim(), voiceTranscript.trim(), String(interim).trim()].filter(Boolean).join(" ");
  input.value = value.slice(0, Number(input.maxLength) || 8192);
  input.dispatchEvent(new Event("input", { bubbles: true }));
}

function voiceInputError(error) {
  const messages = {
    "not-allowed": "Voice input needs microphone permission.",
    "service-not-allowed": "Voice input needs microphone permission.",
    "audio-capture": "No microphone was found.",
    "no-speech": "I did not hear anything. Try again.",
    network: "Voice recognition is temporarily unavailable.",
  };
  return messages[error] || "Voice recognition is temporarily unavailable.";
}

function stopVoiceInput() {
  voiceShouldListen = false;
  if (voiceRecognition && voiceListening) voiceRecognition.stop();
  setVoiceInputButton(false);
}

function startVoiceInput() {
  if (!voiceInputSupported || !voiceRecognition || chatBusy) return;
  stopSpeaking();
  voiceDraft = byId("chat-input").value;
  voiceTranscript = "";
  voiceShouldListen = true;
  voiceRecognition.lang = localeTag();
  setVoiceInputButton(true);
  byId("chat-state").textContent = "Listening… tap MIC to stop";
  try {
    voiceRecognition.start();
  } catch (_error) {
    voiceShouldListen = false;
    setVoiceInputButton(false);
    byId("chat-state").textContent = "Voice recognition is temporarily unavailable.";
  }
}

function initializeVoiceSupport() {
  const inputButton = byId("voice-input");
  updateVoiceOutputButton();
  if (!voiceInputSupported) {
    inputButton.disabled = true;
    inputButton.setAttribute("aria-label", "Voice input is unavailable in this browser");
    inputButton.title = "Voice input is unavailable in this browser";
  } else {
    voiceRecognition = new BrowserSpeechRecognition();
    voiceRecognition.continuous = true;
    voiceRecognition.interimResults = true;
    voiceRecognition.maxAlternatives = 1;
    voiceRecognition.lang = localeTag();
    voiceRecognition.onstart = () => {
      setVoiceInputButton(true);
      byId("chat-state").textContent = "Listening… tap MIC to stop";
    };
    voiceRecognition.onresult = (event) => {
      if (!voiceShouldListen) return;
      let interim = "";
      for (let index = event.resultIndex; index < event.results.length; index += 1) {
        const transcript = event.results[index][0]?.transcript || "";
        if (event.results[index].isFinal) voiceTranscript = `${voiceTranscript} ${transcript}`.trim();
        else interim += transcript;
      }
      renderVoiceTranscript(interim);
    };
    voiceRecognition.onerror = (event) => {
      if (event.error === "aborted") return;
      voiceShouldListen = false;
      const message = voiceInputError(event.error);
      byId("chat-state").textContent = message;
      toast(message, "error");
    };
    voiceRecognition.onend = () => {
      voiceShouldListen = false;
      setVoiceInputButton(false);
      if (byId("chat-state").textContent === translatePhrase("Listening… tap MIC to stop")) {
        byId("chat-state").textContent = byId("chat-input").value.trim() ? "Voice input ready" : "Ready";
      }
    };
  }
  inputButton.addEventListener("click", () => {
    if (voiceListening) stopVoiceInput();
    else startVoiceInput();
  });
  byId("voice-output").addEventListener("click", () => {
    if (!voiceOutputSupported) return;
    voiceRepliesEnabled = !voiceRepliesEnabled;
    savePreference("monique-voice-replies", voiceRepliesEnabled ? "on" : "off");
    if (!voiceRepliesEnabled) stopSpeaking();
    updateVoiceOutputButton();
    localizeUi(byId("voice-output"));
  });
}

byId("chat-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (chatBusy) return;
  stopVoiceInput();
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
    appendMessage("assistant", answer.answer, Date.now(), { sources, durationMs: answer.duration_ms, action: answer.action, speak: true });
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
initializeVoiceSupport();

function resetNewChatButton() {
  window.clearTimeout(newChatTimer);
  newChatArmed = false;
  byId("new-chat").textContent = "New conversation";
  byId("new-chat").removeAttribute("data-armed");
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

byId("sidebar-sessions").addEventListener("click", () => showView("sessions"));

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
  if (event.target.closest("[data-open-sessions]")) showView("sessions");
});

document.addEventListener("keydown", (event) => {
  const editing = event.target.matches("input, textarea, select, [contenteditable='true']");
  if (event.key === "Escape" && voiceListening) {
    stopVoiceInput();
  } else if (event.key === "Escape" && activeSpeechUtterance) {
    stopSpeaking();
  } else if (!editing && event.key === "/") {
    event.preventDefault();
    showView("chat");
    byId("chat-input").focus();
  } else if (!editing && document.querySelector('[data-panel="sessions"]')?.classList.contains("is-visible") && event.key.toLowerCase() === "w") {
    event.preventDefault();
    byId("cockpit-workspace-navigation").focus();
  } else if (!editing && document.querySelector('[data-panel="sessions"]')?.classList.contains("is-visible") && event.key.toLowerCase() === "c") {
    event.preventDefault();
    document.querySelector('[data-cockpit-surface="conversation"]').click();
    byId("platform-session-empty").focus({ preventScroll: false });
  } else if (!editing && document.querySelector('[data-panel="sessions"]')?.classList.contains("is-visible") && event.key.toLowerCase() === "a") {
    event.preventDefault();
    document.querySelector('[data-cockpit-surface="activity"]').click();
    byId("cockpit-activity").focus({ preventScroll: false });
  } else if (!editing && event.key.toLowerCase() === "r") {
    event.preventDefault();
    refreshStatus({ announce: true });
  } else if (!editing && event.key.toLowerCase() === "n") {
    event.preventDefault();
    showView("sessions");
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

platformMutation = readPlatformMutation();
try { platformSelectedSession = sessionStorage.getItem("monique-platform-session"); } catch (_error) { platformSelectedSession = null; }
if (platformMutation) platformSelectedSession = platformMutation.sessionId;
refreshStatus();
loadConfiguration();
showView(window.location.hash || storedPreference("monique-start-view", startupViews, "sessions"));
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
window.setInterval(() => {
  if (document.hidden) return;
  if (document.querySelector('[data-panel="sessions"]')?.classList.contains("is-visible")) loadPlatform();
  if (document.querySelector('[data-panel="operations"]')?.classList.contains("is-visible")) loadProcesses();
}, 5_000);
document.addEventListener("visibilitychange", () => { if (!document.hidden) refreshStatus(); });

// ---------------------------------------------------------------------------
// Pairing a phone.
//
// The operator mints a single-use invite and the phone reads it. Everything
// here is deliberately local: the symbol is drawn from the vendored encoder in
// `/assets/qrcode.js` and rendered as inline SVG, because the dashboard's own
// policy is `default-src 'none'` with `img-src 'self'` — a data: image would be
// refused and a remote generator is both blocked and a place a live credential
// must never go.
// ---------------------------------------------------------------------------

const PAIRING_QUIET_MODULES = 4;
let pairingOfferText = null;
let pairingExpiresAtMs = 0;
let pairingCountdown = 0;

/// The offer must reach the phone as the exact bytes the endpoint returned:
/// the app parses it as canonical JSON, so a re-serialised object is a
/// different document and pairing fails. `api()` hands back parsed JSON, so
/// this path reads the response as text and never rebuilds it.
async function pairingRequestText(path, options = {}) {
  const response = await fetch(path, {
    cache: "no-store",
    credentials: "same-origin",
    ...options,
    headers: { Accept: "application/vnd.automonique.mobile-auth.v1+json", ...(options.headers || {}) },
  });
  const text = await response.text();
  return { ok: response.ok, status: response.status, text };
}

function pairingSetStatus(message, kind = "info") {
  const node = byId("pairing-status");
  node.textContent = message ? translatePhrase(message) : "";
  node.dataset.kind = kind;
}

function pairingClearResult() {
  window.clearInterval(pairingCountdown);
  pairingCountdown = 0;
  pairingOfferText = null;
  pairingExpiresAtMs = 0;
  byId("pairing-result").hidden = true;
  byId("pairing-copy").hidden = true;
  byId("pairing-code").replaceChildren();
  byId("pairing-expiry").textContent = "";
  byId("pairing-expiry").classList.remove("is-expired");
}

/// Draw one QR symbol as inline SVG. One path, one rect per dark module, so the
/// whole symbol is a single node the browser scales without resampling.
function pairingDrawCode(value) {
  const host = byId("pairing-code");
  host.replaceChildren();
  const encoder = window.moniqueQrCode;
  if (!encoder?.create) {
    pairingSetStatus("The QR encoder did not load. Use Copy invite instead.", "error");
    return false;
  }
  const symbol = encoder.create(value, { errorCorrectionLevel: "M" });
  const size = symbol.modules.size;
  const span = size + PAIRING_QUIET_MODULES * 2;
  let path = "";
  for (let row = 0; row < size; row += 1) {
    for (let column = 0; column < size; column += 1) {
      if (!symbol.modules.get(row, column)) continue;
      path += `M${column + PAIRING_QUIET_MODULES} ${row + PAIRING_QUIET_MODULES}h1v1h-1z`;
    }
  }
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", `0 0 ${span} ${span}`);
  svg.setAttribute("shape-rendering", "crispEdges");
  const background = document.createElementNS("http://www.w3.org/2000/svg", "rect");
  background.setAttribute("width", String(span));
  background.setAttribute("height", String(span));
  background.setAttribute("fill", "#ffffff");
  const modules = document.createElementNS("http://www.w3.org/2000/svg", "path");
  modules.setAttribute("d", path);
  modules.setAttribute("fill", "#000000");
  svg.append(background, modules);
  host.append(svg);
  return true;
}

function pairingTick() {
  const node = byId("pairing-expiry");
  const remaining = Math.round((pairingExpiresAtMs - Date.now()) / 1000);
  if (remaining <= 0) {
    node.textContent = translatePhrase("This invite has expired. Create another.");
    node.classList.add("is-expired");
    window.clearInterval(pairingCountdown);
    pairingCountdown = 0;
    return;
  }
  node.classList.remove("is-expired");
  node.textContent = translatePhrase(`Expires in ${remaining} seconds`);
}

async function pairingLoadSessions() {
  const select = byId("pairing-sessions");
  select.replaceChildren();
  try {
    const view = await api("/api/mobile/pairing-sessions");
    const sessions = Array.isArray(view.sessions) ? view.sessions : [];
    if (sessions.length === 0) {
      pairingSetStatus("No session exists yet, so an invite would reach nothing. Run a task first.", "error");
      byId("pairing-create").disabled = true;
      return;
    }
    for (const entry of sessions) {
      const id = entry.session?.resource?.id;
      if (!id) continue;
      const option = document.createElement("option");
      option.value = id;
      option.selected = true;
      option.textContent = entry.session?.summary ? `${id} — ${entry.session.summary}` : id;
      option.setAttribute("data-i18n-skip", "");
      select.append(option);
    }
    byId("pairing-create").disabled = select.options.length === 0;
    pairingSetStatus("");
  } catch (error) {
    byId("pairing-create").disabled = true;
    pairingSetStatus("The session list is unavailable, so the invite could not be scoped.", "error");
  }
}

async function pairingCreate() {
  const button = byId("pairing-create");
  const scope = Array.from(byId("pairing-sessions").selectedOptions, (option) => option.value);
  if (scope.length === 0) {
    // session_scope is an allowlist, not a filter: an empty one reaches nothing.
    pairingSetStatus("Select at least one session. A phone can only reach the sessions named here.", "error");
    return;
  }
  button.disabled = true;
  pairingClearResult();
  pairingSetStatus("Creating the invite…");
  try {
    const result = await pairingRequestText("/api/mobile/pairings", {
      method: "POST",
      headers: { "Content-Type": "application/vnd.automonique.mobile-auth.v1+json" },
      body: JSON.stringify({
        actions: ["attach", "follow_up", "decide_approval", "stop_run"],
        session_scope: scope,
        limits: { max_follow_up_bytes: 65536, max_page_events: 100 },
      }),
    });
    if (!result.ok) {
      pairingSetStatus("The invite was refused. Check the operator credential and try again.", "error");
      return;
    }
    let parsed;
    try {
      parsed = JSON.parse(result.text);
    } catch (_error) {
      pairingSetStatus("The invite could not be read.", "error");
      return;
    }
    pairingOfferText = result.text.trim();
    pairingExpiresAtMs = Number(parsed.expires_at_ms) || 0;
    byId("pairing-result").hidden = false;
    byId("pairing-copy").hidden = false;
    pairingDrawCode(pairingOfferText);
    pairingTick();
    pairingCountdown = window.setInterval(pairingTick, 1000);
    pairingSetStatus("");
  } catch (_error) {
    pairingSetStatus("The invite could not be created.", "error");
  } finally {
    button.disabled = false;
  }
}

function pairingOpen(open) {
  byId("pairing-panel").hidden = !open;
  byId("pairing-open").setAttribute("aria-expanded", open ? "true" : "false");
  if (open) {
    byId("pairing-create").disabled = false;
    pairingClearResult();
    pairingSetStatus("");
    void pairingLoadSessions();
    byId("pairing-close").focus();
  } else {
    pairingClearResult();
    byId("pairing-open").focus();
  }
}

byId("pairing-open").addEventListener("click", () => pairingOpen(byId("pairing-panel").hidden));
byId("pairing-close").addEventListener("click", () => pairingOpen(false));
byId("pairing-create").addEventListener("click", () => void pairingCreate());
byId("pairing-copy").addEventListener("click", async () => {
  if (!pairingOfferText) return;
  try {
    await navigator.clipboard.writeText(pairingOfferText);
    pairingSetStatus("Invite copied. Paste it in the app.");
  } catch (_error) {
    pairingSetStatus("The invite could not be copied.", "error");
  }
});
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && !byId("pairing-panel").hidden) pairingOpen(false);
});
document.addEventListener("click", (event) => {
  if (byId("pairing-panel").hidden) return;
  if (event.target.closest("#pairing-panel, #pairing-open")) return;
  pairingOpen(false);
});

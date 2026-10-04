// SPDX-License-Identifier: Elastic-2.0

"use strict";

const byId = (id) => document.getElementById(id);
const supportedLanguages = ["en", "fr"];
let currentLanguage = storedPreference("monique-language", supportedLanguages, navigator.language.toLowerCase().startsWith("fr") ? "fr" : "en");
const localeTag = () => currentLanguage === "fr" ? "fr-FR" : "en-US";
const count = (value) => Number.isSafeInteger(value) && value >= 0 ? value.toLocaleString(localeTag()) : "-";
const words = (value) => typeof value === "string" ? translatePhrase(value.replaceAll("_", " ")) : "-";
const yesNo = (value) => value === true ? translatePhrase("YES") : value === false ? translatePhrase("NO") : "-";
const safeMetric = (value) => Number.isSafeInteger(value) && value >= 0 ? value : 0;
const statusHistory = [];
let memorySnapshot = null;
let memoryKind = "all";
let memoryStatus = "all";
let memorySensitivity = "all";
let memorySort = "updated_desc";
let memoryMode = storedPreference("monique-memory-view", ["graph", "list", "timeline"], "list");
let selectedMemoryReference = null;
let memoryQuery = null;
let memoryReview = "all";
let memoryLoadSequence = 0;
let memoryEditorEntry = null;
let memoryConfirmation = null;
let memorySaving = false;
let operationsSnapshot = null;
let processesSnapshot = null;
let processesLoadSequence = 0;
let platformSnapshot = null;
let cockpitSnapshot = null;
let platformSelectedSession = null;
let platformHistoryCursor = null;
let platformHistoryAutoPages = 0;
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
let cockpitRerunPreview = null;
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
const chatUi = {id:null,ready:false,loading:false,items:[],drafts:new Map(),quotes:new Map(),findHits:[],findIndex:-1,historyGroups:new Map(),follow:true,hasMore:false};
let lastStatusSnapshot = null;
let configurationFilter = "all";
let configurationQuery = "";
let agentAccountsPollTimer = null;
let agentAccountsView = null;
const dismissedAgentLogins = new Set();
let agentAccountsRequest = 0;
let agentAccountMutation = false;
let statusRefreshTimer = null;
let lastNotifiedAttentionKey = null;

// Ops console: shared list rows, badges and drawer state. The views render
// their lists through these helpers so every list scans, selects and opens
// its detail drawer the same way.
const consoleState = { expandedLists: new Set(), taskDrawerDismissed: false, ticketId: null, opsKind: null, opsKey: null, memoryOpen: false };

function consoleViewName(name) {
  return { sessions: "Tasks", tickets: "Tickets", operations: "Agents", memory: "Memory", artifacts: "Deliverables", overview: "Health", configuration: "Settings", chat: "Assistant" }[name] || name;
}

function consoleRow(className, onSelect) {
  const row = document.createElement("div");
  row.className = `row ${className}`;
  row.tabIndex = 0;
  row.setAttribute("role", "button");
  row.dataset.row = "";
  row.addEventListener("click", (event) => {
    if (event.target.closest("a, button") && event.target.closest("a, button") !== row) return;
    onSelect();
  });
  return row;
}

function consoleMsAgo(value) {
  const milliseconds = Number(value);
  if (!Number.isFinite(milliseconds) || milliseconds <= 0) return "-";
  return ticketRelativeTime(new Date(milliseconds).toISOString()) || "-";
}

// Long lists show the newest rows first and fold the rest behind one row.
function consoleCapList(root, key, attribute, selectedValue, limit = 20) {
  const rows = [...root.querySelectorAll(":scope > [data-row]")];
  root.querySelector(":scope > .table-more")?.remove();
  if (rows.length <= limit) return;
  const expanded = consoleState.expandedLists.has(key);
  rows.forEach((row, index) => {
    row.hidden = !expanded && index >= limit && row.getAttribute(attribute) !== selectedValue;
  });
  const more = document.createElement("button");
  more.type = "button";
  more.className = "table-more";
  more.textContent = expanded ? "Show fewer" : `Show all (${rows.length})`;
  more.addEventListener("click", () => {
    if (expanded) consoleState.expandedLists.delete(key);
    else consoleState.expandedLists.add(key);
    consoleCapList(root, key, attribute, selectedValue, limit);
  });
  root.append(more);
}

// "Open" only means the conversation exists. Working needs real evidence: a
// running agent job on that session, or its workspace reporting "working".
function consoleSessionWorking(sessionId) {
  if (!sessionId) return false;
  const running = (processesSnapshot?.jobs || []).some((job) => processDisplayStatus(job) === "running" && job.session_id === sessionId);
  const workspace = (cockpitPresentation?.workspaces || []).some((item) => item.attention === "working" && (item.session_ids || []).includes(sessionId));
  return running || workspace;
}

function consoleSessionObservedMs(session) {
  const value = Number(session?.session?.observed_at_ms ?? session?.observed_at_ms);
  return Number.isFinite(value) && value > 0 ? value : 0;
}

function consoleShortId(id) {
  const text = String(id || "-");
  return text.length <= 14 ? text : `${text.slice(0, 12)}…`;
}

// What each conversation was about, learned in this page session only (from
// a task started here or the first message of a conversation opened here).
// Kept in memory on purpose: task text is never written to browser storage.
const consoleLearnedTitles = new Map();

function consoleLearnTitle(sessionId, text) {
  const title = String(text || "").replace(/\s+/g, " ").trim();
  if (!sessionId || !title || consoleLearnedTitles.get(sessionId) === title) return;
  consoleLearnedTitles.set(sessionId, title.length > 90 ? `${title.slice(0, 89)}…` : title);
  if (platformSnapshot) renderRetainedPlatform(platformSnapshot);
}

function consoleSessionTitle(session) {
  const learned = consoleLearnedTitles.get(session?.session?.resource?.id);
  if (learned) return learned;
  const observed = consoleSessionObservedMs(session);
  if (!observed) return `${translatePhrase("Session")} ${consoleShortId(session?.session?.resource?.id)}`;
  const when = new Intl.DateTimeFormat(localeTag(), { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" }).format(observed);
  return `${translatePhrase("Session")} · ${when}`;
}

function consoleSentence(value) {
  const text = words(value);
  return text.charAt(0).toLocaleUpperCase(localeTag()) + text.slice(1);
}

function consoleCell(text, className = "cell") {
  const cell = document.createElement("span");
  cell.className = className;
  cell.textContent = text;
  return cell;
}

function consoleCellWrap(child) {
  const cell = document.createElement("span");
  cell.className = "cell";
  cell.append(child);
  return cell;
}

function consoleBadge(text, tone = "quiet") {
  const badge = document.createElement("span");
  badge.className = "badge";
  badge.dataset.tone = tone;
  badge.textContent = text;
  return badge;
}

function consolePriority(priority) {
  const node = document.createElement("span");
  node.className = "prio";
  node.dataset.p = ["urgent", "high", "normal", "low"].includes(priority) ? priority : "normal";
  const bars = document.createElement("i");
  bars.setAttribute("aria-hidden", "true");
  bars.append(document.createElement("span"));
  const text = document.createElement("span");
  text.textContent = operationLabel(priority || "normal");
  node.append(bars, text);
  return node;
}

function consoleFact(labelText, value) {
  const row = document.createElement("div");
  const term = document.createElement("dt");
  term.textContent = labelText;
  const detail = document.createElement("dd");
  detail.setAttribute("data-i18n-skip", "");
  detail.textContent = value || "-";
  row.append(term, detail);
  return row;
}

let consoleDrawerOrigin = null;

function consoleDrawer(id, open, reveal = false) {
  const drawer = byId(id);
  if (!drawer) return;
  const narrow = window.matchMedia("(max-width: 760px)").matches;
  if (open && reveal) consoleDrawerOrigin = document.querySelector(".view.is-visible [data-row].is-selected");
  if (!open && narrow && drawer.classList.contains("is-open") && consoleDrawerOrigin?.isConnected) {
    // On a phone the drawer sits under the list: closing it returns to the
    // row it was opened from instead of leaving the reader at the bottom.
    const origin = consoleDrawerOrigin;
    window.requestAnimationFrame(() => origin.scrollIntoView({ block: "center" }));
  }
  if (open && reveal) {
    // On a phone the drawer sits under the list; bring it into view.
    window.requestAnimationFrame(() => {
      if (window.matchMedia("(max-width: 760px)").matches) drawer.scrollIntoView({ block: "start" });
    });
  }
  drawer.classList.toggle("is-open", open);
  drawer.inert = !open;
  drawer.closest(".view-split")?.classList.toggle("has-drawer", open);
  document.documentElement.dataset.sheet = document.querySelector(".view.is-visible .drawer.is-open") ? "open" : "closed";
}

function consoleDrawerIsOpen(id) {
  return byId(id)?.classList.contains("is-open") === true;
}

function consoleMarkSelected(root, attribute, value) {
  root?.querySelectorAll("[data-row]").forEach((row) => row.classList.toggle("is-selected", value !== null && row.getAttribute(attribute) === value));
}

function consoleOpenTicket(id, reveal = true) {
  const ticket = (operationsSnapshot?.tickets?.items || []).find((item) => item.id === id);
  if (!ticket) {
    consoleState.ticketId = null;
    consoleDrawer("ticket-drawer", false);
    return;
  }
  consoleState.ticketId = id;
  renderTicketDrawer(ticket);
  loadTicketConversation(ticket, reveal);
  consoleMarkSelected(byId("ticket-list"), "data-ticket-id", id);
  if (reveal) consoleDrawer("ticket-drawer", true, true);
}

function consoleRefreshTicketDrawer() {
  if (consoleState.ticketId && consoleDrawerIsOpen("ticket-drawer")) consoleOpenTicket(consoleState.ticketId, false);
}

function consoleOpenProcess(id, reveal = true) {
  const job = (processesSnapshot?.jobs || []).find((item) => item.id === id);
  if (!job) {
    if (reveal) return;
    if (consoleState.opsKind === "process") consoleCloseOps();
    return;
  }
  if (!reveal && !consoleDrawerIsOpen("ops-drawer")) return;
  consoleState.opsKind = "process";
  consoleState.opsKey = id;
  renderProcessDrawer(job);
  consoleMarkSelected(byId("process-list"), "data-process-id", id);
  consoleMarkSelected(byId("operations-tool-grid"), "data-tool-key", null);
  if (reveal) consoleDrawer("ops-drawer", true, true);
}

function consoleOpenTool(key, reveal = true) {
  const tool = (operationsSnapshot?.tools || []).find((item) => `${item.server}:${item.name}` === key);
  if (!tool) {
    if (!reveal && consoleState.opsKind === "tool") consoleCloseOps();
    return;
  }
  if (!reveal && !consoleDrawerIsOpen("ops-drawer")) return;
  consoleState.opsKind = "tool";
  consoleState.opsKey = key;
  processPanel.resetShell();
  renderToolDrawer(tool);
  consoleMarkSelected(byId("operations-tool-grid"), "data-tool-key", key);
  consoleMarkSelected(byId("process-list"), "data-process-id", null);
  if (reveal) consoleDrawer("ops-drawer", true, true);
}

function consoleCloseOps() {
  processPanel.resetShell();
  consoleState.opsKind = null;
  consoleState.opsKey = null;
  consoleMarkSelected(byId("process-list"), "data-process-id", null);
  consoleMarkSelected(byId("operations-tool-grid"), "data-tool-key", null);
  consoleDrawer("ops-drawer", false);
}

function consoleOpenMemory(reference) {
  selectedMemoryReference = reference;
  consoleState.memoryOpen = true;
  renderSelectedMemory();
  byId("memory-drawer-title").setAttribute("data-i18n-skip", "");
  byId("memory-drawer-title").textContent = reference;
  consoleDrawer("memory-drawer", true, true);
}

function consoleShowTaskPane(pane) {
  const workspace = pane === "workspace";
  byId("drawer-workspace-pane").hidden = !workspace;
  const workspaceTab = document.querySelector("[data-drawer-pane='workspace']");
  workspaceTab.classList.toggle("is-active", workspace);
  workspaceTab.setAttribute("aria-selected", String(workspace));
  workspaceTab.tabIndex = workspace ? 0 : -1;
  if (workspace) {
    document.querySelectorAll("[data-cockpit-surface]").forEach((item) => {
      item.classList.remove("is-active");
      item.setAttribute("aria-selected", "false");
      item.tabIndex = -1;
      const panel = byId(item.getAttribute("aria-controls"));
      panel.hidden = true;
      panel.classList.remove("is-active");
    });
  } else {
    document.querySelector(`[data-cockpit-surface="${pane}"]`)?.click();
  }
  consoleSyncTaskDrawerTitle();
}

function consoleTaskPane() {
  if (!byId("drawer-workspace-pane").hidden) return "workspace";
  return document.querySelector("[data-cockpit-surface].is-active")?.dataset.cockpitSurface || "conversation";
}

function consoleSyncTaskDrawerTitle() {
  const title = byId("task-drawer-title");
  const kicker = byId("task-drawer-kicker");
  if (!title || !kicker) return;
  title.setAttribute("data-i18n-skip", "");
  if (consoleTaskPane() === "conversation") {
    kicker.textContent = "Conversation";
    title.textContent = byId("platform-session-detail").hidden ? translatePhrase("Nothing selected") : byId("platform-session-summary").textContent;
  } else {
    kicker.textContent = "Workspace";
    title.textContent = byId("cockpit-workspace-title").textContent;
  }
}

function consoleTaskDrawerOpened() {
  if (!consoleDrawerIsOpen("task-drawer")) {
    consoleDrawer("task-drawer", true);
    consoleShowTaskPane("conversation");
  }
}

function consoleOpenSession(sessionId) {
  consoleDrawer("task-drawer", true, true);
  consoleShowTaskPane("conversation");
  selectPlatformSession(sessionId);
}

function consoleOpenWorkspace(workspace) {
  consoleDrawer("task-drawer", true, true);
  consoleShowTaskPane("workspace");
  selectCockpitWorkspace(workspace);
}
const frenchUi = Object.freeze({
  "Deliverables": "Livrables",
  "No deliverables attached to this run yet.": "Aucun livrable rattaché à cette exécution pour le moment.",
  "Deliverables are unavailable.": "Les livrables sont indisponibles.",
  "Open deliverable": "Ouvrir le livrable",
  "Conversation deliverables": "Livrables de la conversation",
  "Close preview": "Fermer l’aperçu",
  "archived": "archivés",
  "Model not reported": "Modèle non communiqué",
  "active jobs": "tâches actives",
  "Manage reports this run as active, but the assigned worker reports no active jobs.": "Manage indique une exécution en cours, mais le worker assigné ne signale aucune tâche active.",
  "Test response": "Tester une réponse",
  "Response test started.": "Test de réponse lancé.",
  "Sends a small test prompt using this subscription.": "Envoie une courte demande de test avec cet abonnement.",
  "MCP servers & tools": "Serveurs et outils MCP",
  "No MCP servers configured.": "Aucun serveur MCP configuré.",
  "MCP configuration is unavailable.": "La configuration MCP est indisponible.",
  "Refresh tools": "Actualiser les outils",
  "Tools discovered": "Outils disponibles",
  "Discovery failed": "Échec de la découverte",
  "Changes data": "Modifie des données",
  "Not checked yet": "Pas encore vérifié",
  "Automations": "Automatisations",
  "Pause stops future runs. Work already running can finish.": "La pause arrête les prochaines exécutions. Le travail en cours peut se terminer.",
  "Automation service is unavailable.": "Le service d’automatisation est indisponible.",
  "No automations registered.": "Aucune automatisation enregistrée.",
  "Last result": "Dernier résultat",
  "Next run": "Prochaine exécution",
  "Last run": "Dernière exécution",
  "Never run": "Jamais exécutée",
  "Preview": "Aperçu",
  "Preview only · nothing will run": "Aperçu uniquement · aucune exécution",
  "Schedule": "Planification",
  "Scope": "Périmètre",
  "No task registered.": "Aucune tâche enregistrée.",
  "Pause": "Mettre en pause",
  "Resume": "Reprendre",
  "Paused": "En pause",
  "Archived": "Archivé",
  "Backups": "Sauvegardes",
  "Next backup": "Prochaine sauvegarde",
  "Latest backup": "Dernière sauvegarde",
  "Automatic backups are not configured.": "Les sauvegardes automatiques ne sont pas configurées.",
  "Automatic backups are paused.": "Les sauvegardes automatiques sont en pause.",
  "Backup schedule is unavailable.": "La planification des sauvegardes est indisponible.",
  "No completed backups found.": "Aucune sauvegarde terminée trouvée.",
  "Older backups": "Sauvegardes précédentes",
  "databases": "bases de données",
  "Verify backup": "Vérifier la sauvegarde",
  "Verifying backup…": "Vérification de la sauvegarde…",
  "Backup verified": "Sauvegarde vérifiée",
  "Backup verification failed": "Échec de la vérification de la sauvegarde",
  "Check latest status": "Vérifier l’état actuel",
  "Checking latest status…": "Vérification de l’état actuel…",
  "Fresh snapshot": "Relevé récent",
  "Last activity": "Dernière activité",
  "GitHub is closed while Manage still reports pending or running work. These sources disagree.": "Le ticket GitHub est fermé, mais Manage indique encore un travail en attente ou en cours. Les sources sont en désaccord.",
  "Issue state and agent execution are separate. An open issue can contain completed work.": "L’état du ticket et l’exécution de l’agent sont distincts. Un ticket ouvert peut contenir un travail terminé.",
  "The source status differs from the ticket list. Refresh the list to reconcile the display.": "L’état de la source diffère de la liste. Actualisez la liste pour mettre l’affichage à jour.",
  "Testing response…": "Test de réponse en cours…",
  "Response verified": "Réponse vérifiée",
  "Response test failed": "Échec du test de réponse",
  "Subscription quota reached.": "Quota de l’abonnement atteint.",
  "Sign in before testing a response.": "Connectez le compte avant de tester une réponse.",
  "The provider could not complete the response test.": "Le fournisseur n’a pas pu terminer le test de réponse.",
  "Test retrieval": "Tester le rappel",
  "Find duplicates": "Chercher les doublons",
  "Select filtered memories": "Sélectionner les souvenirs filtrés",
  "Clear selection": "Effacer la sélection",
  "Archive selected": "Archiver la sélection",
  "selected": "sélectionnés",
  "Select": "Sélectionner",
  "Select up to 100 memories.": "Sélectionnez jusqu’à 100 souvenirs.",
  "Retrieval preview": "Aperçu du rappel",
  "These are the memories supplied to dashboard chat for this question. No message was sent.": "Voici les souvenirs fournis à l’assistant pour cette question. Aucun message n’a été envoyé.",
  "No active memories match this question.": "Aucun souvenir actif ne correspond à cette question.",
  "Duplicate memories": "Souvenirs en double",
  "Matches ignore letter case and extra spaces. Review each group before archiving.": "La recherche ignore les majuscules et les espaces supplémentaires. Vérifiez chaque groupe avant d’archiver.",
  "No duplicate memories found.": "Aucun doublon trouvé.",
  "Results are limited. Search to narrow the inventory.": "Les résultats sont limités. Affinez votre recherche.",
  "Enter a question in the memory search field.": "Saisissez une question dans le champ de recherche des souvenirs.",
  "Archive selected memories": "Archiver les souvenirs sélectionnés",
  "Selected memories": "Souvenirs sélectionnés",
  "They will stop appearing in retrieval. Their content and audit history will be retained.": "Ils ne seront plus utilisés par l’assistant. Leur contenu et leur historique seront conservés.",
  "Archive": "Archiver",
  "Selected memories archived.": "Souvenirs sélectionnés archivés.",
  "This automation changed. Refresh before trying again.": "Cette automatisation a changé. Actualisez avant de réessayer.",
  "A selected memory changed. Refresh and select it again.": "Un souvenir sélectionné a changé. Actualisez et sélectionnez-le à nouveau.",
  "A backup verification is already running.": "Une vérification de sauvegarde est déjà en cours.",
  "An agent response test is already running.": "Un test de réponse d’agent est déjà en cours.",
  "Check the selected item and try again.": "Vérifiez l’élément sélectionné et réessayez.",

  "Test": "Tester",
  "Test again": "Retester",
  "Testing…": "Test en cours…",
  "Checking connection…": "Vérification de la connexion…",
  "Checked": "Vérifié à",
  "servers verified": "serveurs vérifiés",
  "Bot authentication verified.": "Authentification du bot vérifiée.",
  "Account authentication verified.": "Authentification du compte vérifiée.",
  "Support access verified.": "Accès à l’assistance vérifié.",
  "Tool discovery verified.": "Accès aux outils vérifié.",
  "Connection is not configured.": "Connexion non configurée.",
  "Configure an authorized user before testing.": "Configurez un utilisateur autorisé avant de tester.",
  "Review the connection configuration on the server.": "Vérifiez la configuration de la connexion sur le serveur.",
  "Reconnect GitHub on the server, then retry.": "Reconnectez GitHub sur le serveur, puis réessayez.",
  "Authentication rejected. Reconnect and retry.": "Authentification refusée. Reconnectez le compte et réessayez.",
  "Access refused. Check the connection permissions.": "Accès refusé. Vérifiez les permissions de la connexion.",
  "Service unavailable. Check access and retry.": "Service indisponible. Vérifiez l’accès et réessayez.",
  "The connection timed out. Try again.": "Le délai de connexion est dépassé. Réessayez.",
  "Some MCP servers could not list their tools.": "Certains serveurs MCP n’ont pas pu lister leurs outils.",
  "MCP discovery timed out before all servers were checked.": "Le délai est dépassé. Certains serveurs MCP n’ont pas été vérifiés.",
  "The check could not finish. Try again.": "Le test n’a pas pu aboutir. Réessayez.",
  "Another connection test is running. Try again shortly.": "Un autre test est en cours. Réessayez dans un instant.",
  "Read-only tests · no messages sent": "Tests en lecture seule · aucun message envoyé",

  "Dismiss": "Masquer",
  "The connection was lost. These readings may be out of date.": "La connexion a été perdue. Ces relevés peuvent être périmés.",
  "Sign-in required": "Connexion nécessaire",
  "Account overview": "Vue d’ensemble des comptes",
  "Refresh accounts & usage": "Actualiser les comptes et l’utilisation",
  "Find an account": "Rechercher un compte",
  "Search account names…": "Rechercher un nom de compte…",
  "Show accounts": "Afficher les comptes",
  "All accounts": "Tous les comptes",
  "Connected": "Connectés",
  "Needs attention": "À vérifier",
  "Usage is shared with other apps using the same subscription. Readings refresh at most every five minutes.": "L’utilisation est partagée avec les autres applications du même abonnement. Les relevés sont actualisés au maximum toutes les cinq minutes.",
  "Account name": "Nom du compte",
  "Enter an account name.": "Saisissez un nom de compte.",
  "Use a name between 1 and 48 characters.": "Utilisez un nom de 1 à 48 caractères.",
  "Reconnect account": "Reconnecter le compte",
  "Connect a subscription": "Connecter un abonnement",
  "Choose a name, then sign in securely on the provider’s website.": "Choisissez un nom, puis connectez-vous sur le site sécurisé du fournisseur.",
  "Continue to sign-in": "Continuer la connexion",
  "Subscription usage": "Utilisation de l’abonnement",
  "Checking usage…": "Vérification de l’utilisation…",
  "Usage unavailable": "Utilisation indisponible",
  "Latest reading": "Dernier relevé",
  "5-hour window": "Fenêtre de 5 heures",
  "Weekly limit": "Limite hebdomadaire",
  "Usage window": "Période d’utilisation",
  "used": "utilisés",
  "Resets": "Réinitialisation",
  "Reset time passed; refresh pending": "Échéance passée ; actualisation en attente",
  "Reset time not provided": "Date de réinitialisation non fournie",
  "Sign in to view subscription usage.": "Connectez-vous pour voir l’utilisation de cet abonnement.",
  "The provider has limited usage checks. We’ll retry after the cooldown.": "Le fournisseur limite les vérifications. Une nouvelle tentative aura lieu après le délai d’attente.",
  "The provider took too long to respond. Try again later.": "Le fournisseur met trop de temps à répondre. Réessayez plus tard.",
  "The provider has not returned usage limits for this account.": "Le fournisseur n’a pas renvoyé de limites d’utilisation pour ce compte.",
  "Usage could not be retrieved. Try again later.": "L’utilisation n’a pas pu être récupérée. Réessayez plus tard.",
  "Previous reading — usage may have changed.": "Relevé précédent — l’utilisation a pu évoluer.",
  "Usage has not been checked yet.": "L’utilisation n’a pas encore été vérifiée.",
  "Checked": "Vérifié",
  "Worker account": "Compte sélectionné pour l’agent",
  "Available account": "Compte disponible",
  "Last verified": "Dernière vérification",
  "Not verified yet": "Pas encore vérifié",
  "Selected for worker": "Sélectionné pour l’agent",
  "Verify connection": "Vérifier la connexion",
  "Manage account": "Gérer le compte",
  "Rename": "Renommer",
  "Rename account": "Renommer le compte",
  "This name is only used in Monique.": "Ce nom est utilisé uniquement dans Monique.",
  "Account renamed.": "Compte renommé.",
  "Sign out account": "Déconnecter le compte",
  "This account is selected for the worker. New work may require signing in again.": "Ce compte est sélectionné pour l’agent. Les prochaines tâches pourront nécessiter une nouvelle connexion.",
  "Remove account": "Supprimer le compte",
  "No accounts match these filters.": "Aucun compte ne correspond à ces filtres.",
  "accounts": "comptes",
  "Connected accounts": "Comptes connectés",
  "Need sign-in": "À connecter",
  "Approaching a limit": "Proches d’une limite",
  "Connect your first subscription to see its usage and choose an account for the worker.": "Connectez votre premier abonnement pour suivre son utilisation et choisir le compte de l’agent.",

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
  "Start a task, then follow its workspace and conversation in one place.": "Lancez une tâche, puis suivez son espace de travail et sa conversation au même endroit.",
  "See what agents are running and which Support and Manage tools Monique can use. Anything that changes data waits for your approval.": "Voyez quels agents tournent et quels outils Support et Manage Monique peut utiliser. Tout changement de données attend votre accord.",
  "Pick a session to read its history. Reading never takes control, and every follow-up is checked against the latest state first.": "Choisissez une session pour lire son historique. La lecture ne prend jamais le contrôle, et chaque relance est vérifiée sur l’état le plus récent.",
  "Its history, progress and approvals will appear here.": "Son historique, sa progression et ses validations apparaîtront ici.",
  "What Monique is doing right now, and anything that needs you.": "Ce que fait Monique en ce moment, et ce qui demande votre attention.",
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
  "need a manual check": "à vérifier à la main",
  "AMBIGUOUS": "AMBIGU",
  "outcome unclear": "résultat incertain",
  "ATTENTION": "ATTENTION",
  "checks failing": "contrôles en échec",
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
  "Received and saved": "Reçu et enregistré",
  "Execution": "Exécution",
  "Agents at work": "Agents au travail",
  "Delivery": "Livraison",
  "Results being sent": "Résultats en cours d’envoi",
  "Reconcile": "Réconcilier",
  "Results being confirmed": "Résultats en cours de confirmation",
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
  "What Monique remembers, where it came from, and when to review it.": "Ce dont Monique se souvient, d’où cela vient, et quand le revoir.",
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
  "Project, host, and workspace navigation": "Navigation par projet, serveur et espace de travail",
  "Structured workspace attention inbox": "Éléments qui vous attendent",
  "Chronological workspace activity": "Activité récente de l’espace de travail",
  "Live": "En direct",
  "Saved history": "Historique enregistré",
  "No linked run": "Aucune exécution liée",
  "Next review": "Prochain réexamen",
  "No review scheduled": "Aucun réexamen planifié",
  "Review due": "Réexamen requis",
  "Add memory": "Ajouter un souvenir",
  "Edit memory": "Modifier le souvenir",
  "Save memory": "Enregistrer le souvenir",
  "Export results": "Exporter les résultats",
  "Any review date": "Toutes les dates de réexamen",
  "Needs review": "À réexaminer",
  "Unscheduled": "Non planifié",
  "Close editor": "Fermer l’éditeur",
  "Content": "Contenu",
  "Certainty (%)": "Certitude (%)",
  "User preference": "Préférence utilisateur",
  "Event": "Événement",
  "Personal": "Personnel",
  "Restricted": "Restreint",
  "Only me": "Moi uniquement",
  "Everyone in this tenant": "Tout le monde dans cet espace",
  "Forget": "Oublier",
  "Expires": "Expiration",
  "Never": "Jamais",
  "Replaced by": "Remplacé par",
  "What should Monique remember?": "Que doit retenir Monique ?",
  "Save a stable fact or preference for future conversations.": "Enregistrez un fait stable ou une préférence pour les prochaines conversations.",
  "Save a stable fact or preference for future conversations. It will be active immediately.": "Enregistrez un fait stable ou une préférence pour les prochaines conversations. Il sera actif immédiatement.",
  "Saving keeps the previous version as a replaced record. Approval status is preserved. Choose a future review date or leave it empty.": "L’enregistrement conserve la version précédente et l’état d’approbation. Choisissez une date de réexamen future ou laissez ce champ vide.",
  "This proposal will become active and available in future conversations.": "Cette proposition deviendra active et disponible dans les prochaines conversations.",
  "This memory will be excluded from future recall. Its content and audit history remain available as an archived record.": "Ce souvenir ne sera plus utilisé. Son contenu et son historique restent disponibles dans les éléments supprimés.",
  "This memory changed elsewhere. Your draft is still here. Cancel and refresh before trying again.": "Ce souvenir a été modifié ailleurs. Votre brouillon est conservé. Annulez et actualisez avant de réessayer.",
  "This memory is unavailable or belongs to another author. Refresh the list.": "Ce souvenir est indisponible ou appartient à un autre auteur. Actualisez la liste.",
  "Check the content, certainty, and future review date. Content must fit within 8 KB.": "Vérifiez le contenu, la certitude et la date de réexamen future. Le contenu est limité à 8 Ko.",
  "The change could not be confirmed. Your draft is still here. Refresh the list before retrying.": "La modification n’a pas pu être confirmée. Votre brouillon est conservé. Actualisez la liste avant de réessayer.",
  "Memory unavailable. Refresh to try again.": "Mémoire indisponible. Actualisez pour réessayer.",
  "Status unconfirmed": "État non confirmé",
  "Out-of-date snapshot": "Données périmées",
  "Saved agent output": "Sortie de l’agent conservée",
  "Last reported status": "Dernier état signalé",
  "Snapshot": "Relevé",
  "This snapshot is out of date. The last reported status is shown in Details; current execution is unconfirmed.": "Ce relevé est périmé. Le dernier état signalé figure dans les détails ; l’exécution actuelle n’est pas confirmée.",
  "Memory added.": "Souvenir ajouté.",
  "Memory updated. Previous version retained.": "Souvenir modifié. Version précédente conservée.",
  "Memory approved.": "Souvenir approuvé.",
  "Proposal rejected.": "Proposition rejetée.",
  "Memory removed from recall.": "Souvenir retiré du rappel.",
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
  "Your preferences, connected accounts and how this dashboard is protected.": "Vos préférences, vos comptes connectés et la protection de ce tableau de bord.",
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
  "Effective capabilities, boundaries, and limits-not credentials or private coordinates.": "Fonctionnalités, limites et périmètres effectifs - sans identifiants ni coordonnées privées.",
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
  "Approve and post": "Approuver et publier",
  "Posting the approved message…": "Publication du message approuvé…",
  "Slack post decided": "Publication Slack décidée",
  "The Slack post was decided. Read the reply for the outcome.": "La publication Slack a été décidée. Lisez la réponse pour le résultat.",
  "This action is still awaiting your decision.": "Cette action attend toujours votre décision.",
  "That action is no longer pending. Nothing was run.": "Cette action n’est plus en attente. Rien n’a été exécuté.",
  "That Slack post is no longer pending. Nothing was posted.": "Cette publication Slack n’est plus en attente. Rien n’a été publié.",
  "That Slack draft expired. Nothing was posted. Ask Monique to draft it again.": "Ce brouillon Slack a expiré. Rien n’a été publié. Demandez à Monique de le rédiger à nouveau.",
  "Too many Slack drafts are awaiting decisions. Resolve one and try again.": "Trop de brouillons Slack attendent une décision. Traitez-en un et réessayez.",
  "Monique could not hold the Slack draft safely. Nothing was posted.": "Monique n’a pas pu conserver le brouillon Slack en toute sécurité. Rien n’a été publié.",
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
  "Use for worker": "Utiliser pour l’agent",
  "Verify": "Vérifier",
  "Sign in again": "Se reconnecter",
  "Sign out": "Se déconnecter",
  "Remove": "Supprimer",
  "Worker account selected.": "Compte de l’agent sélectionné.",
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
  "Run a task": "Lancer une tâche",
  "Run task": "Lancer la tâche",
  "What should Monique do?": "Que doit faire Monique ?",
  "Ask Monique to write, run, or test code in a private writable workspace. Continue the resulting session here.": "Demandez à Monique d’écrire, d’exécuter ou de tester du code dans un espace de travail privé. Poursuivez ensuite la session ici.",
  "Create a script, run it, and report the result…": "Crée un script, exécute-le et présente le résultat…",
  "Each turn gets a fresh workspace; session history is retained. Repository changes use the ticket workflow.": "Chaque tour utilise un nouvel espace de travail ; l’historique de la session est conservé. Les modifications des dépôts passent par les tickets.",
  "Ready for a new task.": "Prêt pour une nouvelle tâche.",
  "Check task status": "Vérifier la tâche",
  "Open task session": "Ouvrir la session de la tâche",
  "Preparing task…": "Préparation de la tâche…",
  "Task accepted. Waiting for execution to finish…": "Tâche acceptée. En attente de la fin de l’exécution…",
  "Task completed. Open its session to read the result or continue.": "Tâche terminée. Ouvrez sa session pour lire le résultat ou continuer.",
  "Task completed; no retained session was returned.": "Tâche terminée ; aucune session conservée n’a été renvoyée.",
  "Checking the previous task’s receipt…": "Vérification du résultat de la tâche précédente…",
  "Task outcome is uncertain. Check its receipt; do not resubmit.": "Le résultat de la tâche est incertain. Vérifiez son état sans la relancer.",
  "Task was not submitted. Check the connection and browser storage, then try again.": "La tâche n’a pas été envoyée. Vérifiez la connexion et le stockage du navigateur, puis réessayez.",
  "Task status is unavailable. Check again; the task will not be resubmitted.": "L’état de la tâche est indisponible. Vérifiez à nouveau ; la tâche ne sera pas relancée.",
  "Task recovery storage is unavailable. Restore browser storage before starting work.": "Le stockage de suivi des tâches est indisponible. Rétablissez le stockage du navigateur avant de lancer une tâche.",
  "Create or resume a workspace": "Créer ou reprendre un espace de travail",
  "Task input remains local while lifecycle actions are unavailable": "La tâche reste locale tant que les actions du cycle de vie sont indisponibles",
  "Create unavailable": "Création indisponible",
  "Resume unavailable": "Reprise indisponible",
  "Task create and resume remain unavailable. Local host setup and checkout support typed preview and receipt operations.": "La création et la reprise de tâche restent indisponibles. La configuration d’hôte local et le checkout prennent en charge des opérations typées d’aperçu et de reçu.",
  // Conversation workspace.
  "New chat": "Nouvelle discussion",
  "Conversations retained for 90 days": "Conversations conservées 90 jours",
  "Find in conversation": "Rechercher dans la conversation",
  "Find in this conversation…": "Rechercher dans cette conversation…",
  "Find in this conversation": "Rechercher dans cette conversation",
  "Navigate conversation": "Parcourir la conversation",
  "Navigation mode": "Mode de navigation",
  "Close conversation navigation": "Fermer la navigation",
  "Conversation outline": "Sommaire de la conversation",
  "Find": "Rechercher",
  "Outline": "Sommaire",
  "Previous match": "Résultat précédent",
  "Next match": "Résultat suivant",
  "No matches": "Aucun résultat",
  "First 1000 matches": "1 000 premiers résultats",
  "Loaded messages": "Messages chargés",
  "All retained messages loaded": "Tous les messages conservés sont chargés",
  "Questions and reply headings will appear here.": "Les questions et les titres des réponses apparaîtront ici.",
  "Quote": "Citer",
  "Quoted excerpt": "Extrait cité",
  "Remove quote": "Retirer la citation",
  "Download reply": "Télécharger la réponse",
  "Export full conversation": "Exporter toute la conversation",
  "Cancel export": "Annuler l’export",
  "Preparing retained messages…": "Préparation des messages conservés…",
  "Conversation exported.": "Conversation exportée.",
  "Export cancelled.": "Export annulé.",
  "Export could not finish. No partial file was downloaded.": "L’export n’a pas abouti. Aucun fichier partiel n’a été téléchargé.",
  "This conversation is too large to export here.": "Cette conversation est trop volumineuse pour être exportée ici.",
  "Retained messages at the time of export.": "Messages conservés au moment de l’export.",
  "Today": "Aujourd’hui",
  "Close conversation history": "Fermer l’historique",
  "Toggle conversation history": "Afficher ou masquer l’historique",
  "Search conversations…": "Rechercher une conversation…",
  "Search conversations": "Rechercher une conversation",
  "Recent conversations · retained for 90 days": "Conversations récentes · conservées 90 jours",
  "Conversation options": "Options de la conversation",
  "Export visible messages": "Exporter les messages affichés",
  "Reload conversation": "Recharger la conversation",
  "Conversation messages": "Messages de la conversation",
  "Think it through, find an answer, or get something done.": "Réfléchir ensemble, trouver une réponse ou avancer sur un projet.",
  "↓ Latest messages": "↓ Derniers messages",
  "Loading conversation…": "Chargement de la conversation…",
  "Shift + Enter for a new line": "Maj + Entrée pour une nouvelle ligne",
  "Response mode": "Mode de réponse",
  "Monique can make mistakes. Check important information.": "Monique peut se tromper. Vérifiez les informations importantes.",
  "Your message is too long. Shorten it before sending.": "Votre message est trop long. Raccourcissez-le avant de l’envoyer.",
  "Previous 7 days": "7 derniers jours",
  "Earlier": "Plus anciennes",
  "No conversations match your search.": "Aucune conversation ne correspond à votre recherche.",
  "Your conversations will appear here.": "Vos conversations apparaîtront ici.",
  "Conversation history is unavailable.": "L’historique des conversations est indisponible.",
  "Load earlier messages": "Charger les messages précédents",
  "Thinking…": "Réflexion en cours…",
  "Reply unavailable · your draft is kept": "Réponse indisponible · votre brouillon est conservé",
  "Visible messages from this conversation.": "Messages affichés dans cette conversation.",
  "Make a plan": "Préparer un plan",
  "Turn an idea into clear next steps": "Passer d’une idée à des étapes concrètes",
  "Help me turn an idea into a clear plan.": "Aide-moi à transformer une idée en un plan clair.",
  "Write something": "Trouver les mots",
  "Draft, rewrite, or find the right words": "Rédiger, reformuler ou améliorer un texte",
  "Help me improve a piece of writing.": "Aide-moi à améliorer un texte.",
  "The active conversation changed. Reload it before sending.": "La conversation active a changé. Rechargez-la avant d’envoyer un message.",
  "This conversation is no longer available.": "Cette conversation n’est plus disponible.",
  "Copy code": "Copier le code",
  "Code copied.": "Code copié.",
  "Code": "Code",
  "Use again": "Réutiliser",
  // Agent run inspector.
  "Saved output": "Sortie conservée",
  "Live output": "Sortie en direct",
  "Runtime not reported": "Environnement non renseigné",
  "Runtime": "Environnement",
  "Previous run": "Exécution précédente",
  "Expand panel": "Agrandir le panneau",
  "Collapse panel": "Réduire le panneau",
  "Run sections": "Sections de l’exécution",
  "This snapshot is out of date. Current execution is unconfirmed.": "Ce relevé est ancien. L’exécution actuelle n’est pas confirmée.",
  "Manage reports a running job, but matching worker activity is not confirmed.": "Manage signale une exécution en cours, mais l’activité correspondante du worker n’est pas confirmée.",
  "Tool started": "Outil démarré",
  "Tool request": "Demande à l’outil",
  "Tool result": "Résultat de l’outil",
  "Tool finished": "Outil terminé",
  "Agent response": "Réponse de l’agent",
  "Run finished": "Exécution terminée",
  "Run failed": "Exécution en échec",
  "Run event": "Événement d’exécution",
  "This event was shortened at the source.": "Cet événement a été raccourci à la source.",
  "Status sources": "Sources de l’état",
  "Compare the latest Manage report with GitHub and the worker.": "Comparer le dernier relevé Manage avec GitHub et le worker.",
  "Failure details": "Détails de l’échec",
  "Latest activity": "Dernière activité",
  "Copy response": "Copier la réponse",
  "Response copied.": "Réponse copiée.",
  "No final response is included in this snapshot. Open GitHub or Manage for the completion report.": "Ce relevé ne contient pas de réponse finale. Consultez GitHub ou Manage pour le compte rendu.",
  "No failure details are included in this snapshot. Open Manage to investigate.": "Ce relevé ne précise pas la cause de l’échec. Consultez Manage pour l’examiner.",
  "Most recent recorded action": "Dernière action enregistrée",
  "Execution context": "Contexte d’exécution",
  "Related runs": "Exécutions liées",
  "Parent run": "Exécution parente",
  "Child run": "Sous-exécution",
  "Recent events retained by the worker; this may not be the full history.": "Événements récents conservés par le worker ; l’historique peut être incomplet.",
  "Copy output": "Copier la sortie",
  "Output copied.": "Sortie copiée.",
  "Show new activity": "Afficher les nouveaux événements",
  "Search activity…": "Rechercher dans l’activité…",
  "Search activity": "Rechercher dans l’activité",
  "Filter activity": "Filtrer l’activité",
  "All events": "Tous les événements",
  "Messages": "Messages",
  "Errors": "Erreurs",
  "Run events": "Événements d’exécution",
  "Newest first": "Plus récents d’abord",
  "Reverse activity order": "Inverser l’ordre de l’activité",
  "No events match your search.": "Aucun événement ne correspond à votre recherche.",
  "Run details": "Détails de l’exécution",
  "References": "Références",
  "Current worker": "Worker actuel",
  "Current worker configuration, not a record of this run’s model or usage.": "Configuration actuelle du worker. Le modèle et l’utilisation propres à cette exécution ne sont pas renseignés ici.",
  "Copied.": "Copié.",
  "events": "événements",
  // Ops console layout.
  "READY": "PRÊT",
  "Session": "Session",
  "Show fewer": "Afficher moins",
  "Closed": "Fermé",
  "Has a linked run": "Exécution liée",
  "Can reply": "Réponse possible",
  "Ready, sandboxed": "Prêt, isolé",
  "Sandbox ready, no agent connected": "Isolation prête, aucun agent connecté",
  "Blocked: sandbox unavailable": "Bloqué : isolation indisponible",
  "Not answering": "Ne répond pas",
  "NO REPORT YET": "PAS ENCORE DE RAPPORT",
  "Worked": "Travail",
  "Shortened by the server.": "Raccourci par le serveur.",
  "History only": "Historique seulement",
  "Can be opened": "Peut être ouverte",
  "Updated": "Mis à jour",
  "completed": "terminé",
  "unread": "non lu",
  "View": "Voir",
  "Tasks": "Tâches",
  "Agents": "Agents",
  "Health": "Santé",
  "Settings": "Réglages",
  "Assistant": "Assistant",
  "TASKS": "TÂCHES",
  "Main sections": "Sections principales",
  "Monique, open tasks": "Monique, ouvrir les tâches",
  "Search or jump to": "Rechercher ou aller à",
  "System health": "Santé du système",
  "Healthy": "En bonne santé",
  "Degraded": "Dégradé",
  "Offline": "Hors ligne",
  "conversations": "conversations",
  "workspaces": "espaces de travail",
  "Task counts": "Compteurs de tâches",
  "Describe a new task, for example: fix the contact form on regalterre.fr and test it": "Décrivez une nouvelle tâche, par exemple : corrige le formulaire de contact de regalterre.fr et teste-le",
  "Run task": "Lancer la tâche",
  "Run a task": "Lancer une tâche",
  "What should Monique do?": "Que doit faire Monique ?",
  "Ready for a new task.": "Prêt pour une nouvelle tâche.",
  "Check task status": "Vérifier l’état de la tâche",
  "Open task conversation": "Ouvrir la conversation de la tâche",
  "Monique works in a private copy. Code changes go through a ticket.": "Monique travaille dans une copie privée. Les changements de code passent par un ticket.",
  "Conversations": "Conversations",
  "Conversation": "Conversation",
  "Task": "Tâche",
  "Sync": "Synchro",
  "Reference": "Référence",
  "Status": "État",
  "Working": "En cours",
  "Idle": "Inactif",
  "Up to date": "À jour",
  "Out of date": "Pas à jour",
  "Unknown": "Inconnu",
  "Untitled task": "Tâche sans titre",
  "Updated just now": "Mis à jour à l’instant",
  "The list is not available": "La liste n’est pas disponible",
  "Not loaded yet": "Pas encore chargé",
  "Loading": "Chargement",
  "Loading conversations…": "Chargement des conversations…",
  "No conversations yet. Start a task above.": "Aucune conversation pour l’instant. Lancez une tâche ci-dessus.",
  "Workspaces": "Espaces de travail",
  "Filter workspaces": "Filtrer les espaces de travail",
  "All": "Tous",
  "Needs you": "Vous attend",
  "Needs": "Besoin",
  "Branch": "Branche",
  "Checking workspaces": "Vérification des espaces de travail",
  "Conversations stay available while this loads.": "Les conversations restent disponibles pendant le chargement.",
  "Workspaces are up to date.": "Les espaces de travail sont à jour.",
  "Some workspace details are missing.": "Certains détails des espaces de travail manquent.",
  "Workspaces are not available on this server.": "Les espaces de travail ne sont pas disponibles sur ce serveur.",
  "This data is out of date. Workspace actions are paused until it refreshes.": "Ces données ne sont pas à jour. Les actions sont en pause jusqu’à la prochaine actualisation.",
  "Projects, servers, workspaces and their status are listed below.": "Projets, serveurs, espaces de travail et leur état sont listés ci-dessous.",
  "No workspaces yet.": "Aucun espace de travail pour l’instant.",
  "No workspaces yet. Conversations above still work.": "Aucun espace de travail pour l’instant. Les conversations ci-dessus fonctionnent toujours.",
  "No workspaces match this filter.": "Aucun espace de travail ne correspond à ce filtre.",
  "No branch yet": "Pas encore de branche",
  "Projects": "Projets",
  "Servers": "Serveurs",
  "None listed.": "Aucun.",
  "Hosted workspaces": "Espaces de travail hébergés",
  "Task details": "Détails de la tâche",
  "Nothing selected": "Rien de sélectionné",
  "Close details": "Fermer les détails",
  "Close (Esc)": "Fermer (Échap)",
  "Workspace": "Espace de travail",
  "Files & review": "Fichiers et revue",
  "Activity": "Activité",
  "Selected workspace surfaces": "Vues de l’espace sélectionné",
  "No conversation open": "Aucune conversation ouverte",
  "Pick a task in the list to read its conversation.": "Choisissez une tâche dans la liste pour lire sa conversation.",
  "Close conversation": "Fermer la conversation",
  "Read only": "Lecture seule",
  "View run": "Voir l’exécution",
  "Show runs": "Voir les exécutions",
  "No messages were saved in this conversation.": "Aucun message n’a été enregistré dans cette conversation.",
  "Missing details are left blank rather than guessed, and workspace actions stay read-only.": "Les détails manquants restent vides au lieu d’être devinés, et les actions sur les espaces restent en lecture seule.",
  "Saved conversations still work.": "Les conversations enregistrées restent disponibles.",
  "Sandboxed runs, kept on disk": "Exécutions isolées, conservées sur disque",
  "Agent runs": "Exécutions d’agent",
  "Waiting for approval": "En attente d’approbation",
  "to approve": "à approuver",
  "To approve": "À approuver",
  "can change data": "modifient des données",
  "Approve in Manage ↗": "Approuver dans Manage ↗",
  "Waiting for your approval in Manage. Nothing runs until it is approved.": "En attente de votre approbation dans Manage. Rien ne s’exécute avant.",
  "Nothing runs until you approve in Manage.": "Rien ne s’exécute avant votre approbation dans Manage.",
  "Open the run to see what went wrong.": "Ouvrez l’exécution pour voir ce qui n’a pas marché.",
  "Opening…": "Ouverture…",
  "Opening conversation…": "Ouverture de la conversation…",
  "Conversation history": "Historique de la conversation",
  "Load newer messages": "Charger les nouveaux messages",
  "Reply in this conversation": "Répondre dans cette conversation",
  "Reply to Monique…": "Répondre à Monique…",
  "Send": "Envoyer",
  "Replies are checked against the latest state first.": "Chaque réponse est d’abord vérifiée avec l’état le plus récent.",
  "Up to date · reply only": "À jour · réponse seulement",
  "Out of date · reply only": "Pas à jour · réponse seulement",

  "Task completed. Its conversation is open on the right.": "Tâche terminée. Sa conversation est ouverte à droite.",
  "You": "Vous",
  "Monique started working": "Monique a commencé",
  "Monique finished": "Monique a terminé",
  "The run failed": "L’exécution a échoué",
  "The run was cancelled": "L’exécution a été annulée",
  "Waiting for your last reply to be confirmed before you can send another.": "En attente de la confirmation de votre dernière réponse avant d’en envoyer une autre.",
  "Replies are not available for this conversation right now.": "Les réponses ne sont pas disponibles pour cette conversation pour le moment.",
  "This conversation is no longer in the list.": "Cette conversation n’est plus dans la liste.",
  "Older messages were trimmed. Reloading the conversation…": "Les anciens messages ont été raccourcis. Rechargement de la conversation…",
  "Not sure your reply arrived. Checking, without sending it twice.": "Pas sûr que votre réponse soit arrivée. Vérification, sans l’envoyer deux fois.",
  "NO WORKSPACE": "AUCUN ESPACE",
  "No workspace selected": "Aucun espace de travail sélectionné",
  "Copy link": "Copier le lien",
  "Workspace status": "État de l’espace de travail",
  "OUTSIDE WORK": "TRAVAIL EXTERNE",
  "AGENT": "AGENT",
  "Not reported": "Non signalé",
  "ACTIONS": "ACTIONS",
  "Create or resume a workspace": "Créer ou reprendre un espace de travail",
  "Not available until the server answers.": "Indisponible tant que le serveur n’a pas répondu.",
  "No linked task": "Aucune tâche liée",
  "Start from": "Partir de",
  "Base branch": "Branche de base",
  "New branch": "Nouvelle branche",
  "Branch name": "Nom de la branche",
  "Creating or resuming a workspace from here is not available yet.": "Créer ou reprendre un espace de travail depuis ici n’est pas encore possible.",
  "Creating or resuming a workspace from here is not available yet. Server setup and checkout are ready.": "Créer ou reprendre un espace de travail depuis ici n’est pas encore possible. La préparation du serveur et la récupération du code sont prêtes.",
  "Creating or resuming a workspace from here is not available yet. Server setup is only partly ready.": "Créer ou reprendre un espace de travail depuis ici n’est pas encore possible. La préparation du serveur n’est que partielle.",
  "REFERENCES": "RÉFÉRENCES",
  "Workspace references": "Références de l’espace de travail",
  "Pane": "Volet",
  "Code line": "Ligne de code",
  "conversation": "conversation",
  "activity": "activité",
  "FILES": "FICHIERS",
  "REVIEW": "REVUE",
  "CHECKS": "VÉRIFICATIONS",
  "DELIVERY": "LIVRAISON",
  "Not available": "Indisponible",
  "Files and review": "Fichiers et revue",
  "Comment on a line of code": "Commenter une ligne de code",
  "Open a link to a specific line before commenting": "Ouvrez un lien vers une ligne précise avant de commenter",
  "Check to run again": "Vérification à relancer",
  "No check can be run again": "Aucune vérification ne peut être relancée",
  "No rerunnable check available": "Aucune vérification ne peut être relancée",
  "Run this check again?": "Relancer cette vérification ?",
  "Confirm": "Confirmer",
  "Review actions need fresh data first.": "Les actions de revue nécessitent d’abord des données à jour.",
  "To comment, open a link to a specific line of code first.": "Pour commenter, ouvrez d’abord un lien vers une ligne de code précise.",
  "You can run the selected check again.": "Vous pouvez relancer la vérification sélectionnée.",
  "Only the review actions this server offers are shown.": "Seules les actions de revue proposées par ce serveur sont affichées.",
  "Waiting for your last action to be confirmed. New actions are paused.": "En attente de la confirmation de votre dernière action. Les nouvelles actions sont en pause.",
  "Workspace activity": "Activité de l’espace de travail",
  "Items that need you": "Éléments qui vous attendent",
  "Nothing needs you": "Rien ne vous attend",
  "This workspace has no open requests.": "Cet espace de travail n’a aucune demande en cours.",
  "Recent activity": "Activité récente",
  "Recent workspace activity": "Activité récente de l’espace de travail",
  "No activity yet": "Aucune activité pour l’instant",
  "The conversation keeps the full history.": "La conversation garde tout l’historique.",
  "Open exact context": "Ouvrir le contexte",
  "Open exact attention context": "Ouvrir le contexte",
  "GENERAL HELP": "AIDE GÉNÉRALE",
  "Ask anything about Monique. For work on a task, reply inside that task instead.": "Posez n’importe quelle question sur Monique. Pour le travail sur une tâche, répondez plutôt dans cette tâche.",
  "Back to tasks": "Retour aux tâches",
  "General assistant": "Assistant général",
  "Mode": "Mode",
  "Ask naturally. I can use what I remember, read connected tools, and prepare actions for your approval.": "Demandez naturellement. Je peux utiliser ce dont je me souviens, lire les outils connectés et préparer des actions pour votre approbation.",
  "Live status and risks": "État en direct et risques",
  "Recent Slack messages": "Messages Slack récents",
  "What Monique remembers": "Ce dont Monique se souvient",
  "Prepare an action for approval": "Préparer une action à approuver",
  "Monique can make mistakes. Answers show when they rely on memory or live sources. Voice uses your browser and starts only when you press a voice button.": "Monique peut se tromper. Les réponses indiquent quand elles s’appuient sur la mémoire ou des sources en direct. La voix utilise votre navigateur et ne démarre que lorsque vous appuyez sur un bouton vocal.",
  "Agent counts": "Compteurs des agents",
  "running": "en cours",
  "waiting": "en attente",
  "finished": "terminées",
  "failed": "en échec",
  "tools": "outils",
  "read only": "lecture seule",
  "need approval": "à approuver",
  "waiting for you": "vous attendent",
  "Open Manage ↗": "Ouvrir Manage ↗",
  "Connecting to Support and Manage": "Connexion à Support et Manage",
  "Looking for available tools…": "Recherche des outils disponibles…",
  "CHECKING": "VÉRIFICATION",
  "Support and Manage are connected": "Support et Manage sont connectés",
  "Monique can see their tools and tickets.": "Monique voit leurs outils et leurs tickets.",
  "Only part of Support and Manage is connected": "Support et Manage ne sont que partiellement connectés",
  "One service needs attention. The other still works.": "Un service demande votre attention. L’autre fonctionne toujours.",
  "Support and Manage are not connected": "Support et Manage ne sont pas connectés",
  "Connect them in the server settings to see tools and tickets.": "Connectez-les dans les réglages du serveur pour voir outils et tickets.",
  "Support and Manage are not answering": "Support et Manage ne répondent pas",
  "They did not send a usable list of tools.": "Ils n’ont pas envoyé de liste d’outils exploitable.",
  "Support and Manage are busy": "Support et Manage sont occupés",
  "Another request is using them. Try again in a moment.": "Une autre requête les utilise. Réessayez dans un instant.",
  "Connection state unknown": "État de connexion inconnu",
  "Refresh to check again.": "Actualisez pour vérifier à nouveau.",
  "CONNECTED": "CONNECTÉ",
  "NOT CONNECTED": "NON CONNECTÉ",
  "Agent runs": "Exécutions d’agents",
  "Waiting for the worker": "En attente du worker",
  "Loading the worker…": "Chargement du worker…",
  "Filter agent runs": "Filtrer les exécutions",
  "Running": "En cours",
  "Waiting": "En attente",
  "Failed": "Échec",
  "Finished": "Terminé",
  "Connecting…": "Connexion…",
  "Queued in Manage means waiting for a worker. Only Running means an agent is executing.": "En file dans Manage signifie en attente d’un worker. Seul En cours signifie qu’un agent travaille.",
  "Queued": "En file",
  "queued": "en file",
  "Run": "Exécution",
  "Agent": "Agent",
  "Updated": "Mis à jour",
  "State": "État",
  "Loading agent runs…": "Chargement des exécutions…",
  "No agent runs to show yet.": "Aucune exécution à afficher pour l’instant.",
  "No agent runs match this filter.": "Aucune exécution ne correspond à ce filtre.",
  "No worker has reported in yet.": "Aucun worker ne s’est encore signalé.",
  "Model": "Modèle",
  "Busy": "Occupation",
  "Seen": "Vu",
  "Issue": "Ticket",
  "Subtask": "Sous-tâche",
  "Tools Monique can use": "Outils que Monique peut utiliser",
  "Read-only tools run right away. Anything that changes data is shown to you first and runs only after you approve it.": "Les outils en lecture seule s’exécutent tout de suite. Tout ce qui modifie des données vous est d’abord montré et ne s’exécute qu’après votre approbation.",
  "Tool": "Outil",
  "Service": "Service",
  "Access": "Accès",
  "Input": "Saisie",
  "Loading tools…": "Chargement des outils…",
  "No tools are connected yet.": "Aucun outil n’est encore connecté.",
  "Needs approval": "À approuver",
  "Needs details": "Détails requis",
  "Ready": "Prêt",
  "Ask the assistant which tool to use →": "Demander à l’assistant quel outil utiliser →",
  "Connected service tool.": "Outil d’un service connecté.",
  "Monique can use this right away. It only reads data.": "Monique peut l’utiliser tout de suite. Il ne fait que lire des données.",
  "This changes data. Monique shows you exactly what it will do and waits for your approval.": "Ceci modifie des données. Monique vous montre exactement ce qu’elle va faire et attend votre approbation.",
  "Use with assistant": "Utiliser avec l’assistant",
  "Category": "Catégorie",
  "Server": "Serveur",
  "Technical name": "Nom technique",
  "Agent details": "Détails de l’agent",
  "Agent run": "Exécution d’agent",
  "Approved": "Approuvé",
  "Part of a larger run": "Fait partie d’une exécution plus large",
  "Waiting for a free agent to pick it up.": "En attente qu’un agent libre la prenne en charge.",
  "An agent is working on this right now.": "Un agent y travaille en ce moment.",
  "The agent finished this run.": "L’agent a terminé cette exécution.",
  "This run failed. Check the output below, then retry from Manage.": "Cette exécution a échoué. Consultez la sortie ci-dessous, puis relancez depuis Manage.",
  "This run was cancelled.": "Cette exécution a été annulée.",
  "No output from the agent yet.": "Aucune sortie de l’agent pour l’instant.",
  "CUT SHORT": "TRONQUÉ",
  "Came from": "Provenance",
  "On this worker": "Sur ce worker",
  "Decisions": "Décisions",
  "Run ID": "ID d’exécution",
  "Part of": "Fait partie de",
  "Ticket ID": "ID du ticket",
  "Yes": "Oui",
  "No": "Non",
  "total": "au total",
  "open": "ouverts",
  "in progress": "en cours",
  "blocked": "bloqués",
  "urgent": "urgents",
  "Ask assistant": "Demander à l’assistant",
  "Ask assistant →": "Demander à l’assistant →",
  "Filter by source": "Filtrer par source",
  "Filter by status": "Filtrer par état",
  "Any status": "Tous les états",
  "In progress": "En cours",
  "Urgent": "Urgent",
  "Search tickets": "Rechercher des tickets",
  "Filter by title, client, site, person": "Filtrer par titre, client, site, personne",
  "Clear search": "Effacer la recherche",
  "Sort by": "Trier par",
  "Waiting for Support and Manage": "En attente de Support et Manage",
  "Loading tickets…": "Chargement des tickets…",
  "ID": "ID",
  "Title": "Titre",
  "Source": "Source",
  "Priority": "Priorité",
  "Assignee": "Responsable",
  "Ticket details": "Détails du ticket",
  "Ticket": "Ticket",
  "Other": "Autre",
  "Review with assistant": "Examiner avec l’assistant",
  "Conversation": "Conversation",
  "Loading the conversation…": "Chargement de la conversation…",
  "This conversation was not found at its source.": "Cette conversation est introuvable dans sa source.",
  "This source does not allow reading the conversation here.": "Cette source ne permet pas de lire la conversation ici.",
  "The conversation could not be loaded right now.": "La conversation n’a pas pu être chargée pour le moment.",
  "No messages in this conversation.": "Aucun message dans cette conversation.",
  "Older messages are not shown.": "Les messages plus anciens ne sont pas affichés.",
  "Unknown sender": "Expéditeur inconnu",
  "Internal note": "Note interne",
  "Message shortened": "Message raccourci",
  "Assigned to": "Attribué à",
  "Requested by": "Demandé par",
  "Client": "Client",
  "Site": "Site",
  "Comments": "Commentaires",
  "Created": "Créé",
  "No tickets right now.": "Aucun ticket pour le moment.",
  "Support and Manage are connected but cannot list tickets.": "Support et Manage sont connectés mais ne peuvent pas lister les tickets.",
  "Monique needs more details to list these tickets. Ask the assistant.": "Monique a besoin de plus de détails pour lister ces tickets. Demandez à l’assistant.",
  "Tickets are not available right now.": "Les tickets ne sont pas disponibles pour le moment.",
  "One source is down. Tickets from the other are shown below.": "Une source est indisponible. Les tickets de l’autre sont affichés ci-dessous.",
  "Connect Support and Manage to see tickets here.": "Connectez Support et Manage pour voir les tickets ici.",
  "No tickets match these filters.": "Aucun ticket ne correspond à ces filtres.",
  "Tickets are not available right now": "Les tickets ne sont pas disponibles pour le moment",
  "Memory counts": "Compteurs de la mémoire",
  "in use": "utilisés",
  "to approve": "à approuver",
  "to recheck": "à revérifier",
  "replaced": "remplacés",
  "deleted": "supprimés",
  "messages": "messages",
  "Search memory": "Rechercher dans la mémoire",
  "Search what Monique remembers": "Rechercher ce dont Monique se souvient",
  "Memory view": "Vue de la mémoire",
  "List": "Liste",
  "Timeline": "Chronologie",
  "Map": "Carte",
  "All types": "Tous les types",
  "Privacy": "Confidentialité",
  "Most certain": "Les plus sûrs",
  "Recheck date": "Date de revérification",
  "Reset": "Réinitialiser",
  "Loading…": "Chargement…",
  "Searching…": "Recherche…",
  "Memory map": "Carte de la mémoire",
  "Memory details": "Détails du souvenir",
  "Pick a memory": "Choisissez un souvenir",
  "Select a row to see where it came from and when to recheck it.": "Sélectionnez une ligne pour voir d’où elle vient et quand la revérifier.",
  "Certainty": "Certitude",
  "Recheck": "À revérifier",
  "How sure Monique is": "Degré de certitude de Monique",
  "Learned from": "Appris de",
  "Visible to": "Visible par",
  "Version": "Version",
  "Not scheduled": "Non planifié",
  "Nothing matches these filters.": "Rien ne correspond à ces filtres.",
  "Preference": "Préférence",
  "Fact": "Fait",
  "Procedure": "Procédure",
  "Decision": "Décision",
  "Active": "Actif",
  "Candidate": "Proposition",
  "Superseded": "Remplacé",
  "Deleted": "Supprimé",
  "preference": "préférence",
  "fact": "fait",
  "procedure": "procédure",
  "decision": "décision",
  "Internal": "Interne",
  "Confidential": "Confidentiel",
  "Public": "Public",
  "Operator": "Opérateur",
  "Live counters": "Compteurs en direct",
  "waiting to start": "en attente de démarrage",
  "waiting to send": "en attente d’envoi",
  "to double-check": "à revérifier",
  "unclear result": "résultat incertain",
  "to fix": "à corriger",
  "Pair a phone": "Associer un téléphone",
  "Open tasks": "Ouvrir les tâches",
  "Checking": "Vérification",
  "Waiting for the first status update.": "En attente de la première mise à jour d’état.",
  "Problems": "Problèmes",
  "Everything is running normally": "Tout fonctionne normalement",
  "Agents, new work and deliveries all look fine.": "Agents, nouvelles demandes et envois : tout va bien.",
  "How work flows": "Comment le travail avance",
  "Work flow": "Flux de travail",
  "Received": "Reçu",
  "Saved and waiting": "Enregistré, en attente",
  "Agents at work": "Agents au travail",
  "Sending": "Envoi",
  "Results going out": "Résultats en cours d’envoi",
  "Double-check": "Revérification",
  "Results to confirm": "Résultats à confirmer",
  "ACTIVE": "ACTIF",
  "CLEAR": "RAS",
  "WAIT": "ATTENTE",
  "CHECK": "À VÉRIFIER",
  "ALL GOOD": "TOUT VA BIEN",
  "System": "Système",
  "Monique": "Monique",
  "AI provider": "Fournisseur d’IA",
  "Accepting new work": "Accepte de nouvelles demandes",
  "Status data": "Données d’état",
  "Available": "Disponible",
  "Unavailable": "Indisponible",
  "Activity since you opened this page": "Activité depuis l’ouverture de cette page",
  "Recent activity levels": "Niveaux d’activité récents",
  "Running work, waiting to start, and waiting to send, as seen by this browser.": "Travail en cours, en attente de démarrage et en attente d’envoi, vus par ce navigateur.",
  "Waiting to start": "En attente de démarrage",
  "Waiting to send": "En attente d’envoi",
  "Samples": "Échantillons",
  "Window": "Fenêtre",
  "Last change": "Dernier changement",
  "Ask the assistant": "Demander à l’assistant",
  "Monique is not fully healthy": "Monique n’est pas en pleine forme",
  "Status is out of date": "L’état n’est pas à jour",
  "This page has not received a recent status update.": "Cette page n’a pas reçu de mise à jour récente.",
  "Results need a double-check": "Des résultats sont à revérifier",
  "Some messages may not have been sent": "Certains messages n’ont peut-être pas été envoyés",
  "AI provider unavailable": "Fournisseur d’IA indisponible",
  "Monique cannot reach its AI provider.": "Monique ne parvient pas à joindre son fournisseur d’IA.",
  "Not accepting new work": "N’accepte plus de nouvelles demandes",
  "Monique is not taking new requests right now.": "Monique ne prend pas de nouvelles demandes pour le moment.",
  "Agent list is out of date": "La liste des agents n’est pas à jour",
  "The list of agent runs has not refreshed recently.": "La liste des exécutions ne s’est pas actualisée récemment.",
  "Open it in Manage to see what went wrong.": "Ouvrez-la dans Manage pour voir ce qui n’a pas marché.",
  "NO SECRETS SHOWN": "AUCUN SECRET AFFICHÉ",
  "Settings summary": "Résumé des réglages",
  "This browser": "Ce navigateur",
  "Manage": "Manage",
  "Connections": "Connexions",
  "Agent sign-in": "Connexion des agents",
  "Not connected": "Non connecté",
  "Settings sections": "Sections des réglages",
  "Search settings": "Rechercher un réglage",
  "Filter settings": "Filtrer les réglages",
  "All settings": "Tous les réglages",
  "AI and agents": "IA et agents",
  "Security": "Sécurité",
  "Passwords and keys are never shown here. Only names and on/off states are.": "Les mots de passe et clés ne sont jamais affichés ici. Seuls les noms et les états activé ou désactivé le sont.",
  "Look and feel": "Apparence",
  "Saved in this browser and applied right away.": "Enregistré dans ce navigateur et appliqué immédiatement.",
  "Theme": "Thème",
  "Colours of the whole app": "Couleurs de toute l’application",
  "Language": "Langue",
  "Labels and menus": "Libellés et menus",
  "Text size": "Taille du texte",
  "Applies everywhere": "S’applique partout",
  "Spacing": "Espacement",
  "How tight lists are": "Densité des listes",
  "Start page": "Page de démarrage",
  "What opens first": "Ce qui s’ouvre en premier",
  "Reduce motion": "Réduire les animations",
  "Fewer animations": "Moins d’animations",
  "Assistant and refresh": "Assistant et actualisation",
  "How the assistant answers and how often data updates.": "Comment l’assistant répond et à quelle fréquence les données s’actualisent.",
  "Assistant mode": "Mode de l’assistant",
  "For new conversations": "Pour les nouvelles conversations",
  "Refresh every": "Actualiser toutes les",
  "While this tab is open": "Tant que cet onglet est ouvert",
  "Technical details": "Détails techniques",
  "Show limits and internal values": "Afficher les limites et valeurs internes",
  "Alerts": "Alertes",
  "Notify me when a new problem appears": "Me prévenir quand un nouveau problème apparaît",
  "Agent accounts": "Comptes des agents",
  "Sign agents in with your Claude or ChatGPT subscription. No API keys needed.": "Connectez les agents avec votre abonnement Claude ou ChatGPT. Aucune clé d’API nécessaire.",
  "Loading accounts…": "Chargement des comptes…",
  "Each account is kept separate. Monique only switches the worker account when you ask.": "Chaque compte reste séparé. Monique ne change le compte de l’agent qu’à votre demande.",
  "System settings": "Réglages du système",
  "Read from the running server. Change them on the server.": "Lus sur le serveur en marche. Modifiez-les sur le serveur.",
  "Loading settings…": "Chargement des réglages…",
  "No matching settings": "Aucun réglage correspondant",
  "Try another word or section.": "Essayez un autre mot ou une autre section.",
  "Web access": "Accès web",
  "AI providers": "Fournisseurs d’IA",
  "Safety": "Sécurité",
  "Extensions": "Extensions",
  "Who can reach this page and request limits.": "Qui peut accéder à cette page et limites des requêtes.",
  "How Monique stores and finds what it remembers.": "Comment Monique stocke et retrouve ce dont elle se souvient.",
  "Whether agents are signed in and ready to work.": "Si les agents sont connectés et prêts à travailler.",
  "The AI models Monique uses.": "Les modèles d’IA utilisés par Monique.",
  "Slack, Telegram, GitHub and other connections.": "Slack, Telegram, GitHub et autres connexions.",
  "Tools and tickets from Manage.": "Outils et tickets de Manage.",
  "Approvals, audit log and backups.": "Approbations, journal d’audit et sauvegardes.",
  "Extra tools, knowledge and automations.": "Outils, connaissances et automatisations supplémentaires.",
  "On": "Activé",
  "Off": "Désactivé",
  "ON": "ACTIVÉ",
  "OFF": "DÉSACTIVÉ",
  "From the server · no secrets": "Depuis le serveur · aucun secret",
  "Mobile": "Mobile",
  "Conversations this phone may open": "Conversations que ce téléphone peut ouvrir",
  "Choose this phone’s access.": "Choisissez les accès de ce téléphone.",
  "Create an invite to display its QR code.": "Créez une invitation pour afficher son QR code.",
  "In the Monique app, open pairing and scan the code.": "Dans l’application Monique, ouvrez l’association et scannez le code.",
  "Phone access": "Accès du téléphone",
  "Selected conversations": "Conversations sélectionnées",
  "Administrator — all conversations": "Administrateur — toutes les conversations",
  "Includes all current and future conversations on this Monique instance. Task creation and ticket management remain separate permissions. Requires an app version that supports administrator pairing.": "Inclut toutes les conversations actuelles et futures de cette instance Monique. La création de tâches et la gestion des tickets restent des autorisations distinctes. Nécessite une version de l’application compatible avec l’association administrateur.",
  "Select the conversations this phone can read and continue. New conversations are not included.": "Sélectionnez les conversations que ce téléphone peut lire et poursuivre. Les nouvelles conversations ne sont pas incluses.",
  "Download QR code": "Télécharger le QR code",
  "Change access": "Modifier les accès",
  "Create another invite": "Créer une autre invitation",
  "This invite works once and expires after five minutes, including downloaded copies. Keep it private.": "Cette invitation est à usage unique et expire après cinq minutes, y compris les copies téléchargées. Gardez-la privée.",
  "An invite works once and lasts five minutes. Create it with the phone already in your hand.": "Une invitation ne sert qu’une fois et dure cinq minutes. Créez-la avec le téléphone déjà en main.",
  "Every listed conversation is selected. The phone can only reach the ones named here.": "Chaque conversation listée est sélectionnée. Le téléphone ne peut atteindre que celles nommées ici.",
  "Allow this phone to read the Slack channel and submit, approve or reject Manage tickets": "Autoriser ce téléphone à lire le canal Slack et à soumettre, approuver ou refuser les tickets Manage",
  "Allow this phone to start tasks and continue the ones it creates": "Autoriser ce téléphone à lancer des tâches et à poursuivre celles qu’il crée",
  "Reset to defaults": "Rétablir les valeurs par défaut",
  "Saved only in this browser.": "Enregistré uniquement dans ce navigateur.",
  "Command palette": "Palette de commandes",
  "Type a command or search…": "Tapez une commande ou une recherche…",
  "Type a command or search": "Tapez une commande ou une recherche",
  "Commands": "Commandes",
  "move": "déplacer",
  "run": "exécuter",
  "move in lists": "se déplacer dans les listes",
  "Go to": "Aller à",
  "Actions": "Actions",
  "Search": "Rechercher",
  "Tickets": "Tickets",
  "New task": "Nouvelle tâche",
  "Refresh": "Actualiser",
  "Switch to light theme": "Passer au thème clair",
  "Switch to dark theme": "Passer au thème sombre",
  "Use the system theme": "Utiliser le thème du système",
  "Appearance settings": "Réglages d’apparence",
  "No matching command": "Aucune commande correspondante",
  "Search tickets for": "Rechercher dans les tickets :",
  "Search memory for": "Rechercher dans la mémoire :",
  "Ask the assistant:": "Demander à l’assistant :",
  "Memory": "Mémoire",
});
const localizedTextSources = new WeakMap();
const localizedAttributeSources = new WeakMap();
const localizedAttributes = ["aria-label", "placeholder", "title", "data-chat-prompt", "data-open-chat"];
let localizingUi = false;

function translatePhraseForFrench(value) {
  const source = String(value);
  if (frenchUi[source]) return frenchUi[source];
  const replacements = [
    [/^Saved output · (.+) events$/, (match) => `Sortie conservée · ${match[1]} événements`],
    [/^Edit (M-\d+)$/, (match) => `Modifier ${match[1]}`],
    [/^(Approve|Reject|Forget) (M-\d+)\?$/, (match) => `${{ Approve: "Approuver", Reject: "Rejeter", Forget: "Oublier" }[match[1]]} ${match[2]} ?`],
    [/^(\d+) memories exported\. This is a filtered export, not a database backup\.$/, (match) => `${match[1]} souvenirs exportés. Cet export filtré n’est pas une sauvegarde de la base de données.`],

    [/^Appearance\. Current theme: (.+)$/, (match) => `Apparence. Thème actuel : ${translatePhraseForFrench(match[1])}`],
    [/^Appearance · (.+)$/, (match) => `Apparence · ${translatePhraseForFrench(match[1])}`],
    [/^Text size: (.+)\. Increase text size$/, (match) => `Taille du texte : ${translatePhraseForFrench(match[1])}. Augmenter la taille du texte`],
    [/^(\S+) agent runs? waits? for your approval$/, (match) => `${match[1]} exécution${match[1] === "1" ? "" : "s"} d’agent attend${match[1] === "1" ? "" : "ent"} votre approbation`],
    [/^Worked: (.+) · (\d+) steps?$/, (match) => `Travail : ${match[1]} · ${match[2]} étape${match[2] === "1" ? "" : "s"}`],
    [/^Working · (\d+) steps?$/, (match) => `En cours · ${match[1]} étape${match[1] === "1" ? "" : "s"}`],
    [/^Updated (.+)$/, (match) => `Mis à jour ${translatePhraseForFrench(match[1])}`],
    [/^(\d+) items? needs? attention$/, (match) => `${match[1]} élément${match[1] === "1" ? " requiert" : "s requièrent"} votre attention`],
    [/^(.+?) of (.+?) runs$/, (match) => `${match[1]} exécution${match[1] === "1" ? "" : "s"} sur ${match[2]}`],
    [/^(\d+)% sure · (.+)$/, (match) => `sûr à ${match[1]} % · ${match[2]}`],
    [/^(\d+) comments$/, (match) => `${match[1]} commentaires`],
    [/^Open ([A-Z]+-\d+)$/, (match) => `Ouvrir ${match[1]}`],
    [/^Open in (.+) ↗$/, (match) => `Ouvrir dans ${translatePhraseForFrench(match[1])} ↗`],
    [/^(.+) ticket · (.+)$/, (match) => `Ticket ${translatePhraseForFrench(match[1])} · ${match[2]}`],
    [/^(.+) tool · (.+)$/, (match) => `Outil ${translatePhraseForFrench(match[1])} · ${translatePhraseForFrench(match[2])}`],
    [/^Agent run · (.+)$/, (match) => `Exécution d’agent · ${translatePhraseForFrench(match[1])}`],
    [/^Agent run (.+) failed$/, (match) => `L’exécution d’agent ${match[1]} a échoué`],
    [/^Live output · (.+) events$/, (match) => `Sortie en direct · ${match[1]} événements`],
    [/^Ready to reply \(version (\d+)\)\.$/, (match) => `Prêt à répondre (version ${match[1]}).`],
    [/^You can reply\. Monique continues this task with your message\. \(version (\d+)\)$/, (match) => `Vous pouvez répondre. Monique poursuit cette tâche avec votre message. (version ${match[1]})`],
    [/^(\d+) \/ (\d+) accounts$/, (match) => `${match[1]} / ${match[2]} comptes`],
    [/^(\S+) (memory|memories)(?: for “(.+)”)?$/, (match) => `${match[1]} souvenir${match[2] === "memory" ? "" : "s"}${match[3] ? ` pour « ${match[3]} »` : ""}`],
    [/^(Live|Saved history)(?: · (\d+) to approve)?$/, (match) => `${match[1] === "Live" ? "En direct" : "Historique enregistré"}${match[2] ? ` · ${match[2]} à approuver` : ""}`],
    [/^Show all \((\d+)\)$/, (match) => `Tout afficher (${match[1]})`],
    [/^Show earlier \((\d+)\)$/, (match) => `Afficher les précédents (${match[1]})`],
    [/^Could not open · (.+)$/, (match) => `Ouverture impossible · ${match[1]}`],
    [/^Conversation not available: (.+)$/, (match) => `Conversation indisponible : ${match[1]}`],
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
  if (!response.ok) throw new Error(payload.error?.code || payload.error || `HTTP ${response.status}`);
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
  const add = (key, title, detail, href = null, processId = null, processFilterName = null) => {
    if (!items.some((item) => item.key === key)) items.push({ key, title, detail, href, processId, processFilterName });
  };
  if (status.health !== "operational") add("runtime", "Monique is not fully healthy", `Current state: ${status.health || "unavailable"}.`);
  if (status.stale) add("stale", "Status is out of date", "This page has not received a recent status update.");
  if ((status.reconciliation_pending || 0) > 0) add("reconciliation", "Results need a double-check", `${count(status.reconciliation_pending)} result(s) need to be confirmed.`);
  if ((status.outbox_ambiguous || 0) > 0) add("ambiguous", "Some messages may not have been sent", `${count(status.outbox_ambiguous)} message(s) have an unclear delivery result.`);
  if (status.provider_available === false) add("provider", "AI provider unavailable", "Monique cannot reach its AI provider.");
  if (status.accepting_intake === false) add("intake", "Not accepting new work", "Monique is not taking new requests right now.");
  if (processesSnapshot && processesSnapshot.health !== "unavailable" && !processSnapshotIsFresh()) add("manage-stale", "Agent list is out of date", "The list of agent runs has not refreshed recently.");
  const manageJobs = Array.isArray(processesSnapshot?.jobs) && processSnapshotIsFresh() ? processesSnapshot.jobs : [];
  const awaitingApproval = manageJobs.filter((job) => job.status === "pending_approval");
  if (awaitingApproval.length > 0) {
    add(
      "manage:approval",
      `${count(awaitingApproval.length)} agent run${awaitingApproval.length === 1 ? " waits" : "s wait"} for your approval`,
      "Nothing runs until you approve in Manage.",
      safeTicketLink(awaitingApproval[0].manage_url),
      null,
      "approval",
    );
  }
  manageJobs.filter((job) => job.status === "failed").slice(0, 5).forEach((job) => {
    add(
      `manage:${job.id}`,
      `Agent run ${shortProcessReference(job.id)} failed`,
      "Open the run to see what went wrong.",
      safeTicketLink(job.manage_url) || safeTicketLink(job.issue_url),
      job.id,
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
  byId("attention-title").textContent = items.length === 0 ? "Everything is running normally" : `${items.length} item${items.length === 1 ? " needs" : "s need"} attention`;
  byId("attention-bar").dataset.state = items.length === 0 ? "clear" : "attention";
  byId("attention-detail").textContent = items.length === 0 ? "Agents, new work and deliveries all look fine." : items.map((item) => translatePhrase(item.title)).join(" · ");
  setMetric("metric-attention", items.length);
  const list = byId("attention-list");
  list.replaceChildren();
  items.forEach((item) => {
    const row = document.createElement("li");
    const title = document.createElement("strong");
    title.textContent = item.title;
    const detail = document.createElement("span");
    detail.textContent = item.detail;
    row.append(title, detail);
    if (item.processFilterName) {
      const show = document.createElement("button");
      show.type = "button";
      show.className = "button ghost small";
      show.textContent = "Show runs";
      show.addEventListener("click", () => {
        window.location.hash = "#operations";
        window.setTimeout(() => setProcessFilter(item.processFilterName), 0);
      });
      row.append(show);
    }
    if (item.processId) {
      // Always reachable in the dashboard, even when Manage gave no link.
      const open = document.createElement("button");
      open.type = "button";
      open.className = "button ghost small";
      open.textContent = "View run";
      open.addEventListener("click", () => {
        window.location.hash = "#operations";
        window.setTimeout(() => consoleOpenProcess(item.processId), 0);
      });
      row.append(open);
    }
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
  if (danger && value > 0) return "CHECK";
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

// Zero counters recede so a non-zero one stands out.
function setMetric(id, value) {
  const element = byId(id);
  element.textContent = count(value);
  const card = element.closest("article");
  if (card) card.dataset.zero = String(value === 0);
}

// The daemon's state names are precise but internal; show what they mean.
const EXECUTION_STATES = {
  sandbox_enforceable_lane_wired: ["Ready, sandboxed", "ok"],
  sandbox_enforceable_no_lane: ["Sandbox ready, no agent connected", "warn"],
  sandbox_unavailable_lane_wired: ["Blocked: sandbox unavailable", "bad"],
  sandbox_unavailable_no_lane: ["Off", "warn"],
};
const TELEGRAM_STATES = {
  polling_live: ["Connected", "ok"],
  lease_owned_no_client: ["Not answering", "warn"],
  disabled_no_client: ["Off", "muted"],
};

function setRuntimeFact(id, known, raw) {
  const element = byId(id);
  element.textContent = known ? known[0] : words(raw);
  element.dataset.tone = known ? known[1] : "";
  element.title = raw ? String(raw) : "";
}

function renderStatus(status) {
  lastStatusSnapshot = status;
  const health = ["operational", "degraded", "unavailable"].includes(status.health) ? status.health : "unavailable";
  document.documentElement.dataset.health = health;
  const issues = renderAttention(status);
  byId("global-health").textContent = { operational: "Healthy", degraded: "Degraded", unavailable: "Offline" }[health];
  byId("generation").textContent = `GEN ${count(status.generation)}`;
  byId("footer-state").textContent = `${health.toUpperCase()} / GEN ${count(status.generation)}`;
  setMetric("metric-running", status.running);
  setMetric("metric-inbox", status.inbox_pending);
  setMetric("metric-outbox", status.outbox_pending);
  setMetric("metric-reconciliation", status.reconciliation_pending);
  setMetric("metric-ambiguous", status.outbox_ambiguous);
  byId("runtime-daemon").textContent = words(status.state);
  byId("runtime-provider").textContent = status.provider_available === true ? "Available" : status.provider_available === false ? "Unavailable" : "-";
  byId("runtime-intake").textContent = status.accepting_intake === true ? "Yes" : status.accepting_intake === false ? "No" : "-";
  setRuntimeFact("runtime-execution", EXECUTION_STATES[status.execution_state], status.execution_state);
  setRuntimeFact("runtime-telegram", TELEGRAM_STATES[status.telegram_state], status.telegram_state);
  byId("runtime-snapshot").textContent = status.stale ? "Out of date" : "Up to date";
  byId("runtime-tag").textContent = issues.length === 0 ? "ALL GOOD" : "CHECK";
  byId("runtime-tag").dataset.state = issues.length === 0 ? "operational" : "degraded";
  const pipeline = [
    ["inbox", status.inbox_pending, false],
    ["running", status.running, false],
    ["outbox", status.outbox_pending, false],
    ["reconcile", status.reconciliation_pending, true],
  ];
  pipeline.forEach(([name, value, danger]) => {
    byId(`pipe-${name}`).textContent = `${count(value)} ${name === "running" ? "active" : "pending"}`;
    byId(`pipe-${name}-state`).textContent = pipelineState(value, danger);
    byId(`pipe-${name}-state`).dataset.state = pipelineState(value, danger).toLowerCase();
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

let artifactLibrary = null, artifactModal = null, artifactPublicBase = "";
async function artifactApi(body) {
  const result = await api("/api/artifacts", {method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
  if(result.public_base)artifactPublicBase=result.public_base;
  return result;
}
function artifactOptions(context={}) {
  const options={context,compact:true,previewUrl:"/artifact-preview",publicBase:artifactPublicBase,
    api:async body=>{const result=await artifactApi(body);options.publicBase=artifactPublicBase;if(body.action==="list" && (context.run_id || context.conversation_id))result.items=(result.items||[]).filter(a=>context.run_id?a.run_id===context.run_id:a.conversation_id===context.conversation_id);return result;},
    onRevise:reviseArtifact,
    getJob:async id=>(await integrationApi({section:"jobs",action:"get",id})).job,
    renderAnswer:renderMarkdown,
    revisionError:error=>humanChatError(error.message),
    onConversation:async id=>{if(chatBusy||chatUi.loading)throw Error("chat_lane_busy");byId("artifact-dialog").close();showView("chat");await selectChatConversation(id);}};
  return options;
}
async function reviseArtifact(artifact,version,request) {
  const key=request.idempotencyKey || crypto.randomUUID();
  const result=await integrationApi({section:"jobs",action:"submit",idempotency_key:key,prompt:request.message,project:artifact.project||"General",title:artifact.title,artifact_id:artifact.id,version:version.number,path:request.file});
  return {answer:"Demande enregistrée. Monique préparera une nouvelle version ; vous pouvez fermer cette page.",job:result.job};
}
function mountArtifactLibrary(id,revise=false){artifactLibrary?.destroy();artifactLibrary=window.ArtifactWorkspace.mount(byId("artifact-library"),{...artifactOptions(),onOpen:a=>history.replaceState(null,"",`#artifacts?artifact=${encodeURIComponent(a.id)}`),onLibrary:()=>history.replaceState(null,"","#artifacts"),...(id?{id,revise}:{})});}
function openArtifact(id,context={}){artifactModal?.destroy();const dialog=byId("artifact-dialog");if(!dialog.open)dialog.showModal();artifactModal=window.ArtifactWorkspace.mount(byId("artifact-dialog-content"),{...artifactOptions(context),...(id?{id}:{})});}
function artifactCard(a){const root=controlNode("div",undefined,"aw aw-inline");root.dataset.i18nSkip="";const button=controlButton("",()=>openArtifact(a.id));button.append(controlData("strong",a.title),controlData("small",` · v${a.version_count} · ${a.visibility==="public"?"Public":"Privé"}`));root.append(button);return root;}
function artifactRunPane(job){const root=controlNode("section",undefined,"run-section");root.append(controlNode("h3","Deliverables"));const list=controlNode("div");root.append(list,controlButton("Deliverables",()=>openArtifact(null,{run_id:job.id,issue_url:processIssueReference(job).href||"",agent:job.provider||""})));
  artifactApi({action:"list"}).then(data=>{if(!root.isConnected)return;const items=(data.items||[]).filter(a=>a.run_id===job.id);list.replaceChildren(...items.map(artifactCard));if(!items.length)list.append(controlNode("p","No deliverables attached to this run yet.","inline-hint"));}).catch(()=>{if(root.isConnected)list.append(controlNode("p","Deliverables are unavailable.","inline-hint"));});return root;
}
function appendArtifactReferences(root,content){const ids=new Set([...String(content).matchAll(/(?:MONIQUE_ARTIFACT_ID:\s*|\/artifacts\?id=)([A-Za-z0-9_-]{24})(?![A-Za-z0-9_-])/g)].map(m=>m[1]));for(const id of ids){const card=controlNode("div",undefined,"aw aw-inline");card.append(controlButton("Open deliverable",()=>openArtifact(id)));root.append(card);}}
async function loadConversationArtifacts(){const id=chatUi.id;if(!id)return;try{const data=await artifactApi({action:"list"});if(id!==chatUi.id)return;byId("chat-linked-artifacts")?.remove();const items=(data.items||[]).filter(a=>a.conversation_id===id);if(items.length){const root=controlNode("div",undefined,"chat-linked-artifacts");root.id="chat-linked-artifacts";root.append(...items.map(artifactCard));byId("chat-thread").append(root);}}catch(_error){/* A separate service outage must not interrupt a conversation. */}}
byId("artifact-dialog-close").addEventListener("click",()=>byId("artifact-dialog").close());
byId("artifact-dialog").addEventListener("close",()=>artifactModal?.destroy());
byId("chat-artifacts-open").addEventListener("click",()=>openArtifact(null,{conversation_id:chatUi.id||""}));

function showView(name) {
  const allowed = ["overview", "sessions", "chat", "operations", "tickets", "memory", "configuration", "artifacts"];
  const link = globalThis.AutomoniquePlatformCockpit.parseDeepLink(typeof name === "string" && name.startsWith("#") ? name : `#${name || ""}`);
  name = allowed.includes(link.view) ? link.view : "sessions";
  if (link.workspace || link.session || link.pane) {
    cockpitState = globalThis.AutomoniquePlatformCockpit.initialState(link);
    if (link.session) platformSelectedSession = link.session;
  }
  document.body.classList.toggle("chat-page", name === "chat");
  document.querySelectorAll("[data-panel]").forEach((node) => node.classList.toggle("is-visible", node.dataset.panel === name));
  document.querySelectorAll("[data-view]").forEach((node) => {
    const active = node.dataset.view === name;
    node.classList.toggle("is-active", active);
    if (active) node.setAttribute("aria-current", "page"); else node.removeAttribute("aria-current");
  });
  byId("current-view").textContent = consoleViewName(name);
  document.title = `${translatePhrase(consoleViewName(name))} · Monique`;
  const linkedSessions = name === "sessions" && (link.workspace || link.session || link.pane || link.file);
  const artifactParams=name==="artifacts"?new URLSearchParams(String(window.location.hash).split("?")[1]||""):null;
  const artifactId=artifactParams?.get("artifact");
  const targetHash = artifactId ? `#artifacts?artifact=${encodeURIComponent(artifactId)}${artifactParams.get("revise")==="1"?"&revise=1":""}` : linkedSessions ? globalThis.AutomoniquePlatformCockpit.buildDeepLink(link) : `#${name}`;
  if (window.location.hash !== targetHash) history.replaceState(null, "", targetHash);
  if (name === "artifacts") mountArtifactLibrary(artifactId,artifactParams?.get("revise")==="1");
  if (name === "memory") loadMemory(memoryQuery);
  if (name === "operations" || name === "tickets") loadOperations();
  if (name === "sessions") loadPlatform();
  if (name === "operations") loadProcesses();
  if (name === "configuration") loadConfiguration();
  if (name === "chat") loadChatHistory();
  if (window.matchMedia("(max-width: 760px)").matches) mobileSidebarOpen(false);
  document.querySelector(".tab.is-active")?.scrollIntoView({ block: "nearest", inline: "nearest" });
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
    .filter((entry) => {
      if (memoryReview === "all") return true;
      const review = entry.review_at_ms;
      if (memoryReview === "none") return review == null;
      if (!["active", "candidate"].includes(entry.status)) return false;
      return Number.isSafeInteger(review) && (memoryReview === "due" ? review <= Date.now() : review > Date.now());
    })
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
    option.textContent = field === "status" && value === "deleted" ? translatePhrase("Archived") : label(value);
    select.append(option);
  });
  const selected = values.includes(previous) ? previous : "all";
  select.value = selected;
  return selected;
}

function memoryDateLabel(value) {
  if (!Number.isSafeInteger(value) || value <= 0) return "-";
  return new Intl.DateTimeFormat(localeTag(), { dateStyle: "medium", timeStyle: "short" }).format(value);
}

function memoryReviewLabel(value) {
  if (!Number.isSafeInteger(value) || value <= 0) return "No review scheduled";
  return value <= Date.now() ? `Review due · ${memoryDateLabel(value)}` : memoryDateLabel(value);
}

function setMemoryMode(mode) {
  memoryMode = ["graph", "list", "timeline"].includes(mode) ? mode : "list";
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
  for (const [reference, selected] of memorySelection) if (!entries.some((entry)=>entry.reference===reference && entry.revision===selected.revision && entry.status==="active")) memorySelection.delete(reference);
  updateMemorySelection();
  byId("memory-active").textContent = count(view.counts?.active);
  byId("memory-candidates").textContent = count(view.counts?.candidates);
  byId("memory-superseded").textContent = count(view.counts?.superseded);
  byId("memory-deleted").textContent = count(view.counts?.deleted);
  byId("memory-review-due").textContent = count(entries.filter((entry) => ["active", "candidate"].includes(entry.status) && Number.isSafeInteger(entry.review_at_ms) && entry.review_at_ms <= Date.now()).length);
  byId("memory-messages").textContent = count(view.counts?.messages);
  memoryKind = updateMemoryFacet("memory-kind", entries, "kind", "All types", memoryKind);
  memoryStatus = updateMemoryFacet("memory-status", entries, "status", "All statuses", memoryStatus);
  memorySensitivity = updateMemoryFacet("memory-sensitivity", entries, "sensitivity", "All levels", memorySensitivity);
  if (!entries.some((entry) => entry.reference === selectedMemoryReference)) selectedMemoryReference = entries[0]?.reference || null;
  setMemoryMode(memoryMode);
  renderSelectedMemory();
}

function renderSelectedMemory() {
  const entries = selectedMemoryEntries();
  if (!entries.some((entry) => entry.reference === selectedMemoryReference)) selectedMemoryReference = entries[0]?.reference || null;
  const query = memoryQuery ? ` for “${memoryQuery}”` : "";
  byId("memory-result-label").textContent = `${count(entries.length)} ${entries.length === 1 ? "memory" : "memories"}${query}${memorySnapshot?.truncated ? " · Limited to 4,096 records. Search to narrow results." : ""}`;
  byId("memory-export").disabled = entries.length === 0;
  renderMemoryList(entries);
  renderMemoryGraph(entries);
  renderMemoryTimeline(entries);
  renderMemoryInspector(entries.find((entry) => entry.reference === selectedMemoryReference) || null);
  byId("memory-reset").disabled = memoryKind === "all" && memoryStatus === "all" && memorySensitivity === "all" && memorySort === "updated_desc" && memoryReview === "all" && !memoryQuery;
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
    root.append(memoryEmpty("Nothing matches these filters."));
    return;
  }
  const head = document.createElement("div");
  head.className = "table-head";
  head.setAttribute("aria-hidden", "true");
  ["Reference", "Memory", "Type", "Status", "Certainty", "Updated"].forEach((text) => {
    const cell = document.createElement("span");
    cell.textContent = text;
    head.append(cell);
  });
  const body = document.createElement("div");
  body.className = "table-body";
  entries.forEach((entry) => {
    const row = consoleRow("memory-record", () => consoleOpenMemory(entry.reference));
    row.classList.toggle("is-selected", consoleState.memoryOpen && entry.reference === selectedMemoryReference);
    row.dataset.memoryReference = entry.reference;
    const ref = consoleCell(entry.reference, "cell cell-mono");
    ref.setAttribute("data-i18n-skip", "");
    ref.prepend(memorySelectionCheckbox(entry));
    const text = consoleCell(entry.content, "cell memory-row-content");
    text.setAttribute("data-i18n-skip", "");
    const kind = consoleCell(consoleSentence(entry.kind), "cell");
    const due = Number.isSafeInteger(entry.review_at_ms) && entry.review_at_ms <= Date.now();
    const status = consoleBadge(due ? "Recheck" : entry.status === "deleted" ? "Archived" : consoleSentence(entry.status), due ? "warn" : { active: "ok", candidate: "info", superseded: "quiet", deleted: "danger" }[entry.status] || "quiet");
    const confidence = document.createElement("span");
    confidence.className = "confidence";
    const bar = document.createElement("i");
    const fill = document.createElement("span");
    fill.className = `c-${Math.max(0, Math.min(10, Math.round(entry.confidence / 100)))}`;
    bar.append(fill);
    const value = document.createElement("b");
    value.textContent = `${Math.round(entry.confidence / 10)}%`;
    confidence.append(bar, value);
    const updated = consoleCell(Number.isSafeInteger(entry.updated_at_ms) ? ticketRelativeTime(new Date(entry.updated_at_ms).toISOString()) : "-", "cell cell-time");
    updated.title = memoryDateLabel(entry.updated_at_ms);
    row.append(ref, text, kind, consoleCellWrap(status), confidence, updated);
    body.append(row);
  });
  root.append(head, body);
  consoleCapList(body, "memory", "data-memory-reference", consoleState.memoryOpen ? selectedMemoryReference : null);
}

function renderMemoryGraph(entries) {
  const graph = byId("memory-graph");
  graph.replaceChildren();
  const core = document.createElement("div");
  core.className = "graph-core";
  core.textContent = "MONIQUE";
  graph.append(core);
  if (entries.length === 0) {
    const empty = memoryEmpty("Nothing matches these filters.");
    empty.classList.add("graph-empty");
    graph.append(empty);
    return;
  }
  entries.slice(0, 14).forEach((entry, index) => {
    const node = document.createElement("button");
    node.type = "button";
    node.className = `graph-node slot-${index}`;
    node.classList.toggle("is-selected", consoleState.memoryOpen && entry.reference === selectedMemoryReference);
    node.setAttribute("aria-label", `Open ${entry.reference}`);
    const reference = document.createElement("span");
    reference.textContent = `${entry.reference} · ${words(entry.kind)}`;
    const content = document.createElement("strong");
    content.setAttribute("data-i18n-skip", "");
    content.textContent = entry.content;
    const metadata = document.createElement("small");
    metadata.textContent = `${Math.round(entry.confidence / 10)}% sure · ${entry.provenance}`;
    node.append(reference, content, metadata);
    node.dataset.row = "";
    node.addEventListener("click", () => consoleOpenMemory(entry.reference));
    graph.append(node);
  });
}

function renderMemoryTimeline(entries) {
  const root = byId("memory-timeline");
  root.replaceChildren();
  if (entries.length === 0) {
    root.append(memoryEmpty("Nothing matches these filters."));
    return;
  }
  [...entries].sort((left, right) => right.updated_at_ms - left.updated_at_ms).forEach((entry) => {
    const item = document.createElement("button");
    item.type = "button";
    item.className = "memory-timeline-item";
    item.classList.toggle("is-selected", consoleState.memoryOpen && entry.reference === selectedMemoryReference);
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
    meta.textContent = `${words(entry.kind)} · ${entry.status === "deleted" ? translatePhrase("Archived") : words(entry.status)}`;
    body.append(heading, content, meta);
    item.append(marker, date, body);
    item.dataset.row = "";
    item.addEventListener("click", () => consoleOpenMemory(entry.reference));
    root.append(item);
  });
}

function memoryInspectorFact(labelText, value) {
  const row = document.createElement("div");
  const term = document.createElement("dt");
  term.textContent = labelText;
  const detail = document.createElement("dd");
  detail.setAttribute("data-i18n-skip", "");
  detail.textContent = value || "-";
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
    title.textContent = "Pick a memory";
    const detail = document.createElement("p");
    detail.textContent = "Select a row to see where it came from and when to recheck it.";
    empty.append(icon, title, detail);
    root.append(empty);
    return;
  }
  const head = document.createElement("div");
  head.className = "memory-inspector-head";
  const headingCopy = document.createElement("div");
  const eyebrow = document.createElement("span");
  eyebrow.textContent = "Memory";
  const title = document.createElement("h2");
  title.setAttribute("data-i18n-skip", "");
  title.textContent = entry.reference;
  headingCopy.append(eyebrow, title);
  const status = document.createElement("i");
  status.textContent = (entry.status === "deleted" ? translatePhrase("Archived") : words(entry.status)).toUpperCase();
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
  confidenceName.textContent = "How sure Monique is";
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
    ["Type", consoleSentence(entry.kind)],
    ["Status", entry.status === "deleted" ? "Archived" : consoleSentence(entry.status)],
    ["Learned from", entry.provenance],
    ["Updated", memoryDateLabel(entry.updated_at_ms)],
    ["Recheck", memoryReviewLabel(entry.review_at_ms)],
    ["Privacy", consoleSentence(entry.sensitivity)],
    ["Visible to", consoleSentence(entry.visibility)],
    ["Version", String(entry.revision)],
    ["Expires", entry.expires_at_ms ? memoryDateLabel(entry.expires_at_ms) : "Never"],
    ["Replaced by", entry.superseded_by || "—"],
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
  ask.textContent = "Ask assistant";
  ask.dataset.openChat = `Review memory evidence ${entry.reference}. Explain what it establishes, its provenance and confidence, whether it needs review, and how it should influence current work.`;
  actions.append(copy, ask);
  if (entry.editable) {
    const edit = document.createElement("button");
    edit.type = "button";
    edit.className = "button primary";
    edit.textContent = "Edit memory";
    edit.addEventListener("click", () => openMemoryEditor(entry));
    actions.prepend(edit);
    for (const action of entry.status === "candidate" ? ["approve", "deny"] : ["forget"]) {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "button secondary";
      button.textContent = { approve: "Approve", deny: "Reject", forget: "Forget" }[action];
      button.addEventListener("click", () => confirmMemoryAction(entry, action));
      actions.append(button);
    }
  }
  root.append(head, content, confidence, facts, actions);
}

async function loadMemory(query = null) {
  const sequence = ++memoryLoadSequence;
  memoryQuery = query?.trim() || null;
  byId("memory-clear").hidden = memoryQuery === null;
  byId("memory-result-label").textContent = memoryQuery ? "Searching…" : "Loading…";
  byId("memory-export").disabled = true;
  try {
    const view = memoryQuery === null
      ? await api("/api/memory")
      : await api("/api/memory/search", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ query: memoryQuery }) });
    if (sequence !== memoryLoadSequence) return;
    renderMemory(view);
  } catch (error) {
    if (sequence !== memoryLoadSequence) return;
    renderMemory({ entries: [], counts: {} });
    byId("memory-result-label").textContent = "Memory unavailable. Refresh to try again.";
    toast("Memory retrieval is unavailable.", "error");
  }
}

function openMemoryEditor(entry = null) {
  memoryEditorEntry = entry;
  byId("memory-editor-form").reset();
  byId("memory-editor-title").textContent = entry ? `Edit ${entry.reference}` : "Add memory";
  byId("memory-editor-help").textContent = entry
    ? "Saving keeps the previous version as a replaced record. Approval status is preserved. Choose a future review date or leave it empty."
    : "Save a stable fact or preference for future conversations. It will be active immediately.";
  byId("memory-edit-content").value = entry?.content || "";
  byId("memory-edit-kind").value = entry?.kind || "user_profile";
  byId("memory-edit-confidence").value = (entry?.confidence ?? 1000) / 10;
  byId("memory-edit-sensitivity").value = entry?.sensitivity || "personal";
  byId("memory-edit-visibility").value = entry?.visibility || "private";
  const tomorrow = new Date(Date.now() + 86400000).toLocaleDateString("en-CA");
  byId("memory-edit-review").min = tomorrow;
  if (entry?.review_at_ms > Date.now()) {
    byId("memory-edit-review").value = new Date(entry.review_at_ms).toLocaleDateString("en-CA");
  }
  byId("memory-editor-error").hidden = true;
  byId("memory-editor").showModal();
  byId("memory-edit-content").focus();
}

function confirmMemoryAction(entry, action) {
  memoryConfirmation = { entry, action };
  const verb = { approve: "Approve", deny: "Reject", forget: "Forget" }[action];
  byId("memory-confirm-title").textContent = `${verb} ${entry.reference}?`;
  byId("memory-confirm-submit").textContent = verb;
  byId("memory-confirm-help").textContent = action === "approve"
    ? "This proposal will become active and available in future conversations."
    : "This memory will be excluded from future recall. Its content and audit history remain available as an archived record.";
  byId("memory-confirm-content").textContent = entry.content;
  byId("memory-confirm-error").hidden = true;
  byId("memory-confirm").showModal();
}

function memoryActionError(error) {
  if (error.message === "memory_revision_stale" || error.message === "memory_conflict") return "This memory changed elsewhere. Your draft is still here. Cancel and refresh before trying again.";
  if (error.message === "memory_not_found") return "This memory is unavailable or belongs to another author. Refresh the list.";
  if (error.message === "memory_field_invalid") return "Check the content, certainty, and future review date. Content must fit within 8 KB.";
  return "The change could not be confirmed. Your draft is still here. Refresh the list before retrying.";
}

async function saveMemoryAction(payload, dialogId, errorId) {
  if (memorySaving) return;
  memorySaving = true;
  const dialog = byId(dialogId);
  dialog.querySelectorAll("button").forEach((button) => { button.disabled = true; });
  byId(errorId).hidden = true;
  try {
    const entry = await api("/api/memory/action", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
    dialog.close();
    selectedMemoryReference = entry.reference;
    memoryKind = memoryStatus = memorySensitivity = memoryReview = "all";
    byId("memory-review").value = "all";
    byId("memory-query").value = "";
    await loadMemory(null);
    if (memorySnapshot?.entries.some((item) => item.reference === entry.reference)) consoleOpenMemory(entry.reference);
    toast({ create: "Memory added.", edit: "Memory updated. Previous version retained.", approve: "Memory approved.", deny: "Proposal rejected.", forget: "Memory removed from recall." }[payload.action]);
  } catch (error) {
    byId(errorId).textContent = memoryActionError(error);
    byId(errorId).hidden = false;
  } finally {
    memorySaving = false;
    dialog.querySelectorAll("button").forEach((button) => { button.disabled = false; });
  }
}

byId("memory-editor-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const review = byId("memory-edit-review").value;
  saveMemoryAction({
    action: memoryEditorEntry ? "edit" : "create",
    ...(memoryEditorEntry ? { reference: memoryEditorEntry.reference, revision: memoryEditorEntry.revision } : {}),
    content: byId("memory-edit-content").value,
    kind: byId("memory-edit-kind").value,
    confidence: Math.round(Number(byId("memory-edit-confidence").value) * 10),
    sensitivity: byId("memory-edit-sensitivity").value,
    visibility: byId("memory-edit-visibility").value,
    review_at_ms: review ? new Date(`${review}T00:00:00`).getTime() : null,
  }, "memory-editor", "memory-editor-error");
});
byId("memory-confirm-form").addEventListener("submit", (event) => {
  event.preventDefault();
  if (!memoryConfirmation) return;
  const { entry, action } = memoryConfirmation;
  saveMemoryAction({ action, reference: entry.reference, revision: entry.revision }, "memory-confirm", "memory-confirm-error");
});
document.querySelectorAll("[data-memory-close]").forEach((button) => button.addEventListener("click", () => byId(button.dataset.memoryClose).close()));
["memory-editor", "memory-confirm"].forEach((id) => byId(id).addEventListener("cancel", (event) => { if (memorySaving) event.preventDefault(); }));
byId("memory-create").addEventListener("click", () => openMemoryEditor());
byId("memory-refresh").addEventListener("click", () => loadMemory(memoryQuery));
byId("memory-review").addEventListener("change", (event) => { memoryReview = event.target.value; renderSelectedMemory(); });
byId("memory-export").addEventListener("click", () => {
  const entries = selectedMemoryEntries();
  const blob = new Blob([JSON.stringify({ schema: "automonique.memory-export/v1", exported_at: new Date().toISOString(), query: memoryQuery, truncated: Boolean(memorySnapshot?.truncated), filters: { kind: memoryKind, status: memoryStatus, sensitivity: memorySensitivity, review: memoryReview }, entries }, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `monique-memory-${new Date().toISOString().slice(0, 10)}.json`;
  link.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  toast(`${entries.length} memories exported. This is a filtered export, not a database backup.`);
});

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
  memoryReview = "all";
  byId("memory-review").value = "all";
  byId("memory-query").value = "";
  byId("memory-kind").value = memoryKind;
  byId("memory-status").value = memoryStatus;
  byId("memory-sensitivity").value = memorySensitivity;
  byId("memory-sort").value = memorySort;
  loadMemory(null);
});
document.querySelectorAll("[data-memory-mode]").forEach((button) => button.addEventListener("click", () => {
  setMemoryMode(button.dataset.memoryMode);
}));

function operationLabel(value) {
  return String(value || "operation").replaceAll("_", " ").replaceAll("-", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function operationsMessage(health) {
  const messages = {
    attached: ["Support and Manage are connected", "Monique can see their tools and tickets."],
    degraded: ["Only part of Support and Manage is connected", "One service needs attention. The other still works."],
    not_attached: ["Support and Manage are not connected", "Connect them in the server settings to see tools and tickets."],
    unavailable: ["Support and Manage are not answering", "They did not send a usable list of tools."],
    busy: ["Support and Manage are busy", "Another request is using them. Try again in a moment."],
  };
  return messages[health] || ["Connection state unknown", "Refresh to check again."];
}

function processStatusLabel(status) {
  const labels = { pending: "Queued in Manage", pending_approval: "Waiting for approval", running: "Running", done: "Finished", failed: "Failed", cancelled: "Cancelled", unknown: "Unknown", unconfirmed: "Status unconfirmed", authenticated: "Signed in" };
  return labels[status] || operationLabel(status);
}

function processSnapshotIsFresh(view = processesSnapshot) {
  return ["ready", "degraded"].includes(view?.health)
    && Number.isSafeInteger(view?.observed_at_ms)
    && view.observed_at_ms <= Date.now() + 5000
    && Date.now() - view.observed_at_ms <= 90000;
}

function processDisplayStatus(job) {
  if (["done", "failed", "cancelled"].includes(job.status)) return job.status;
  if (!processSnapshotIsFresh()) return "unconfirmed";
  if (job.status === "running") {
    const worker = processesSnapshot?.worker;
    const matching = job.assigned_to_worker && worker?.active_jobs > 0
      && worker.provider === job.provider && worker.runtime === job.runtime
      && ["online", "ready", "busy", "running"].includes(worker.status);
    if (!matching) return "unconfirmed";
  }
  return job.status;
}

function processMatches(job, filter) {
  if (filter === "all") return true;
  if (filter === "active") return processDisplayStatus(job) === "running";
  if (filter === "queued") return job.status === "pending";
  if (filter === "approval") return job.status === "pending_approval";
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
  if (timestamp === null) return "-";
  return ticketRelativeTime(value) || ticketDateLabel(value);
}

function processDetail(labelText, value, title = null) {
  const detail = document.createElement("div");
  detail.className = "process-detail";
  const labelNode = document.createElement("span");
  labelNode.textContent = labelText;
  const valueNode = document.createElement("strong");
  valueNode.setAttribute("data-i18n-skip", "");
  valueNode.textContent = value || "-";
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
    empty.textContent = "No worker has reported in yet.";
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
  status.textContent = health === "stale" ? "OUT OF DATE" : worker.status.toUpperCase();
  const facts = document.createElement("div");
  facts.className = "process-worker-facts";
  [
    ["Model", worker.model],
    ["Busy", health === "stale" ? translatePhrase("Status unconfirmed") : `${count(worker.active_jobs)} of ${count(worker.concurrency)} slots active`],
    ["Seen", processTimeLabel(worker.last_seen_at), worker.last_seen_at],
  ].forEach(([labelText, value, exact]) => facts.append(processDetail(labelText, value, exact)));
  root.append(identity, status, facts);
}

function setProcessFilter(filter) {
  processFilter = ["all", "active", "queued", "approval", "failed", "completed"].includes(filter) ? filter : "all";
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
  const fresh = processSnapshotIsFresh(view);
  const health = fresh ? String(view.health) : view.health === "unavailable" ? "unavailable" : "stale";
  // No worker report yet is a waiting state, not an outage.
  const waiting = health === "unavailable" && !view.worker && jobs.length === 0;
  byId("processes-health").textContent = waiting ? "NO REPORT YET" : health.toUpperCase();
  byId("processes-health").dataset.state = waiting ? "waiting" : health;
  const observed = Number.isSafeInteger(view.observed_at_ms) ? new Date(view.observed_at_ms).toISOString() : null;
  byId("process-observed").textContent = observed ? `Updated ${processTimeLabel(observed)}` : "Waiting for the worker";
  byId("process-observed").title = observed ? ticketDateLabel(observed) : "";
  byId("process-running").textContent = count(fresh ? view.stats?.running : null);
  byId("process-queued").textContent = count(fresh ? view.stats?.queued : null);
  byId("process-approval").textContent = count(jobs.filter((job) => job.status === "pending_approval").length);
  byId("process-completed").textContent = count(view.stats?.completed);
  byId("process-failed").textContent = count(view.stats?.failed);
  renderProcessWorker(view.worker, health);
  const filterCounts = {
    all: jobs.length,
    active: jobs.filter((job) => processMatches(job, "active")).length,
    queued: jobs.filter((job) => processMatches(job, "queued")).length,
    approval: jobs.filter((job) => processMatches(job, "approval")).length,
    failed: jobs.filter((job) => processMatches(job, "failed")).length,
    completed: jobs.filter((job) => processMatches(job, "completed")).length,
  };
  Object.entries(filterCounts).forEach(([name, value]) => { byId(`process-filter-${name}`).textContent = count(value); });
  const visible = processHierarchy(jobs).filter(({ job }) => processMatches(job, processFilter));
  byId("process-result-state").textContent = `${visible.length.toLocaleString(localeTag())} of ${jobs.length.toLocaleString(localeTag())} runs`;
  const root = byId("process-list");
  root.replaceChildren();
  if (visible.length === 0) {
    const empty = document.createElement("div");
    empty.className = "integration-empty process-empty";
    empty.textContent = health === "unavailable" ? "No agent runs to show yet." : "No agent runs match this filter.";
    root.append(empty);
    if (consoleState.opsKind === "process") consoleOpenProcess(consoleState.opsKey, false);
    return;
  }
  visible.forEach(({ job, depth }) => {
    const row = consoleRow(`process-card status-${job.status}`, () => consoleOpenProcess(job.id));
    row.dataset.processId = job.id;
    if (depth > 0) row.classList.add("is-child", `depth-${depth}`);
    row.classList.toggle("is-selected", consoleState.opsKind === "process" && consoleState.opsKey === job.id);
    const issueReference = processIssueReference(job);
    const main = document.createElement("span");
    main.className = "cell-main";
    const referenceTitle = document.createElement("strong");
    referenceTitle.setAttribute("data-i18n-skip", "");
    referenceTitle.textContent = issueReference.label;
    const referenceId = document.createElement("small");
    referenceId.setAttribute("data-i18n-skip", "");
    referenceId.textContent = `${job.kind ? `${translatePhrase(operationLabel(job.kind))} · ` : ""}${shortProcessReference(job.id)}`;
    referenceId.title = job.id;
    main.append(referenceTitle, referenceId);
    const executionName = [operationLabel(job.provider), operationLabel(job.runtime)].filter((value) => value !== "Unknown").join(" · ");
    const execution = consoleCell(executionName || "-", "cell");
    const updated = consoleCell(processTimeLabel(job.updated_at), "cell cell-time");
    if (job.updated_at) updated.title = ticketDateLabel(job.updated_at);
    const status = consoleBadge(processStatusLabel(processDisplayStatus(job)), processStatusTone(processDisplayStatus(job)));
    status.classList.add("process-status", `status-${job.status}`);
    row.append(main, execution, updated, consoleCellWrap(status));
    root.append(row);
  });
  consoleCapList(root, "processes", "data-process-id", consoleState.opsKind === "process" ? consoleState.opsKey : null);
  if (consoleState.opsKind === "process") consoleOpenProcess(consoleState.opsKey, false);
}

function processStatusTone(status) {
  return { pending: "quiet", pending_approval: "warn", running: "info", done: "ok", failed: "danger", cancelled: "quiet" }[status] || "quiet";
}

// Agent details retain the selected tab, search and reading position during polling.
const processPanel = (() => {
  const states = new Map();
  let currentId = null;
  let signature = null;
  const text = (tag, value, className) => controlNode(tag, value, className);
  const raw = (tag, value, className) => {
    const node = controlData(tag, value);
    if (className) node.className = className;
    return node;
  };
  const action = (label, fn, key, className = "button ghost small") => {
    const button = controlButton(label, fn); button.className = className;
    if (key) button.dataset.runFocus = key;
    return button;
  };
  const currentJob = () => (processesSnapshot?.jobs || []).find((job) => job.id === currentId);
  const eventKey = (line) => JSON.stringify([line.at_ms, line.kind, line.text, line.truncated]);
  const timestamp = (value) => {
    const ms = typeof value === "number" ? value : ticketTimestamp(value);
    return Number.isFinite(ms) && ms > 0 && ms < 8640000000000000 ? new Date(ms).toISOString() : null;
  };
  function time(value) {
    const iso = timestamp(value), node = text("time", iso ? processTimeLabel(iso) : "Not available");
    if (iso) { node.dateTime = iso; node.title = ticketDateLabel(iso); }
    return node;
  }
  function stateFor(job) {
    if (!states.has(job.id)) states.set(job.id, {tab:"overview",query:"",filter:"all",newest:true,open:new Set(),output:job.output || [],pending:null});
    if (states.size > 100) states.delete(states.keys().next().value);
    return states.get(job.id);
  }
  function copy(value, message = "Copied.") {
    return navigator.clipboard.writeText(value).then(() => toast(translatePhrase(message))).catch(() => toast(translatePhrase("The browser did not allow clipboard access."), "error"));
  }
  function category(line) {
    const kind = String(line.kind || "").toLowerCase();
    if (/error|fail/.test(kind)) return "errors";
    if (/^tool/.test(kind)) return "tools";
    if (["final","assistant","message","answer","result"].includes(kind)) return "messages";
    return "events";
  }
  function eventLabel(line) {
    return ({tool_start:"Tool started",tool_input:"Tool request",tool_result:"Tool result",tool_end:"Tool finished",final:"Agent response",done:"Run finished",error:"Error",failed:"Run failed",lifecycle:"Run event",assistant:"Agent response"})[line.kind] || operationLabel(line.kind);
  }
  function groups(lines) {
    const result = [];
    lines.forEach((line) => {
      const previous = result[result.length - 1];
      if (line.kind === "tool_input" && previous?.lines.length === 1 && previous.lines[0].kind === "tool_start") {
        previous.lines.push(line); previous.content = line.text; previous.key += eventKey(line);
      } else result.push({key:eventKey(line),lines:[line],content:line.text,category:category(line)});
    });
    return result;
  }
  function eventRow(group, state, compact = false) {
    const row = text("article", undefined, `run-event run-event-${group.category}`);
    const meta = text("div", undefined, "run-event-meta");
    meta.append(text("span", group.lines.length > 1 ? "Tool request" : eventLabel(group.lines[0])), time(group.lines[group.lines.length-1].at_ms));
    const content = String(group.content || "");
    row.append(meta);
    if (content.length > (compact ? 220 : 700) || content.split("\n").length > (compact ? 3 : 8)) {
      const disclosure = text("details", undefined, "run-event-disclosure");
      disclosure.dataset.runDisclosure = group.key; disclosure.open = state.open.has(group.key);
      disclosure.append(raw("summary", content.replace(/\s+/g," ").slice(0,compact ? 160 : 200) + "…"),raw("pre",content,"run-event-text"));
      disclosure.firstChild.dataset.runFocus = `event-${group.key}`;
      disclosure.addEventListener("toggle",()=>disclosure.open ? state.open.add(group.key) : state.open.delete(group.key)); row.append(disclosure);
    } else row.append(raw("pre", content, "run-event-text"));
    if (group.lines.length > 1 && !compact) row.append(raw("small",group.lines[0].text,"run-tool-context"));
    if (group.lines.some((line)=>line.truncated)) row.append(text("small","This event was shortened at the source.","run-truncated"));
    return row;
  }
  function section(title, className = "") {
    const root = text("section",undefined,`run-section ${className}`); root.append(text("h3",title)); return root;
  }
  function fact(root, label, value) {
    const row = text("div",undefined,"run-fact");row.append(text("dt",label),raw("dd",value || translatePhrase("Not reported")));root.append(row);
  }
  function switchTab(tab, focus = false) {
    const job = currentJob(); if (!job) return;
    stateFor(job).tab = tab; render(job,true); byId("ops-drawer-body").scrollTop = 0;
    if (focus) byId(`run-tab-${tab}`)?.focus({preventScroll:true});
  }
  function sourceCheck(job) {
    const root = section("Status sources","run-sources");
    const output = text("div",undefined,"run-source-result");output.dataset.runCheck = job.id;
    const result = controlState.runs.get(job.id);
    const check = action("Check latest status",async()=>{
      controlState.runs.set(job.id,{pending:true});render(currentJob(),true);
      try {controlState.runs.set(job.id,await controlAction({action:"check_run",id:job.id}));}
      catch(error) {controlState.runs.set(job.id,{error});}
      if(currentId===job.id && consoleState.opsKind === "process")render(currentJob(),true);
    },"check-status");check.disabled=result?.pending===true;
    const heading=text("div",undefined,"run-section-head");heading.append(root.firstChild,check);root.append(heading,output);
    if(result?.pending) output.append(text("p","Checking latest status…","inline-hint"));
    else if(result?.error) output.append(text("p",controlError(result.error),"run-warning"));
    else if(result?.manage) {
      output.append(text("small",`${translatePhrase("Checked")} ${controlTime(result.checked_at_ms)}`,"inline-hint"));
      const rows=text("dl",undefined,"run-facts");
      fact(rows,"Manage",`${translatePhrase(processStatusLabel(result.manage.status))} · ${translatePhrase(result.manage.fresh ? "Fresh snapshot" : "Out-of-date snapshot")}`);
      fact(rows,"GitHub",result.github?.status==="verified"?translatePhrase(ticketStatusLabel(result.github.state)):translatePhrase("Not available"));
      if(result.worker?.status)fact(rows,"Worker",`${translatePhrase(operationLabel(result.worker.status))} · ${result.worker.active_jobs ?? "—"} ${translatePhrase("active jobs")}`);
      output.append(rows);
      if(result.issue_conflict)output.append(text("p","GitHub is closed while Manage still reports pending or running work. These sources disagree.","run-warning"));
      else output.append(text("p","Issue state and agent execution are separate. An open issue can contain completed work.","inline-hint"));
      if(result.worker_conflict)output.append(text("p","Manage reports this run as active, but the assigned worker reports no active jobs.","run-warning"));
      output.dataset.state=result.disagreement?"failed":"verified";
    } else output.append(text("p","Compare the latest Manage report with GitHub and the worker.","inline-hint"));
    return root;
  }
  function overview(job,state) {
    const root = text("div");
    const lines=job.output || [];
    const final=[...lines].reverse().find((line)=>line.kind==="final" && String(line.text || "").trim());
    const error=[...lines].reverse().find((line)=>category(line)==="errors" && String(line.text || "").trim());
    const result=job.status==="failed" ? error || final : final;
    const outcome=section(result ? (job.status==="failed" ? "Failure details" : "Agent response") : "Latest activity","run-outcome");
    if(result) {
      outcome.dataset.outcome=job.status;
      outcome.append(eventRow({key:eventKey(result),lines:[result],content:result.text,category:category(result)},state));
      outcome.append(action("Copy response",()=>copy(String(result.text),"Response copied."),"copy-response"));
    } else {
      outcome.append(text("p",job.status==="done" ? "No final response is included in this snapshot. Open GitHub or Manage for the completion report." : job.status==="failed" ? "No failure details are included in this snapshot. Open Manage to investigate." : lines.length ? "Most recent recorded action" : "No output from the agent yet.","inline-hint"));
      const latest=groups(lines).slice(-1)[0];if(latest)outcome.append(eventRow(latest,state,true));
    }
    root.append(outcome);
    const context=section("Execution context");const facts=text("dl",undefined,"run-facts");
    fact(facts,"Agent",operationLabel(job.provider));fact(facts,"Runtime",job.runtime && job.runtime!=="unknown"?operationLabel(job.runtime):null);
    fact(facts,"Last activity",job.updated_at?ticketDateLabel(job.updated_at):null);
    context.append(facts);root.append(context);
    root.append(sourceCheck(job));
    const related=(processesSnapshot?.jobs || []).filter((item)=>item.id===job.parent_id || item.parent_id===job.id);
    if(related.length){const sectionRoot=section("Related runs");for(const item of related){const label=`${translatePhrase(item.id===job.parent_id?"Parent run":"Child run")} · ${processIssueReference(item).label}`;sectionRoot.append(action(label,()=>consoleOpenProcess(item.id),`related-${item.id}`));}root.append(sectionRoot);}
    return root;
  }
  function outputText(job,lines) {
    return [`${processIssueReference(job).label} · ${job.id}`,`${translatePhrase("Last reported status")}: ${translatePhrase(processStatusLabel(job.status))}`,translatePhrase("Recent events retained by the worker; this may not be the full history."),"",...lines.map(line=>`[${timestamp(line.at_ms)||"—"}] ${line.kind}${line.truncated?" [truncated]":""}\n${line.text}`)].join("\n\n");
  }
  function activity(job,state) {
    const root=text("div",undefined,"run-activity");
    const live=processDisplayStatus(job)==="running";
    const head=text("div",undefined,"run-section-head");
    head.append(text("h3",`${translatePhrase(live?"Live output":"Saved output")} · ${state.output.length} ${translatePhrase("events")}`));
    head.append(action("Copy output",()=>copy(outputText(job,state.output),"Output copied."),"copy-output"));root.append(head);
    root.append(text("p","Recent events retained by the worker; this may not be the full history.","inline-hint"));
    if(state.pending){root.append(action("Show new activity",()=>{state.output=state.pending;state.pending=null;render(job,true);byId("ops-drawer-body").scrollTop=0;},"new-activity","button primary small"));}
    const toolbar=text("div",undefined,"run-activity-toolbar");
    const search=text("input");search.type="search";search.placeholder=translatePhrase("Search activity…");search.setAttribute("aria-label",translatePhrase("Search activity"));search.value=state.query;search.dataset.runFocus="search";
    const select=text("select");select.setAttribute("aria-label",translatePhrase("Filter activity"));select.dataset.runFocus="filter";
    for(const [value,label] of [["all","All events"],["messages","Messages"],["tools","Tools"],["errors","Errors"],["events","Run events"]]) {const option=text("option",label);option.value=value;select.append(option);}select.value=state.filter;
    const order=action(state.newest?"Newest first":"Oldest first",()=>{state.newest=!state.newest;render(job,true);},"order");order.setAttribute("aria-label",translatePhrase("Reverse activity order"));
    toolbar.append(search,select,order);root.append(toolbar);
    const count=text("p",undefined,"run-match-count");count.setAttribute("role","status");
    const log=text("div",undefined,"run-event-list");log.setAttribute("aria-label",translatePhrase(live?"Live agent output":"Saved agent output"));
    const paint=()=>{
      const query=state.query.trim().toLocaleLowerCase();
      let visible=groups(state.output).filter(group=>(state.filter==="all" || group.category===state.filter) && (!query || group.lines.some(line=>`${line.kind} ${line.text}`.toLocaleLowerCase().includes(query))));
      if(state.newest)visible.reverse();
      const events=visible.reduce((n,group)=>n+group.lines.length,0);count.textContent=`${events} / ${state.output.length} ${translatePhrase("events")}`;
      log.replaceChildren(...visible.map(group=>eventRow(group,state)));
      if(!visible.length)log.append(text("p",state.output.length?"No events match your search.":"No output from the agent yet.","run-empty"));
    };
    search.addEventListener("input",()=>{state.query=search.value;paint();});select.addEventListener("change",()=>{state.filter=select.value;paint();});
    root.append(count,log);paint();return root;
  }
  function details(job) {
    const root=text("div");const facts=section("Run details");const list=text("dl",undefined,"run-facts");
    for(const [label,value] of [
      ["Last reported status",translatePhrase(processStatusLabel(job.status))],
      ["Created",job.created_at?ticketDateLabel(job.created_at):null],
      ["Updated",job.updated_at?ticketDateLabel(job.updated_at):null],
      ["On this worker",translatePhrase(job.assigned_to_worker?"Yes":"No")],
      ["Approval",translatePhrase(job.approved?"Approved":"Not reported")],
      ["Decisions",String(job.decision_count ?? 0)],
      ["Type",job.kind?translatePhrase(operationLabel(job.kind)):null],
      ["Came from",job.source && job.source!=="unknown"?translatePhrase(operationLabel(job.source)):null],
    ])if(value)fact(list,label,value);
    const observed=text("div",undefined,"run-fact");observed.append(text("dt","Snapshot"));const date=raw("dd",controlTime(processesSnapshot?.observed_at_ms));date.dataset.runSnapshot="";observed.append(date);list.append(observed);
    facts.append(list);root.append(facts);
    const references=section("References");
    for(const [label,value] of [["Run ID",job.id],["Ticket ID",job.issue_id],["Conversation",job.session_id],["Part of",job.parent_id],["Site",job.site_id]])if(value){
      const row=text("div",undefined,"run-reference");const content=text("div");content.append(text("small",label),raw("code",value));
      const button=action("Copy",()=>copy(value),`copy-${label}`);button.setAttribute("aria-label",`${translatePhrase("Copy")} ${translatePhrase(label)}`);row.append(content,button);references.append(row);
    }
    root.append(references);
    if(job.assigned_to_worker && processesSnapshot?.worker){const worker=processesSnapshot.worker;const sectionRoot=section("Current worker");sectionRoot.append(text("p","Current worker configuration, not a record of this run’s model or usage.","inline-hint"));const workerFacts=text("dl",undefined,"run-facts");
      for(const [label,value] of [["Status",translatePhrase(operationLabel(worker.status))],["Agent",operationLabel(worker.provider)],["Model",worker.model],["Runtime",worker.runtime],["Version",worker.cli_version],["Active jobs",`${worker.active_jobs ?? 0} / ${worker.concurrency ?? "—"}`]])if(value)fact(workerFacts,label,value);
      sectionRoot.append(workerFacts);root.append(sectionRoot);}
    return root;
  }
  function header(job,state) {
    const drawer=byId("ops-drawer");drawer.classList.add("is-run-panel");
    let tools=drawer.querySelector(".run-header-tools");if(!tools){tools=text("div",undefined,"run-header-tools");drawer.querySelector(".drawer-head").insertBefore(tools,drawer.querySelector(".drawer-close"));}
    const visible=processHierarchy(processesSnapshot?.jobs || []).filter(({job})=>processMatches(job,processFilter)).map(({job})=>job);
    const index=visible.findIndex(item=>item.id===job.id);
    const previous=action("‹",()=>{consoleOpenProcess(visible[index-1].id);byId("ops-drawer").querySelector('[data-run-focus="previous"]')?.focus();},"previous","run-icon-button");
    const next=action("›",()=>{consoleOpenProcess(visible[index+1].id);byId("ops-drawer").querySelector('[data-run-focus="next"]')?.focus();},"next","run-icon-button");
    previous.setAttribute("aria-label",translatePhrase("Previous run"));next.setAttribute("aria-label",translatePhrase("Next run"));previous.title=previous.getAttribute("aria-label");next.title=next.getAttribute("aria-label");previous.disabled=index<=0;next.disabled=index<0 || index>=visible.length-1;
    const position=raw("small",index>=0?`${index+1} / ${visible.length}`:"—","run-position");
    const expand=action(drawer.classList.contains("is-expanded")?"↙":"↗",()=>{drawer.classList.toggle("is-expanded");drawer.closest(".view-split").classList.toggle("has-expanded-run",drawer.classList.contains("is-expanded"));render(job,true);byId("ops-drawer").querySelector('[data-run-focus="expand"]')?.focus();},"expand","run-icon-button run-expand");
    expand.setAttribute("aria-label",translatePhrase(drawer.classList.contains("is-expanded")?"Collapse panel":"Expand panel"));expand.title=expand.getAttribute("aria-label");expand.setAttribute("aria-pressed",String(drawer.classList.contains("is-expanded")));
    tools.replaceChildren(previous,position,next,expand);
  }
  function render(job,force=false) {
    if(!job)return;
    const body=byId("ops-drawer-body"),drawer=byId("ops-drawer");
    const changed=currentId!==job.id || !drawer.classList.contains("is-run-panel");
    const state=stateFor(job);const fresh=processSnapshotIsFresh();const displayStatus=processDisplayStatus(job);
    const nextSignature=JSON.stringify([job,processesSnapshot?.worker,fresh,currentLanguage,processFilter,(processesSnapshot?.jobs || []).map(j=>[j.id,j.parent_id,j.status]),controlState.runs.get(job.id)]);
    if(!changed && !force && nextSignature===signature){body.querySelectorAll("[data-run-snapshot]").forEach(node=>node.textContent=controlTime(processesSnapshot?.observed_at_ms));return;}
    const focused=drawer.contains(document.activeElement)?document.activeElement:null;
    const focusKey=focused?.dataset.runFocus;const selection=focused?.tagName==="INPUT"?[focused.selectionStart,focused.selectionEnd]:null;
    const scroll=changed?0:body.scrollTop;
    const incoming=job.output || [];
    if(JSON.stringify(incoming)!==JSON.stringify(state.output)) {
      if(!changed && state.tab==="activity" && scroll>100)state.pending=incoming;
      else {state.output=incoming;state.pending=null;}
    }
    currentId=job.id;signature=nextSignature;
    byId("ops-drawer-kicker").textContent=`${translatePhrase("Agent run")} · ${translatePhrase(processStatusLabel(displayStatus))}`;
    const title=byId("ops-drawer-title");title.dataset.i18nSkip="";title.textContent=processIssueReference(job).label;
    header(job,state);
    const summary=text("section",undefined,"run-summary");
    const identity=text("div",undefined,"run-identity");const mark=raw("span",String(operationLabel(job.provider)).slice(0,1).toUpperCase(),"run-agent-mark");mark.setAttribute("aria-hidden","true");
    const provider=text("div",undefined,"run-agent-name");provider.append(raw("strong",operationLabel(job.provider)),text("small",job.runtime && job.runtime!=="unknown"?operationLabel(job.runtime):"Runtime not reported"));
    const badge=consoleBadge(translatePhrase(processStatusLabel(displayStatus)),processStatusTone(displayStatus));identity.append(mark,provider,badge);summary.append(identity);
    const lede={pending:"Waiting for a free agent to pick it up.",pending_approval:"Waiting for your approval in Manage. Nothing runs until it is approved.",running:"An agent is working on this right now.",done:"The agent finished this run.",failed:"This run failed. Check the output below, then retry from Manage.",cancelled:"This run was cancelled.",unconfirmed:!fresh?"This snapshot is out of date. Current execution is unconfirmed.":"Manage reports a running job, but matching worker activity is not confirmed."}[displayStatus] || "Agent run.";
    summary.append(text("p",lede,displayStatus==="unconfirmed"||displayStatus==="failed"?"run-warning":"run-lede"));
    if(!fresh)summary.append(text("small","Out-of-date snapshot","run-warning"));
    const actions=text("div",undefined,"run-actions");
    for(const [label,url] of [["GitHub ↗",processIssueReference(job).href],[job.status==="pending_approval"?"Approve in Manage ↗":"Manage ↗",safeTicketLink(job.manage_url)]])if(url){const link=text("a",label,"button ghost small");link.href=url;link.target="_blank";link.rel="noreferrer";actions.append(link);}
    actions.append(action("Refresh",()=>loadProcesses({announce:true}),"refresh"));
    const updated=text("span",undefined,"run-updated");updated.append(time(job.updated_at));actions.append(updated);summary.append(actions);
    const tabs=text("div",undefined,"drawer-tabs run-tabs");tabs.setAttribute("role","tablist");tabs.setAttribute("aria-label",translatePhrase("Run sections"));
    for(const [key,label] of [["overview","Overview"],["activity","Activity"],["artifacts","Deliverables"],["details","Details"]]){
      const button=action(label,()=>switchTab(key,true),`tab-${key}`,state.tab===key?"is-active":"");button.id=`run-tab-${key}`;button.setAttribute("role","tab");button.setAttribute("aria-controls",`run-pane-${key}`);button.setAttribute("aria-selected",String(state.tab===key));button.tabIndex=state.tab===key?0:-1;
      button.addEventListener("keydown",event=>{const keys=["overview","activity","artifacts","details"],i=keys.indexOf(key);const target=event.key==="ArrowRight"?keys[(i+1)%keys.length]:event.key==="ArrowLeft"?keys[(i+keys.length-1)%keys.length]:event.key==="Home"?keys[0]:event.key==="End"?keys[keys.length-1]:null;if(target){event.preventDefault();switchTab(target,true);}});tabs.append(button);
    }
    body.replaceChildren(summary,tabs);
    for(const [key,build] of [["overview",()=>overview(job,state)],["activity",()=>activity(job,state)],["artifacts",()=>artifactRunPane(job)],["details",()=>details(job)]]){const pane=build();pane.id=`run-pane-${key}`;pane.classList.add("run-pane");pane.setAttribute("role","tabpanel");pane.setAttribute("aria-labelledby",`run-tab-${key}`);pane.hidden=state.tab!==key;body.append(pane);}
    body.scrollTop=scroll;
    if(focusKey){const replacement=[...drawer.querySelectorAll("[data-run-focus]")].find(node=>node.dataset.runFocus===focusKey && !node.closest("[hidden]"));if(replacement){replacement.focus({preventScroll:true});if(selection && replacement.tagName==="INPUT")replacement.setSelectionRange(...selection);}}
  }
  function resetShell() {
    const drawer=byId("ops-drawer");drawer.classList.remove("is-run-panel","is-expanded");drawer.closest(".view-split")?.classList.remove("has-expanded-run");drawer.querySelector(".run-header-tools")?.remove();currentId=null;signature=null;
  }
  return {render,resetShell};
})();

function renderProcessDrawer(job) { processPanel.render(job); }

async function loadProcesses({ announce = false } = {}) {
  const sequence = ++processesLoadSequence;
  const button = byId("processes-refresh");
  button.disabled = true;
  try {
    const view = await api("/api/processes");
    if (sequence !== processesLoadSequence) return;
    renderProcesses(view);
    if (announce) toast("Process visibility refreshed.");
  } catch (_error) {
    if (sequence !== processesLoadSequence) return;
    renderProcesses({ health: "unavailable", observed_at_ms: Date.now(), stats: {}, worker: null, jobs: [] });
    if (announce) toast("Process visibility is unavailable.", "error");
  } finally {
    if (sequence === processesLoadSequence) button.disabled = false;
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
  state.textContent = signal ? words(signal.state) : "Unknown";
  const detail = document.createElement("span");
  detail.textContent = signal
    ? `${signal.reference ? `${signal.reference} · ` : ""}${words(signal.freshness)} · ${signal.unread === null ? "unread unknown" : `${count(signal.unread)} unread`}`
    : "Not reported";
  root.dataset.freshness = signal?.freshness || "unknown";
  root.append(source, state, detail);
}

function renderCockpitReadModels(readModels) {
  const semantics = readModels.semantics;
  const semanticWords = (key) => key.split(".").slice(1).map(words).join(" · ");
  const withSource = (value) => `${semanticWords(value.semantic_key)} · ${semanticWords(value.freshness_key)} · source revision ${value.source_revision}`;
  const previews = semantics?.previews.length
    ? `${semantics.previews.map((value) => semanticWords(value.semantic_key)).join(" · ")} · source revision ${semantics.source_revision}`
    : semantics ? `No previews · source revision ${semantics.source_revision}` : null;
  const review = semantics
    ? `${semanticWords(semantics.attention.semantic_key)}${semantics.attention.reason_key ? ` · ${semanticWords(semantics.attention.reason_key)}` : ""} · ${withSource(semantics.review)} · ${withSource(semantics.pull_request)}`
    : null;
  const checks = semantics?.checks.length
    ? semantics.checks.map(withSource).join(" · ")
    : semantics ? `No checks · source revision ${semantics.source_revision}` : null;
  const delivery = semantics ? withSource(semantics.delivery) : null;
  const values = [
    ["cockpit-files-state", previews, semantics?.previews.map((value) => value.semantic_key).join(" ")],
    ["cockpit-review-state", review, semantics ? `${semantics.attention.semantic_key} ${semantics.review.semantic_key} ${semantics.pull_request.semantic_key}` : null],
    ["cockpit-checks-state", checks, semantics?.checks.map((value) => value.semantic_key).join(" ")],
    ["cockpit-delivery-state", delivery, semantics?.delivery.semantic_key],
  ];
  values.forEach(([id, value, semanticKey]) => {
    const node = byId(id);
    node.textContent = value === null ? "Unavailable" : value;
    node.dataset.available = String(value !== null);
    if (semanticKey) node.dataset.semanticKey = semanticKey;
    else delete node.dataset.semanticKey;
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

function cockpitCollectionCoverage(coverage) {
  const unavailable = Object.entries(coverage?.sources || {})
    .filter(([, source]) => source.state !== "available")
    .map(([name, source]) => `${words(name)} ${words(source.state)}${source.category ? ` (${source.category})` : ""}`);
  const omitted = coverage?.omitted && coverage.omitted !== "0"
    ? `${coverage.omitted} of ${coverage.total} newest-ordered records omitted by the dashboard bound`
    : null;
  return [...unavailable, omitted].filter(Boolean).join(" · ");
}

function appendCockpitCollectionState(root, coverage, emptyTitle, emptyDetail) {
  if (coverage.state === "complete" && coverage.total !== "0") return;
  const item = document.createElement("li");
  const title = document.createElement("strong");
  const detail = document.createElement("span");
  if (coverage.state === "complete") {
    title.textContent = emptyTitle;
    detail.textContent = emptyDetail;
  } else {
    title.textContent = coverage.state === "partial" ? "Structured projection is partial" : "Structured projection unavailable";
    detail.textContent = cockpitCollectionCoverage(coverage) || "The authenticated server did not provide complete source coverage.";
  }
  item.append(title, detail);
  root.append(item);
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
  capabilityTitle.textContent = cockpitPresentation.mode === "v2" ? "Workspaces are up to date." : cockpitPresentation.mode === "partial" ? "Some workspace details are missing." : "Workspaces are not available on this server.";
  const capabilityDetail = document.createElement("span");
  // The shared core explains degradation in technical terms; show a plain
  // sentence and keep the exact reason codes beside it for diagnosis.
  const reasonCodes = (cockpitPresentation.degradation || "").match(/\(([^)]+)\)/)?.[1] || "";
  capabilityDetail.textContent = cockpitPresentation.stale
    ? "This data is out of date. Workspace actions are paused until it refreshes."
    : cockpitPresentation.mode === "partial"
      ? "Missing details are left blank rather than guessed, and workspace actions stay read-only."
      : cockpitPresentation.mode === "v1"
        ? "Saved conversations still work."
        : "Projects, servers, workspaces and their status are listed below.";
  capability.append(capabilityTitle, capabilityDetail);
  if (!cockpitPresentation.stale && reasonCodes) {
    const codes = document.createElement("code");
    codes.className = "capability-codes";
    codes.setAttribute("data-i18n-skip", "");
    codes.textContent = reasonCodes;
    codes.title = cockpitPresentation.degradation;
    capability.append(codes);
  }

  byId("cockpit-project-count").textContent = count(cockpitPresentation.projects.length);
  byId("cockpit-host-count").textContent = count(cockpitPresentation.hosts.length);
  byId("cockpit-workspace-count").textContent = count(cockpitPresentation.workspaces.length);
  cockpitReplaceNamedList("cockpit-project-list", cockpitPresentation.projects, "None listed.");
  cockpitReplaceNamedList("cockpit-host-list", cockpitPresentation.hosts, "None listed.");

  const workspaceRoot = byId("cockpit-workspace-list");
  workspaceRoot.replaceChildren();
  const filtered = cockpitPresentation.workspaces.filter((workspace) => !cockpitPresentation.attentionAvailable || cockpitState.attentionFilter === "all" || workspace.attention === cockpitState.attentionFilter);
  if (filtered.length === 0) {
    const empty = document.createElement("div");
    empty.className = "cockpit-unavailable";
    empty.textContent = cockpitPresentation.workspaces.length === 0 ? "No workspaces yet. Conversations above still work." : "No workspaces match this filter.";
    workspaceRoot.append(empty);
  }
  filtered.forEach((workspace) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "row cockpit-workspace-option";
    button.dataset.row = "";
    button.setAttribute("role", "option");
    button.setAttribute("aria-selected", String(cockpitPresentation.selectedWorkspace?.id === workspace.id));
    button.classList.toggle("is-selected", cockpitPresentation.selectedWorkspace?.id === workspace.id);
    const main = document.createElement("span");
    main.className = "cell-main";
    const labelNode = document.createElement("strong");
    labelNode.textContent = workspace.label;
    const context = document.createElement("small");
    context.setAttribute("data-i18n-skip", "");
    context.textContent = workspace.id;
    main.append(labelNode, context);
    const tones = { needs_you: "warn", blocked: "danger", working: "info", done: "ok" };
    const attentionNames = { needs_you: "Needs you", blocked: "Blocked", working: "Working", done: "Done" };
    const attentionBadge = consoleBadge(workspace.attention ? attentionNames[workspace.attention] || words(workspace.attention) : "Unknown", tones[workspace.attention] || "quiet");
    const branch = consoleCell(workspace.branch || "No branch yet", "cell cell-mono");
    button.append(main, consoleCellWrap(attentionBadge), branch);
    button.addEventListener("click", () => consoleOpenWorkspace(workspace));
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
  byId("cockpit-workspace-coordinate").textContent = workspace ? workspace.id : "NO WORKSPACE";
  byId("cockpit-workspace-title").textContent = workspace?.label || "No workspace selected";
  byId("cockpit-workspace-branch").textContent = workspace?.branch ? `Branch ${workspace.branch}` : "No branch yet";
  cockpitSignal("cockpit-external-signal", "OUTSIDE WORK", workspace?.external_work);
  cockpitSignal("cockpit-agent-signal", "AGENT", workspace?.internal_agent);
  // With fully available workspaces the selected one is the primary context,
  // so its drawer starts open until the operator closes it. When the
  // workspace service is only partial, the drawer would open on blank fields
  // and unavailable actions, so it waits until a workspace is picked.
  if (workspace && cockpitPresentation.mode === "v2" && !consoleState.taskDrawerDismissed && !consoleDrawerIsOpen("task-drawer")) {
    consoleDrawer("task-drawer", true);
    if (byId("platform-session-detail").hidden) consoleShowTaskPane("workspace");
  }
  consoleSyncTaskDrawerTitle();

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
  // A plain summary first, then the server's exact categories: a refusal
  // reason is never paraphrased away.
  const lifecyclePlain = document.createElement("span");
  lifecyclePlain.textContent = {
    available: "Creating or resuming a workspace from here is not available yet. Server setup and checkout are ready.",
    partial: "Creating or resuming a workspace from here is not available yet. Server setup is only partly ready.",
    unavailable: "Creating or resuming a workspace from here is not available yet.",
  }[localLifecycle.state] || "";
  const lifecycleExact = document.createElement("small");
  lifecycleExact.className = "exact-reason";
  lifecycleExact.setAttribute("data-i18n-skip", "");
  lifecycleExact.textContent = localLifecycle.message;
  lifecycleReason.replaceChildren(...(lifecyclePlain.textContent ? [lifecyclePlain, document.createTextNode(" ")] : []), lifecycleExact);
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
  byId("cockpit-inspector-session").textContent = link.session || workspace?.session_id || "-";
  byId("cockpit-inspector-pane").textContent = link.pane || "-";
  byId("cockpit-inspector-anchor").textContent = link.file ? `${link.file} · ${link.hunk} · ${link.side}:${link.line}` : "-";

  renderCockpitReadModels(cockpitPresentation.readModels);
  renderCockpitReceipt(cockpitState.receipt.state === "idle" ? cockpitPresentation.receipt : cockpitState.receipt);
  const reviewLink = globalThis.AutomoniquePlatformCockpit.parseDeepLink(window.location.hash);
  const exactAnchor = reviewLink.file && reviewLink.hunk && reviewLink.side && reviewLink.line;
  const addComment = cockpitPresentation.reviewActions.addComment;
  const approveReview = cockpitPresentation.reviewActions.approveReview;
  const rerunCheck = cockpitPresentation.reviewActions.rerunCheck;
  const rerunTarget = byId("cockpit-rerun-check-target");
  const selectedCheck = rerunTarget.value;
  rerunTarget.replaceChildren();
  for (const target of rerunCheck.targets || []) {
    const option = document.createElement("option");
    option.value = target.check_id;
    option.textContent = `${target.check_id} · revision ${target.exact_check_revision}`;
    rerunTarget.append(option);
  }
  if (selectedCheck && (rerunCheck.targets || []).some((target) => target.check_id === selectedCheck)) {
    rerunTarget.value = selectedCheck;
  }
  if (rerunTarget.options.length === 0) {
    const option = document.createElement("option");
    option.value = "";
    option.textContent = "No rerunnable check available";
    rerunTarget.append(option);
  }
  rerunTarget.disabled = !rerunCheck.available || unresolvedControl;
  byId("cockpit-add-comment").disabled = !addComment.available || !exactAnchor || unresolvedControl;
  byId("cockpit-approve-review").disabled = !approveReview.available || unresolvedControl;
  byId("cockpit-rerun-check").disabled = !rerunCheck.available || unresolvedControl;
  byId("cockpit-add-comment").textContent = addComment.available ? "Add exact comment" : "Add comment unavailable";
  byId("cockpit-approve-review").textContent = approveReview.available ? "Approve review" : "Approve unavailable";
  byId("cockpit-rerun-check").textContent = rerunCheck.available ? "Preview exact rerun" : "Preview rerun unavailable";
  const previewTarget = cockpitRerunPreview && (rerunCheck.targets || []).find((target) =>
    target.check_id === cockpitRerunPreview.check_id
      && target.exact_revision === cockpitRerunPreview.exact_revision
      && target.exact_check_revision === cockpitRerunPreview.exact_check_revision
      && target.confirmation_digest === cockpitRerunPreview.confirmation_digest);
  if (cockpitRerunPreview && !previewTarget) cockpitRerunPreview = null;
  const rerunPreview = byId("cockpit-rerun-preview");
  rerunPreview.hidden = !cockpitRerunPreview;
  byId("cockpit-rerun-preview-detail").textContent = cockpitRerunPreview
    ? `${cockpitRerunPreview.check_id} · workspace revision ${cockpitRerunPreview.exact_revision} · check revision ${cockpitRerunPreview.exact_check_revision}`
    : "";
  byId("cockpit-rerun-confirm").disabled = !cockpitRerunPreview || unresolvedControl;
  byId("cockpit-rerun-cancel").disabled = !cockpitRerunPreview || cockpitControlBusy;
  byId("cockpit-review-comment").disabled = !addComment.available || unresolvedControl;
  byId("cockpit-review-action-reason").textContent = unresolvedControl
    ? "Waiting for your last action to be confirmed. New actions are paused."
    : !exactAnchor
      ? "To comment, open a link to a specific line of code first."
      : rerunCheck.available
        ? "You can run the selected check again."
        : "Only the review actions this server offers are shown.";
  const inbox = byId("cockpit-inbox-list");
  inbox.replaceChildren();
  if (cockpitPresentation.inbox.length > 0) {
    cockpitPresentation.inbox.forEach((entry) => {
      const item = document.createElement("li");
      const title = document.createElement("strong");
      title.textContent = `${words(entry.state)} · ${words(entry.reason)}`;
      const detail = document.createElement("span");
      detail.textContent = `${consoleSentence(entry.source_kind)} · ${consoleMsAgo(entry.observed_at_ms)} · ${entry.unread} unread`;
      // The exact generation stays visible: cross-client acceptance compares
      // this line verbatim, so it is never rounded or paraphrased.
      const generation = document.createElement("small");
      generation.className = "cockpit-exact-generation";
      generation.textContent = `${words(entry.source_kind)} · observed ${entry.observed_at_ms} ms · source revision ${entry.source_revision} · item revision ${entry.item_revision} · ${entry.unread} unread`;
      const exactLink = document.createElement("a");
      exactLink.href = entry.deep_link;
      exactLink.textContent = "View";
      exactLink.setAttribute("aria-label", `Open exact attention context for ${words(entry.reason)} at source revision ${entry.source_revision}`);
      item.append(title, detail, generation, exactLink);
      inbox.append(item);
    });
  }
  appendCockpitCollectionState(
    inbox,
    cockpitPresentation.inboxCoverage,
    "No structured attention",
    "The complete authoritative attention source snapshots have no items.",
  );

  const activity = byId("cockpit-activity-list");
  activity.replaceChildren();
  if (cockpitPresentation.activities.length > 0) {
    cockpitPresentation.activities.forEach((entry) => {
      const item = document.createElement("li");
      const title = document.createElement("strong");
      title.textContent = entry.label;
      const detail = document.createElement("span");
      detail.textContent = `${consoleMsAgo(entry.at)} · ${consoleSentence(entry.source || entry.kind)} · ${words(entry.freshness)} · source revision ${entry.source_revision}`;
      if (entry.deep_link) {
        const exactLink = document.createElement("a");
        exactLink.href = entry.deep_link;
        exactLink.textContent = "View";
        exactLink.setAttribute("aria-label", `Open exact context for ${entry.label} at source revision ${entry.source_revision}`);
        item.append(title, detail, exactLink);
      } else {
        item.append(title, detail);
      }
      activity.append(item);
    });
  }
  appendCockpitCollectionState(
    activity,
    cockpitPresentation.activityCoverage,
    "No structured activity",
    "The complete lineage and review projections contain no activity. Retained history remains in Conversation.",
  );
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
    ? "Updated just now"
    : inventory.state === "refused"
      ? "The list is not available"
      : "Not loaded yet";
  const root = byId("platform-session-list");
  root.replaceChildren();
  if (sessions.length === 0) {
    const empty = document.createElement("div");
    empty.className = "integration-empty";
    empty.textContent = inventory.state === "refused"
      ? `Conversations not available: ${inventory.explanation || "the server refused the request"}.`
      : "No conversations yet. Start a task above.";
    root.append(empty);
    return;
  }
  // The server's summary is only a state word ("open"/"closed"), so rows are
  // titled by time and short id, newest first.
  const ordered = [...sessions].sort((left, right) => consoleSessionObservedMs(right) - consoleSessionObservedMs(left));
  ordered.forEach((session) => {
    const record = session.session || {};
    const coordinate = record.resource || {};
    const row = consoleRow("platform-session-option", () => consoleOpenSession(coordinate.id));
    row.classList.toggle("is-selected", coordinate.id === platformSelectedSession);
    // A retained session can be read and resumed without a live attachment.
    row.dataset.sessionId = coordinate.id || "";
    const main = document.createElement("span");
    main.className = "cell-main";
    const title = document.createElement("strong");
    title.setAttribute("data-i18n-skip", "");
    title.textContent = consoleSessionTitle(session);
    const detail = document.createElement("small");
    // Whether replies are possible is only known once the conversation is
    // opened, so the row no longer guesses ("Read only" was wrong for tasks).
    detail.hidden = true;
    main.append(title, detail);
    const stateWord = String(record.summary || "").trim().toLowerCase();
    const state = consoleSessionWorking(coordinate.id)
      ? consoleBadge("Working", "info")
      : consoleBadge(stateWord === "open" ? "Open" : stateWord === "closed" ? "Closed" : stateWord ? consoleSentence(stateWord) : "Unknown", "quiet");
    if (!consoleSessionWorking(coordinate.id)) state.classList.add("plain");
    const observed = consoleSessionObservedMs(session);
    const updated = consoleCell(observed ? consoleMsAgo(observed) : "", "cell cell-time");
    if (observed) updated.title = memoryDateLabel(observed);
    const reference = consoleCell(consoleShortId(coordinate.id), "cell cell-mono");
    reference.title = coordinate.id || "";
    reference.setAttribute("data-i18n-skip", "");
    row.append(main, consoleCellWrap(state), updated, reference);
    root.append(row);
  });
  consoleCapList(root, "sessions", "data-session-id", platformSelectedSession);
  if (platformSelectedSession && !sessions.some((session) => session.session?.resource?.id === platformSelectedSession)) {
    platformExactRevision = null;
    byId("platform-session-empty").hidden = true;
    byId("platform-session-detail").hidden = false;
    byId("platform-session-status").textContent = "This conversation is no longer in the list.";
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
      item.textContent = `History not available: ${history?.explanation || "no reason given"}.`;
      root.append(item);
    }
    byId("platform-history-more").hidden = true;
    return;
  }
  if (history.state === "resync_required") {
    root.replaceChildren();
    const item = document.createElement("div");
    item.className = "platform-history-notice";
    item.textContent = "Older messages were trimmed. Reloading the conversation…";
    root.append(item);
    byId("platform-history-more").hidden = true;
    window.setTimeout(() => openPlatformSession(platformSelectedSession), 0);
    return;
  }
  if (history.state !== "page") return;
  if (replace) platformHistoryAutoPages = 0;
  platformHistoryCursor = history.terminal_cursor;
  const events = Array.isArray(history.events) ? history.events : [];
  events.forEach((event) => {
    if (event.kind === "message") {
      if (replace && event.role === "user" && !root.querySelector('[data-role="user"]')) {
        consoleLearnTitle(platformSelectedSession, event.text);
      }
      root.append(historyMessage(event));
      return;
    }
    if (event.kind === "run_state" && (event.state === "failed" || event.state === "cancelled")) {
      const item = document.createElement("p");
      item.className = `platform-history-run is-${event.state}`;
      item.textContent = RUN_STATE_LABELS[event.state] || `Run ${words(event.state)}`;
      root.append(item);
      return;
    }
    // Everything between two messages (tool steps, run start, and the
    // content-free events the server withholds) folds into one line.
    addHistoryStep(historyStepGroup(root), event);
  });
  const more = history.has_more === true;
  if (replace && events.length === 0 && !more) {
    const empty = document.createElement("div");
    empty.className = "platform-history-notice is-empty";
    empty.textContent = "No messages were saved in this conversation.";
    root.append(empty);
  }
  byId("platform-history-more").hidden = !more;
  // The answer usually sits on a later page, so keep reading (bounded)
  // instead of leaving it behind a button.
  if (more && platformHistoryAutoPages < HISTORY_AUTO_PAGES) {
    platformHistoryAutoPages += 1;
    window.setTimeout(() => pagePlatformHistory(), 0);
  }
  root.scrollTop = root.scrollHeight;
}

const HISTORY_AUTO_PAGES = 20;
const RUN_STATE_LABELS = {
  completed: "Monique finished",
  failed: "The run failed",
  cancelled: "The run was cancelled",
};
const TOOL_STEP_LABELS = {
  todo: "planned",
  write: "wrote files",
  edit: "edited files",
  bash: "ran commands",
  read: "read files",
  grep: "searched",
  glob: "searched",
  web: "browsed",
};

function historyMessage(event) {
  const user = event.role === "user";
  const item = document.createElement("article");
  item.className = "platform-history-event is-message";
  item.dataset.role = user ? "user" : "assistant";
  item.dataset.cursor = event.cursor || "";
  const head = document.createElement("header");
  const who = document.createElement("strong");
  who.textContent = user ? "You" : event.role === "assistant" ? "Monique" : words(event.role || "message");
  head.append(who);
  if (validPlatformDecimal(event.at_ms)) {
    const at = document.createElement("time");
    at.textContent = new Date(Number(event.at_ms)).toLocaleString(localeTag(), { dateStyle: "medium", timeStyle: "short" });
    head.append(at);
  }
  const content = document.createElement("section");
  content.className = "platform-history-text";
  content.setAttribute("data-i18n-skip", "");
  appendMessageText(content, event.text || "");
  if (event.truncated === true) {
    const note = document.createElement("small");
    note.textContent = "Shortened by the server.";
    content.append(note);
  }
  item.append(head, content);
  return item;
}

// Code fences become blocks and `inline code` stays code; everything else is
// plain text. Built node by node, never parsed as HTML.
function appendMessageText(root, text) {
  text.split(/```/).forEach((part, index) => {
    if (index % 2 === 1) {
      const pre = document.createElement("pre");
      const code = document.createElement("code");
      // The fence's language tag may arrive on the same line once whitespace
      // is collapsed upstream, so drop a known tag either way.
      code.textContent = part
        .replace(/^[\w-]*\n/, "")
        .replace(/^\s*(text|txt|bash|sh|shell|console|json|js|ts|python|py|diff|html|css|rust|toml|yaml)\s+/, "")
        .replace(/\s+$/, "");
      pre.append(code);
      root.append(pre);
      return;
    }
    part.split(/\n{2,}/).forEach((paragraph) => {
      if (!paragraph.trim()) return;
      const p = document.createElement("p");
      paragraph.split(/(`[^`\n]+`)/).forEach((piece) => {
        if (piece.startsWith("`") && piece.endsWith("`") && piece.length > 2) {
          const code = document.createElement("code");
          code.textContent = piece.slice(1, -1);
          p.append(code);
        } else if (piece) {
          p.append(document.createTextNode(piece));
        }
      });
      root.append(p);
    });
  });
}

function historyStepGroup(root) {
  const last = root.lastElementChild;
  if (last?.classList.contains("platform-history-steps")) return last;
  const group = document.createElement("details");
  group.className = "platform-history-steps";
  group.dataset.count = "0";
  const summary = document.createElement("summary");
  const list = document.createElement("ol");
  group.append(summary, list);
  root.append(group);
  return group;
}

function addHistoryStep(group, event) {
  group.dataset.count = String(Number(group.dataset.count) + 1);
  if (event.kind === "tool_state" && event.label) {
    const done = new Set((group.dataset.tools || "").split(",").filter(Boolean));
    done.add(event.label);
    group.dataset.tools = [...done].join(",");
    if (event.state === "completed" || event.state === "failed") {
      const step = document.createElement("li");
      step.textContent = `${TOOL_STEP_LABELS[event.label] || words(event.label)}${event.state === "failed" ? " (failed)" : ""}`;
      step.setAttribute("data-i18n-skip", "");
      group.querySelector("ol").append(step);
    }
  }
  const tools = (group.dataset.tools || "").split(",").filter(Boolean)
    .map((label) => TOOL_STEP_LABELS[label] || words(label));
  const count = Number(group.dataset.count);
  group.querySelector("summary").textContent = tools.length
    ? `Worked: ${tools.join(", ")} · ${count} ${count === 1 ? "step" : "steps"}`
    : `Working · ${count} ${count === 1 ? "step" : "steps"}`;
}

function renderPlatformReceipt(view) {
  const root = byId("platform-receipt");
  root.hidden = false;
  root.dataset.state = view.state;
  if (view.state === "ambiguous") {
    root.textContent = "Not sure your reply arrived. Checking, without sending it twice.";
    return;
  }
  if (view.state === "refused") {
    root.textContent = `Not accepted (${words(view.outcome)}): ${view.explanation}`;
    return;
  }
  const receipt = view.receipt || {};
  root.textContent = `Reply ${words(receipt.outcome || "unknown")} · ${words(receipt.lifecycle || "unknown")}.`;
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
    ? "Waiting for your last reply to be confirmed before you can send another."
    : revision
      ? `You can reply. Monique continues this task with your message. (version ${revision})`
      : "Replies are not available for this conversation right now.";
}

async function openPlatformSession(sessionId) {
  if (!sessionId || platformBusy) return;
  platformBusy = true;
  byId("platform-session-empty").hidden = true;
  byId("platform-session-detail").hidden = false;
  byId("platform-session-status").textContent = "Opening conversation…";
  consoleTaskDrawerOpened();
  settlePlatformFence(null);
  try {
    const view = await platformPost({ action: "open", session_id: sessionId });
    if (view.state === "refused") {
      renderPlatformReceipt(view);
      byId("platform-session-status").textContent = `Could not open · ${words(view.outcome)}`;
      return;
    }
    if (view.state !== "open") throw new Error("Unexpected retained-session response");
    const record = view.session?.session || {};
    const coordinate = record.resource || {};
    byId("platform-session-coordinate").textContent = `${coordinate.authority || "automonique"} / ${coordinate.kind || "session"} / ${coordinate.id || sessionId}`;
    byId("platform-session-summary").textContent = consoleSessionTitle(view.session || {});
    // Replies are allowed; what is not claimed is control of a live run.
    byId("platform-session-posture").textContent = record.freshness === "stale" ? "Out of date · reply only" : "Up to date · reply only";
    const approvals = view.command?.state === "ready" && Array.isArray(view.command.pending_approvals) ? view.command.pending_approvals.length : 0;
    // A run target is not proof that anything is executing, so it is named as linked only.
    byId("platform-session-status").textContent = `${view.attachment_cursor ? "Live" : "Saved history"}${approvals === 0 ? "" : ` · ${approvals} to approve`}`;
    consoleSyncTaskDrawerTitle();
    renderPlatformHistory(view.history, true);
    settlePlatformFence(view.command);
  } catch (error) {
    byId("platform-session-status").textContent = `Conversation not available: ${error.message}`;
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
  // The exact revision this reply is fenced against, never re-read from the
  // note's visible (and translatable) text.
  const revisionText = platformExactRevision;
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
    if (platformTask?.pending) await reconcilePlatformTask();
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
    empty.textContent = "No tools are connected yet.";
    root.append(empty);
    return;
  }
  tools.forEach((tool) => {
    const key = `${tool.server}:${tool.name}`;
    const row = consoleRow("tool-card", () => consoleOpenTool(key));
    row.dataset.toolKey = key;
    row.classList.toggle("is-selected", consoleState.opsKind === "tool" && consoleState.opsKey === key);
    const main = document.createElement("span");
    main.className = "cell-main";
    const title = document.createElement("strong");
    title.setAttribute("data-i18n-skip", "");
    title.textContent = operationLabel(tool.name);
    const description = document.createElement("small");
    if (tool.description) description.setAttribute("data-i18n-skip", "");
    description.textContent = tool.description || "Connected service tool.";
    main.append(title, description);
    const service = document.createElement("span");
    service.className = "source-pill";
    service.textContent = operationLabel(tool.surface);
    service.title = `${operationLabel(tool.category)} · ${tool.server}`;
    const access = consoleBadge(tool.authority === "read_only" ? "Read only" : "Needs approval", tool.authority === "read_only" ? "ok" : "warn");
    const input = consoleCell(tool.requires_input ? "Needs details" : "Ready", "cell cell-time");
    row.append(main, consoleCellWrap(service), consoleCellWrap(access), input);
    root.append(row);
  });
  consoleCapList(root, "tools", "data-tool-key", consoleState.opsKind === "tool" ? consoleState.opsKey : null);
  if (consoleState.opsKind === "tool") consoleOpenTool(consoleState.opsKey, false);
}

function renderToolDrawer(tool) {
  byId("ops-drawer-kicker").textContent = `${operationLabel(tool.surface)} tool · ${operationLabel(tool.category)}`;
  const title = byId("ops-drawer-title");
  title.setAttribute("data-i18n-skip", "");
  title.textContent = operationLabel(tool.name);
  const body = byId("ops-drawer-body");
  body.replaceChildren();
  const summary = document.createElement("section");
  summary.className = "drawer-section";
  const description = document.createElement("p");
  description.className = "drawer-lede";
  if (tool.description) description.setAttribute("data-i18n-skip", "");
  description.textContent = tool.description || "Connected service tool.";
  const badges = document.createElement("div");
  badges.className = "drawer-badges";
  badges.append(consoleBadge(tool.authority === "read_only" ? "Read only" : "Needs approval", tool.authority === "read_only" ? "ok" : "warn"), consoleBadge(tool.requires_input ? "Needs details" : "Ready", "quiet"));
  const note = document.createElement("p");
  note.className = "inline-hint";
  note.textContent = tool.authority === "read_only"
    ? "Monique can use this right away. It only reads data."
    : "This changes data. Monique shows you exactly what it will do and waits for your approval.";
  const actions = document.createElement("div");
  actions.className = "drawer-actions";
  const use = document.createElement("button");
  use.type = "button";
  use.className = "button primary small";
  use.textContent = "Use with assistant";
  use.dataset.openChat = `Help me use the ${operationLabel(tool.surface)} capability “${operationLabel(tool.name)}”. Explain what it does, collect any required details, and stage any mutation for my approval.`;
  actions.append(use);
  summary.append(description, badges, note, actions);
  const detailsSection = document.createElement("section");
  detailsSection.className = "drawer-section";
  const detailsTitle = document.createElement("h3");
  detailsTitle.textContent = "Details";
  const details = document.createElement("dl");
  details.className = "kv";
  [["Service", operationLabel(tool.surface)], ["Category", operationLabel(tool.category)], ["Server", tool.server], ["Technical name", tool.name]]
    .forEach(([labelText, value]) => details.append(consoleFact(labelText, value)));
  detailsSection.append(detailsTitle, details);
  body.append(summary, detailsSection);
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
  if (timestamp === null) return value || "-";
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
    empty: "No tickets right now.",
    no_read_surface: "Support and Manage are connected but cannot list tickets.",
    input_required: "Monique needs more details to list these tickets. Ask the assistant.",
    unavailable: "Tickets are not available right now.",
    degraded: "One source is down. Tickets from the other are shown below.",
    not_attached: "Connect Support and Manage to see tickets here.",
  };
  return messages[health] || "No tickets match these filters.";
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
  valueNode.textContent = value || "-";
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
    ? `${visible.length.toLocaleString(localeTag())} of ${tickets.length.toLocaleString(localeTag())} tickets`
    : ticketEmptyMessage(health);
  const sources = operationsSnapshot?.tickets?.sources || [];
  byId("tickets-source").textContent = sources.length
    ? sources.map((source) => `${operationLabel(source.surface)}: ${translatePhrase(operationLabel(source.health)).toLocaleLowerCase(localeTag())}`).join(" · ")
    : "Waiting for Support and Manage";
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
      action.textContent = "Ask assistant";
      action.dataset.openChat = "Inspect the available Support and Manage capabilities and help me retrieve or review the right work queue.";
    }
    empty.append(title, action);
    root.append(empty);
    return;
  }
  visible.forEach((ticket) => {
    const row = consoleRow(`ticket-row priority-${ticket.priority}`, () => consoleOpenTicket(ticket.id));
    row.dataset.ticketId = ticket.id;
    row.classList.toggle("is-selected", consoleState.ticketId === ticket.id);
    const reference = consoleCell(ticketReferenceLabel(ticket.id), "cell cell-mono");
    reference.setAttribute("data-i18n-skip", "");
    reference.title = ticket.id.startsWith("#") ? ticket.id : `#${ticket.id}`;
    const titleCell = document.createElement("span");
    titleCell.className = "cell-main";
    const titleLine = document.createElement("span");
    titleLine.className = "ticket-row-title";
    const title = document.createElement("strong");
    title.setAttribute("data-i18n-skip", "");
    title.textContent = ticket.title;
    titleLine.append(title);
    if (Number.isSafeInteger(ticket.comments) && ticket.comments > 0) {
      const comments = document.createElement("span");
      comments.className = "comments";
      comments.textContent = String(ticket.comments);
      comments.setAttribute("aria-label", `${ticket.comments} comments`);
      titleLine.append(comments);
    }
    const context = document.createElement("small");
    context.setAttribute("data-i18n-skip", "");
    context.textContent = [ticket.site || ticket.tenant, ticket.requester].filter(Boolean).join(" · ");
    titleCell.append(titleLine);
    if (context.textContent) titleCell.append(context);
    const source = document.createElement("span");
    source.className = "source-pill";
    source.textContent = ticket.integration ? operationLabel(ticket.integration) : "Other";
    const workflowConflict = (ticket.status === "closed" || ticket.status === "done") && !["closed", "done", "unknown"].includes(ticket.workflow);
    const status = consoleBadge(ticketStatusLabel(ticket.status), ticketStatusTone(ticket.status));
    status.classList.add("ticket-status", `status-${ticket.status}`);
    if (workflowConflict) status.title = `Workflow mismatch · ${ticketStatusLabel(ticket.workflow)}`;
    const priority = consolePriority(ticket.priority);
    const assignee = consoleCell(ticket.assignee || "Unassigned", "cell");
    assignee.setAttribute("data-i18n-skip", "");
    if (!ticket.assignee) assignee.removeAttribute("data-i18n-skip");
    const relative = ticketRelativeTime(ticket.updated_at);
    const updated = consoleCell(relative || "", "cell cell-time");
    if (ticket.updated_at) updated.title = ticketDateLabel(ticket.updated_at);
    row.append(reference, titleCell, consoleCellWrap(source), consoleCellWrap(status), consoleCellWrap(priority), assignee, updated);
    root.append(row);
  });
  root.closest(".table").classList.toggle("no-updated", !visible.some((ticket) => ticketRelativeTime(ticket.updated_at)));
  consoleCapList(root, "tickets", "data-ticket-id", consoleState.ticketId);
  consoleRefreshTicketDrawer();
}

function ticketStatusTone(status) {
  return { open: "info", triaging: "info", in_progress: "warn", blocked: "danger", done: "ok", closed: "quiet" }[status] || "quiet";
}

function renderTicketDrawer(ticket) {
  byId("ticket-drawer-kicker").textContent = `${ticket.integration ? operationLabel(ticket.integration) : "Work"} ticket · ${ticket.id.startsWith("#") ? ticket.id : `#${ticket.id}`}`;
  const title = byId("ticket-drawer-title");
  title.setAttribute("data-i18n-skip", "");
  title.textContent = ticket.title;
  const body = byId("ticket-drawer-body");
  body.replaceChildren();
  const badges = document.createElement("div");
  badges.className = "drawer-badges";
  badges.append(consoleBadge(ticketStatusLabel(ticket.status), ticketStatusTone(ticket.status)), consolePriority(ticket.priority));
  const workflowConflict = (ticket.status === "closed" || ticket.status === "done") && !["closed", "done", "unknown"].includes(ticket.workflow);
  if (ticket.workflow && ticket.workflow !== ticket.status) {
    badges.append(consoleBadge(workflowConflict ? `Workflow mismatch · ${ticketStatusLabel(ticket.workflow)}` : `Workflow · ${ticketStatusLabel(ticket.workflow)}`, workflowConflict ? "warn" : "quiet"));
  }
  const actions = document.createElement("div");
  actions.className = "drawer-actions";
  const ask = document.createElement("button");
  ask.type = "button";
  ask.className = "button primary small";
  ask.textContent = "Review with assistant";
  ask.dataset.openChat = `Review this ${ticket.integration || "work"} item ${ticket.id}: “${ticket.title}”. Summarize its current state and recommend the next action without conflating Support, Manage, or GitHub state.`;
  actions.append(ask);
  const href = safeTicketLink(ticket.url);
  if (href) {
    const openLink = document.createElement("a");
    openLink.className = "button ghost small";
    openLink.href = href;
    openLink.target = "_blank";
    openLink.rel = "noreferrer";
    openLink.textContent = `Open in ${ticket.integration ? operationLabel(ticket.integration) : "source"} ↗`;
    actions.append(openLink);
  }
  const summary = document.createElement("section");
  summary.className = "drawer-section";
  summary.append(badges, actions);
  appendTicketCheck(actions, summary, ticket);
  const detailsSection = document.createElement("section");
  detailsSection.className = "drawer-section";
  const detailsTitle = document.createElement("h3");
  detailsTitle.textContent = "Details";
  const details = document.createElement("div");
  details.className = "ticket-details";
  [
    ["Assigned to", ticket.assignee || "Unassigned"],
    ["Requested by", ticket.requester],
    ["Client", ticket.tenant],
    ["Site", ticket.site],
    ["Comments", Number.isSafeInteger(ticket.comments) ? String(ticket.comments) : null],
    ["Created", ticket.created_at ? ticketDateLabel(ticket.created_at) : null, ticket.created_at],
    ["Updated", ticket.updated_at ? ticketDateLabel(ticket.updated_at) : null, ticket.updated_at],
    ["Came from", ticket.source],
    ["Service", ticket.integration_server],
    ["Ticket ID", ticket.id.startsWith("#") ? ticket.id : `#${ticket.id}`],
  ].filter(([, value]) => value).forEach(([labelText, value, exact]) => details.append(ticketDetail(labelText, value, exact)));
  detailsSection.append(detailsTitle, details);
  const conversation = document.createElement("section");
  conversation.className = "drawer-section ticket-conversation";
  conversation.id = "ticket-conversation";
  conversation.dataset.key = ticketConversationKey(ticket);
  body.append(summary, conversation, detailsSection);
}

// One ticket's conversation, read on demand from the service that listed it.
// Entries live for the session; one fetched before the latest ticket list is
// fetched again the next time its drawer is opened.
const ticketConversations = new Map();
const TICKET_CONVERSATION_VISIBLE = 20;

function ticketConversationKey(ticket) {
  return `${ticket.integration_server || ""}\n${ticket.id}`;
}

function loadTicketConversation(ticket, opening) {
  const key = ticketConversationKey(ticket);
  if (!ticket.integration_server || ticket.id === "unreferenced") {
    renderTicketConversation(key, { state: "failed", error: "ticket_detail_unavailable" });
    return;
  }
  let entry = ticketConversations.get(key);
  const outdated = entry && opening && entry.state !== "loading" && (entry.snapshot !== operationsSnapshot || entry.state === "failed");
  if (!entry || outdated) {
    entry = { state: "loading", snapshot: operationsSnapshot, view: null, error: null, expanded: entry?.expanded === true };
    ticketConversations.set(key, entry);
    const pending = entry;
    api("/api/tickets/detail", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ integration_server: ticket.integration_server, id: ticket.id }),
    }).then((view) => {
      pending.state = "ready";
      pending.view = view;
    }, (error) => {
      pending.state = "failed";
      pending.error = error.message;
    }).finally(() => {
      if (ticketConversations.get(key) === pending) renderTicketConversation(key, pending);
    });
  }
  renderTicketConversation(key, entry);
}

// Sources may give epoch seconds or milliseconds instead of ISO text.
function ticketMessageTimestamp(value) {
  const text = String(value || "");
  if (/^\d{9,13}$/.test(text)) {
    const number = Number(text);
    return new Date(number < 1e12 ? number * 1000 : number).toISOString();
  }
  return text;
}

function ticketConversationFailure(category) {
  if (category === "not_found") return "This conversation was not found at its source.";
  if (category === "refused") return "This source does not allow reading the conversation here.";
  return "The conversation could not be loaded right now.";
}

function ticketConversationNote(text) {
  const note = document.createElement("p");
  note.className = "ticket-thread-note";
  note.textContent = text;
  return note;
}

// Plain text with https links made clickable and markdown images shown as a
// named link. Built node by node; nothing is parsed as HTML.
function appendLinkedText(root, text) {
  const pattern = /!\[([^\]\n]{0,120})\]\((https:\/\/[^\s)]+)\)|https:\/\/[^\s<>"')\]]+/g;
  let last = 0;
  for (const match of text.matchAll(pattern)) {
    if (match.index > last) root.append(document.createTextNode(text.slice(last, match.index)));
    const raw = match[2] || match[0].replace(/[.,;:!?]+$/, "");
    const href = safeTicketLink(raw);
    if (href) {
      const link = document.createElement("a");
      link.href = href;
      link.target = "_blank";
      link.rel = "noreferrer";
      link.textContent = match[2] ? `🖼 ${match[1] || "image"}` : raw;
      root.append(link);
      const trailing = match[2] ? "" : match[0].slice(raw.length);
      if (trailing) root.append(document.createTextNode(trailing));
    } else {
      root.append(document.createTextNode(match[0]));
    }
    last = match.index + match[0].length;
  }
  if (last < text.length) root.append(document.createTextNode(text.slice(last)));
}

function ticketMessageCard(message) {
  const item = document.createElement("li");
  item.className = "ticket-message";
  if (message.direction === "inbound" || message.direction === "outbound") item.dataset.direction = message.direction;
  if (message.internal === true) item.dataset.internal = "true";
  const meta = document.createElement("div");
  meta.className = "ticket-message-meta";
  const author = document.createElement("strong");
  if (message.author) {
    author.setAttribute("data-i18n-skip", "");
    author.textContent = message.author;
  } else {
    author.textContent = "Unknown sender";
  }
  meta.append(author);
  if (message.internal === true) meta.append(consoleBadge("Internal note", "warn"));
  const at = ticketMessageTimestamp(message.at);
  const relative = ticketRelativeTime(at);
  if (relative) {
    const time = document.createElement("time");
    time.setAttribute("data-i18n-skip", "");
    time.dateTime = at;
    time.title = ticketDateLabel(at);
    time.textContent = relative;
    meta.append(time);
  }
  const body = document.createElement("p");
  body.className = "ticket-message-body";
  body.setAttribute("data-i18n-skip", "");
  appendLinkedText(body, typeof message.body === "string" ? message.body : "");
  item.append(meta, body);
  if (message.body_truncated === true) {
    const cut = document.createElement("span");
    cut.className = "ticket-message-cut";
    cut.textContent = "Message shortened";
    item.append(cut);
  }
  return item;
}

function renderTicketConversation(key, entry) {
  const section = byId("ticket-conversation");
  if (!section || section.dataset.key !== key) return;
  const heading = document.createElement("h3");
  heading.textContent = "Conversation";
  section.replaceChildren(heading);
  if (entry.state === "loading") {
    section.append(ticketConversationNote("Loading the conversation…"));
    return;
  }
  if (entry.state === "failed") {
    section.append(ticketConversationNote(ticketConversationFailure(entry.error)));
    return;
  }
  const messages = Array.isArray(entry.view?.messages) ? entry.view.messages : [];
  if (!messages.length) {
    section.append(ticketConversationNote("No messages in this conversation."));
    return;
  }
  const hidden = entry.expanded ? 0 : Math.max(0, messages.length - TICKET_CONVERSATION_VISIBLE);
  if (hidden > 0) {
    const earlier = document.createElement("button");
    earlier.type = "button";
    earlier.className = "table-more";
    earlier.textContent = `Show earlier (${hidden})`;
    earlier.addEventListener("click", () => {
      entry.expanded = true;
      renderTicketConversation(key, entry);
    });
    section.append(earlier);
  } else if (entry.view?.truncated === true) {
    section.append(ticketConversationNote("Older messages are not shown."));
  }
  const thread = document.createElement("ol");
  thread.className = "ticket-thread";
  messages.slice(hidden).forEach((message) => thread.append(ticketMessageCard(message)));
  section.append(thread);
}

function renderOperations(view) {
  operationsSnapshot = view;
  const [title, detail] = operationsMessage(view.health);
  byId("operations-banner").dataset.state = view.health;
  byId("operations-health").textContent = title;
  byId("operations-detail").textContent = detail;
  byId("operations-authority").textContent = ["attached", "degraded"].includes(view.health) ? "CONNECTED" : "NOT CONNECTED";
  byId("operations-tools").textContent = count(view.tools_total);
  byId("operations-reads").textContent = count(view.read_only_tools);
  byId("operations-actions").textContent = count(view.approval_tools);
  byId("operations-pending").textContent = count(view.pending_actions);
  byId("operations-catalog-tag").textContent = ["attached", "degraded"].includes(view.health) ? `${count(view.tools_total)} LIVE` : "UNAVAILABLE";
  byId("operations-catalog-tag").dataset.state = ["attached", "degraded"].includes(view.health) ? "ready" : "unavailable";
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
    byId("operations-health").textContent = "Support and Manage are not answering";
    byId("operations-detail").textContent = error.message;
    byId("tickets-state").textContent = "Tickets are not available right now";
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
const platformTaskStorageKey = "monique-platform-task-v1";
let platformTaskBusy = false;
let platformTaskStorageError = false;
let platformTask = (() => {
  try {
    const raw = sessionStorage.getItem(platformTaskStorageKey);
    if (!raw) return null;
    const value = JSON.parse(raw);
    if (typeof value.nodeId !== "string" || !/^dashboard-task-[a-zA-Z0-9-]+$/.test(value.key) ||
        !validPlatformDecimal(value.revision, false) || typeof value.pending !== "boolean" ||
        (value.sessionId !== null && typeof value.sessionId !== "string")) throw new Error("Invalid task handle");
    return value;
  } catch (_error) {
    platformTaskStorageError = true;
    return null;
  }
})();

function savePlatformTask(value) {
  // Save only correlation metadata, never the task text. A reload may only
  // reconcile this handle: it must never create another execution.
  sessionStorage.setItem(platformTaskStorageKey, JSON.stringify(value));
  if (sessionStorage.getItem(platformTaskStorageKey) !== JSON.stringify(value)) throw new Error("Task recovery storage unavailable");
  platformTask = value;
}

function renderPlatformTask(message) {
  const pending = platformTask?.pending === true;
  byId("platform-task-submit").disabled = platformTaskBusy || pending || platformTaskStorageError;
  byId("platform-task-text").disabled = platformTaskBusy || pending || platformTaskStorageError;
  byId("platform-task-check").hidden = !pending;
  byId("platform-task-check").disabled = platformTaskBusy;
  byId("platform-task-open").hidden = !platformTask?.sessionId || pending;
  if (message) byId("platform-task-status").textContent = message;
  else if (platformTaskStorageError) byId("platform-task-status").textContent = "Task recovery storage is unavailable. Restore browser storage before starting work.";
  else if (pending) byId("platform-task-status").textContent = "Checking the previous task’s receipt…";
  else if (platformTask?.sessionId) byId("platform-task-status").textContent = "Task completed. Open its session to read the result or continue.";
}

function platformTaskPost(body) {
  return api("/api/platform/task", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
}

function acceptPlatformTaskResult(view) {
  const outcome = view.state === "receipt" ? view.receipt?.outcome : view.state === "refused" ? view.outcome : null;
  if (["completed", "rejected", "conflict"].includes(outcome)) {
    const sessionId = outcome === "completed" && typeof view.session_id === "string" ? view.session_id : null;
    savePlatformTask({ ...platformTask, pending: false, sessionId });
    if (outcome === "completed") {
      byId("platform-task-text").value = "";
      renderPlatformTask(sessionId ? "Task completed. Its conversation is open on the right." : "Task completed; no retained session was returned.");
      // Show the result straight away instead of asking for another click.
      if (sessionId) window.setTimeout(() => consoleOpenSession(sessionId), 0);
    } else renderPlatformTask(`Task did not complete: ${view.receipt?.explanation || view.explanation || outcome}. You can submit a new task.`);
  } else if (outcome === "accepted") {
    byId("platform-task-text").value = "";
    renderPlatformTask("Task accepted. Waiting for execution to finish…");
  } else renderPlatformTask("Task outcome is uncertain. Check its receipt; do not resubmit.");
}

async function submitPlatformTask(event) {
  event.preventDefault();
  if (platformTaskBusy || platformTask?.pending || platformTaskStorageError) return;
  const text = byId("platform-task-text").value.trim();
  if (!text) return;
  platformTaskBusy = true;
  renderPlatformTask("Preparing task…");
  let submitted = false;
  try {
    const ready = await platformTaskPost({ action: "prepare" });
    if (ready.state !== "ready" || typeof ready.node_id !== "string" || !validPlatformDecimal(ready.expected_revision, false)) throw new Error("No ready task runner");
    savePlatformTask({ nodeId: ready.node_id, revision: ready.expected_revision, key: `dashboard-task-${crypto.randomUUID()}`, pending: true, sessionId: null });
    submitted = true;
    acceptPlatformTaskResult(await platformTaskPost({ action: "submit", node_id: platformTask.nodeId, expected_revision: platformTask.revision, idempotency_key: platformTask.key, text }));
  } catch (_error) {
    renderPlatformTask(submitted ? "Task outcome is uncertain. Check its receipt; do not resubmit." : "Task was not submitted. Check the connection and browser storage, then try again.");
  } finally {
    platformTaskBusy = false;
    renderPlatformTask(byId("platform-task-status").textContent);
  }
}

async function reconcilePlatformTask() {
  if (!platformTask?.pending || platformTaskBusy) return;
  platformTaskBusy = true;
  renderPlatformTask(byId("platform-task-status").textContent);
  try {
    acceptPlatformTaskResult(await platformTaskPost({ action: "reconcile", node_id: platformTask.nodeId, idempotency_key: platformTask.key }));
  } catch (_error) {
    renderPlatformTask("Task status is unavailable. Check again; the task will not be resubmitted.");
  } finally {
    platformTaskBusy = false;
    renderPlatformTask(byId("platform-task-status").textContent);
  }
}

byId("platform-new-task-form").addEventListener("submit", submitPlatformTask);
byId("platform-task-check").addEventListener("click", reconcilePlatformTask);
byId("platform-task-open").addEventListener("click", async () => {
  if (!platformTask?.sessionId) return;
  document.querySelector('[data-cockpit-surface="conversation"]').click();
  await selectPlatformSession(platformTask.sessionId);
  byId("platform-session-detail").scrollIntoView({ block: "start", behavior: "smooth" });
});
renderPlatformTask();

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
  if (cockpitPresentation?.[action]?.available !== true) {
    toast("The current exact capability is unavailable; review a fresh preview.", "error");
    return;
  }
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
  if (action === "rerunCheck" && !cockpitRerunPreview) return;
  const idempotencyKey = newCockpitReceiptId("cockpit-review");
  const handle = globalThis.AutomoniquePlatformCockpit.prepareControlHandle(
    capability,
    action,
    idempotencyKey,
    action === "rerunCheck" ? cockpitRerunPreview?.receipt_correlation_digest : null,
  );
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
  } : action === "approveReview" ? {
    action: "approve_review",
    project_id: capability.project_id,
    workspace_id: capability.workspace_id,
    expected_revision: capability.exact_revision,
    expected_review_revision: capability.exact_review_revision,
    idempotency_key: idempotencyKey,
  } : (() => {
    const checkId = byId("cockpit-rerun-check-target").value;
    const target = (capability.targets || []).find((candidate) => candidate.check_id === checkId);
    return target ? {
      action: "rerun_check",
      project_id: target.project_id,
      workspace_id: target.workspace_id,
      expected_revision: target.exact_revision,
      check_id: target.check_id,
      expected_check_revision: target.exact_check_revision,
      confirmation_digest: cockpitRerunPreview?.confirmation_digest,
      idempotency_key: idempotencyKey,
    } : null;
  })();
  if (!body) {
    clearCockpitControl();
    toast("An exact server-advertised check must be selected.", "error");
    return;
  };
  if (action === "addComment" && !body.body) {
    clearCockpitControl();
    toast("A bounded comment body is required.", "error");
    return;
  }
  if (action === "rerunCheck") cockpitRerunPreview = null;
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

async function previewCockpitRerun() {
  const capability = cockpitPresentation?.reviewActions?.rerunCheck;
  if (!capability?.available || cockpitControlHandle || cockpitControlBusy) return;
  const checkId = byId("cockpit-rerun-check-target").value;
  const target = (capability.targets || []).find((candidate) => candidate.check_id === checkId);
  if (!target) return;
  cockpitControlBusy = true;
  try {
    const preview = await api("/api/platform/cockpit", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        action: "preview_rerun_check",
        project_id: target.project_id,
        workspace_id: target.workspace_id,
        expected_revision: target.exact_revision,
        check_id: target.check_id,
        expected_check_revision: target.exact_check_revision,
      }),
    });
    if (preview?.state !== "confirmation_preview"
      || preview.confirmation_digest !== target.confirmation_digest
      || preview.receipt_correlation_digest !== target.receipt_correlation_digest
      || preview.check_id !== target.check_id
      || preview.exact_revision !== target.exact_revision
      || preview.exact_check_revision !== target.exact_check_revision) {
      throw new Error("invalid rerun preview");
    }
    cockpitRerunPreview = Object.freeze(preview);
  } catch (_error) {
    cockpitRerunPreview = null;
    toast("The exact rerun preview is unavailable; nothing was sent.", "error");
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
      receipt_correlation_digest: handle.receipt_correlation_digest,
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
byId("cockpit-rerun-check").addEventListener("click", previewCockpitRerun);
byId("cockpit-rerun-confirm").addEventListener("click", () => submitCockpitReview("rerunCheck"));
byId("cockpit-rerun-cancel").addEventListener("click", () => {
  cockpitRerunPreview = null;
  renderHostedCockpit(cockpitSnapshot || {});
});
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
  "Web boundary": { category: "security", description: "Who can reach this page and request limits." },
  Memory: { category: "ai", description: "How Monique stores and finds what it remembers." },
  "Agent authentication": { category: "ai security", description: "Whether agents are signed in and ready to work." },
  Providers: { category: "ai", description: "The AI models Monique uses." },
  Connectors: { category: "integrations", description: "Slack, Telegram, GitHub and other connections." },
  "Manage AI Operations": { category: "integrations ai", description: "Tools and tickets from Manage." },
  "Governance & safety": { category: "security", description: "Approvals, audit log and backups." },
  "Extensions & automation": { category: "ai integrations", description: "Extra tools, knowledge and automations." },
});
const configurationSectionTitles = Object.freeze({
  "Web boundary": "Web access",
  "Agent authentication": "Agent sign-in",
  Providers: "AI providers",
  Connectors: "Connections",
  "Manage AI Operations": "Manage",
  "Governance & safety": "Safety",
  "Extensions & automation": "Extensions",
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
  if (typeof value === "boolean") return value ? "On" : "Off";
  if (value === null || value === undefined) return "-";
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

const connectionTestResults = new Map();
let connectionTestActive = false;
const connectionTestReasons = {
  bot_authenticated: "Bot authentication verified.",
  account_authenticated: "Account authentication verified.",
  support_read_verified: "Support access verified.",
  tools_discovered: "Tool discovery verified.",
  not_configured: "Connection is not configured.",
  not_enabled: "Configure an authorized user before testing.",
  invalid_configuration: "Review the connection configuration on the server.",
  credentials_unavailable: "Reconnect GitHub on the server, then retry.",
  authentication_rejected: "Authentication rejected. Reconnect and retry.",
  request_rejected: "Access refused. Check the connection permissions.",
  service_unavailable: "Service unavailable. Check access and retry.",
  timed_out: "The connection timed out. Try again.",
  discovery_failed: "Some MCP servers could not list their tools.",
  discovery_timed_out: "MCP discovery timed out before all servers were checked.",
};

function renderConnectionResult(key, output) {
  const result = connectionTestResults.get(key);
  output.replaceChildren();
  output.hidden = !result;
  if (!result) return;
  output.dataset.state = result.ok ? "success" : "error";
  const message = document.createElement("span");
  message.textContent = translatePhrase(connectionTestReasons[result.reason] || "The check could not finish. Try again.");
  output.append(message);
  if (Number.isSafeInteger(result.servers_passed) && Number.isSafeInteger(result.servers_total)) {
    const count = document.createElement("span");
    count.textContent = `${result.servers_passed}/${result.servers_total} ${translatePhrase("servers verified")}`;
    output.append(count);
  }
  if (Number.isSafeInteger(result.checked_at_ms) && result.checked_at_ms > 0) {
    const time = document.createElement("time");
    time.dateTime = new Date(result.checked_at_ms).toISOString();
    time.textContent = `${translatePhrase("Checked")} ${new Intl.DateTimeFormat(localeTag(), { hour: "2-digit", minute: "2-digit", second: "2-digit" }).format(result.checked_at_ms)}`;
    time.title = new Date(result.checked_at_ms).toLocaleString(localeTag());
    output.append(time);
  }
}

function addConnectionTest(row, detail, key) {
  if (!["slack", "telegram", "github", "support", "mcp"].includes(key)) return;
  row.dataset.connection = key;
  row.classList.add("connection-row");
  detail.classList.add("connection-state");
  const controls = document.createElement("dd");
  controls.className = "connection-controls";
  const button = document.createElement("button");
  button.type = "button";
  button.className = "connection-test-button";
  button.dataset.connectionTest = key;
  button.disabled = connectionTestActive;
  button.textContent = translatePhrase("Test");
  const name = { slack: "Slack", telegram: "Telegram", github: "GitHub", support: translatePhrase("Support"), mcp: "MCP" }[key];
  button.setAttribute("aria-label", `${translatePhrase("Test")} ${name}`);
  const output = document.createElement("dd");
  output.className = "connection-test-result";
  output.setAttribute("role", "status");
  output.setAttribute("aria-live", "polite");
  renderConnectionResult(key, output);
  button.addEventListener("click", async () => {
    if (connectionTestActive) return;
    connectionTestActive = true;
    document.querySelectorAll("[data-connection-test]").forEach((item) => { item.disabled = true; });
    button.textContent = translatePhrase("Testing…");
    button.setAttribute("aria-busy", "true");
    output.hidden = false;
    output.dataset.state = "pending";
    output.textContent = translatePhrase("Checking connection…");
    try {
      const result = await api("/api/connections/test", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ connector: key }), signal: AbortSignal.timeout(25000),
      });
      if (result.connector !== key || typeof result.ok !== "boolean") throw new Error("invalid_response");
      connectionTestResults.set(key, result);
      renderConnectionResult(key, output);
    } catch (error) {
      connectionTestResults.delete(key);
      output.dataset.state = "error";
      output.textContent = translatePhrase(error.message === "connection_test_busy" ? "Another connection test is running. Try again shortly." : "The check could not finish. Try again.");
    } finally {
      connectionTestActive = false;
      document.querySelectorAll("[data-connection-test]").forEach((item) => { item.disabled = false; });
      button.textContent = translatePhrase("Test again");
      button.removeAttribute("aria-busy");
    }
  });
  controls.append(button);
  row.append(controls, output);
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
  heading.textContent = configurationSectionTitles[title] || title;
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
    state.textContent = configuredValues.length === 0 || configuredValues.some(Boolean) ? "ON" : "OFF";
  }
  headingWrap.append(headingText, state);
  const list = document.createElement("dl");
  list.className = "config-list";
  Object.entries(values || {}).forEach(([key, value]) => {
    const row = document.createElement("div");
    if (/(seconds|bytes|count|depth|limit)/.test(key)) row.dataset.configTechnical = "true";
    const term = document.createElement("dt");
    term.textContent = key === "github" ? "GitHub" : label(key);
    const detail = document.createElement("dd");
    detail.textContent = configurationValue(key, value);
    if (typeof value === "boolean") detail.className = value ? "boolean-true" : "boolean-false";
    if (title === "Agent authentication" && key === "status") {
      detail.className = value === "authenticated" ? "auth-good" : value === "configured_unverified" ? "auth-warning" : "auth-danger";
    }
    row.append(term, detail);
    if (title === "Connectors") addConnectionTest(row, detail, key);
    list.append(row);
  });
  const footer = document.createElement("div");
  footer.className = "config-card-footer";
  const scope = document.createElement("small");
  scope.textContent = title === "Connectors" ? "Read-only tests · no messages sent" : "From the server · no secrets";
  const action = document.createElement("button");
  action.className = "config-inline-action";
  action.type = "button";
  action.textContent = "Ask assistant →";
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
  byId("configuration-manage-state").textContent = config.manage?.configured ? "Connected" : "Not connected";
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
  button.addEventListener("click", async () => {
    if (button.disabled) return;
    button.disabled = true;
    try { await action(); } finally { if (button.isConnected) button.disabled = disabled; }
  });
  return button;
}

async function mutateAgentAccounts(payload, successMessage) {
  if (agentAccountMutation) return null;
  agentAccountMutation = true;
  ++agentAccountsRequest;
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
      account_label_invalid: "Use a name between 1 and 48 characters.",
      account_not_authenticated: "Complete native sign-in before selecting this account.",
      selected_account_cannot_be_removed: "Select another worker account before removing this one.",
      confirmation_required: "Confirmation is required for this account change.",
      native_login_unavailable: "Native provider sign-in could not be started.",
      account_limit_reached: "The local native-account limit has been reached.",
    };
    toast(messages[error.message] || `Agent account action failed (${error.message}).`, "error");
    return null;
  } finally { agentAccountMutation = false; }
}

function agentAccountDialog(titleText, description, { value = null, submit = "Save" } = {}) {
  return new Promise((resolve) => {
    const dialog = document.createElement("dialog");
    dialog.className = "agent-dialog";
    const form = document.createElement("form");
    const title = document.createElement("h2");
    title.id = "agent-dialog-title";
    title.textContent = translatePhrase(titleText);
    dialog.setAttribute("aria-labelledby", title.id);
    const hint = document.createElement("p");
    hint.textContent = translatePhrase(description);
    form.append(title, hint);
    let input;
    if (value !== null) {
      const field = document.createElement("label");
      field.textContent = translatePhrase("Account name");
      input = document.createElement("input");
      input.value = value;
      input.required = true;
      input.maxLength = 48;
      input.autocomplete = "off";
      input.addEventListener("input", () => input.setCustomValidity(""));
      field.append(input);
      form.append(field);
    }
    const buttons = document.createElement("div");
    buttons.className = "agent-dialog-actions";
    buttons.append(agentAccountButton("Cancel", () => dialog.close()));
    const save = document.createElement("button");
    save.type = "submit";
    save.className = "button primary";
    save.textContent = translatePhrase(submit);
    buttons.append(save);
    form.append(buttons);
    let result = null;
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      if (input && !input.value.trim()) { input.setCustomValidity(translatePhrase("Enter an account name.")); input.reportValidity(); return; }
      result = input ? input.value.trim() : true;
      dialog.close();
    });
    dialog.addEventListener("close", () => { dialog.remove(); resolve(result); }, { once: true });
    dialog.append(form);
    document.body.append(dialog);
    dialog.showModal();
    if (input) { input.focus(); input.select(); }
  });
}

async function startAgentLogin(provider, account = null) {
  const proposed = account?.label || agentProviderName(provider);
  const alias = await agentAccountDialog(account ? "Reconnect account" : "Connect a subscription", "Choose a name, then sign in securely on the provider’s website.", { value: proposed, submit: "Continue to sign-in" });
  if (!alias) return;
  await mutateAgentAccounts({ action: "start_login", provider, label: alias, account_id: account?.id || null }, "Native sign-in started.");
  scheduleAgentAccountsPoll(true);
}

function renderAgentLoginSession(session) {
  const terminal = ["authenticated", "failed", "cancelled"].includes(session.status);
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
  const authorizationUrl = terminal ? null : safeAgentAuthorizationUrl(session);
  if (authorizationUrl) {
    const link = document.createElement("a");
    link.className = "agent-login-link";
    link.href = authorizationUrl;
    link.target = "_blank";
    link.rel = "noopener noreferrer";
    link.textContent = translatePhrase(session.provider === "claude" ? "Continue with Claude.ai ↗" : "Continue with ChatGPT ↗");
    instructions.append(link);
  }
  if (!terminal && typeof session.user_code === "string") {
    const code = document.createElement("code");
    code.className = "agent-login-code";
    code.dataset.i18nSkip = "";
    code.textContent = session.user_code;
    instructions.append(code);
  }
  if (!terminal && session.accepts_authorization_code === true) {
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
  if (!terminal) {
    instructions.append(agentAccountButton("Cancel", () => mutateAgentAccounts({ action: "cancel_login", session_id: session.id }, "Native sign-in cancelled.")));
  } else {
    instructions.append(agentAccountButton("Dismiss", () => {
      dismissedAgentLogins.add(session.id);
      renderAgentAccounts(agentAccountsView);
    }));
  }
  card.append(head);
  if (instructions.childNodes.length) card.append(instructions);
  return card;
}

function agentUsageDate(value) {
  const date = new Date(value);
  return value && Number.isFinite(date.getTime()) ? new Intl.DateTimeFormat(localeTag(), { dateStyle: "medium", timeStyle: "short" }).format(date) : null;
}

function renderAgentUsage(usage = {}) {
  const root = document.createElement("div");
  root.className = "agent-usage";
  const header = document.createElement("div");
  header.className = "agent-usage-heading";
  const title = document.createElement("strong");
  title.textContent = translatePhrase("Subscription usage");
  const state = document.createElement("span");
  const stale = usage.status !== "available" || !usage.checked_at_ms || Date.now() - usage.checked_at_ms > 360000;
  state.textContent = translatePhrase(usage.status === "loading" ? "Checking usage…" : stale ? "Usage unavailable" : "Latest reading");
  header.append(title, state);
  root.append(header);
  const windows = Array.isArray(usage.windows) ? usage.windows : [];
  for (const window of windows) {
    if (typeof window.used_percent !== "number" || !Number.isFinite(window.used_percent) || window.used_percent < 0 || window.used_percent > 100) continue;
    const row = document.createElement("div");
    row.className = "agent-usage-window";
    const used = Math.round(window.used_percent * 10) / 10;
    row.dataset.level = stale ? "stale" : used >= 95 ? "critical" : used >= 80 ? "warning" : "normal";
    const line = document.createElement("div");
    line.className = "agent-usage-line";
    const labelNode = document.createElement("span");
    const minutes = window.duration_minutes;
    const duration = minutes === 300 ? "5-hour window" : minutes === 10080 ? "Weekly limit" : minutes ? `${minutes} min` : "Usage window";
    labelNode.textContent = `${window.name === "codex" ? "Codex" : window.name || ""} · ${translatePhrase(duration)}`;
    const amount = document.createElement("strong");
    amount.textContent = `${new Intl.NumberFormat(localeTag(), { maximumFractionDigits: 1 }).format(used)}% ${translatePhrase("used")}`;
    line.append(labelNode, amount);
    const bar = document.createElement("progress");
    bar.max = 100;
    bar.value = used;
    bar.setAttribute("aria-label", labelNode.textContent);
    const detail = document.createElement("small");
    const resetValue = window.resets_at_ms || window.resets_at;
    const reset = agentUsageDate(resetValue);
    detail.textContent = reset ? `${translatePhrase(new Date(resetValue).getTime() <= Date.now() ? "Reset time passed; refresh pending" : "Resets")} · ${reset}` : translatePhrase("Reset time not provided");
    row.append(line, bar, detail);
    root.append(row);
  }
  const note = document.createElement("p");
  note.className = "agent-usage-note";
  const reasons = {
    sign_in_required: "Sign in to view subscription usage.",
    provider_rate_limited: "The provider has limited usage checks. We’ll retry after the cooldown.",
    provider_timeout: "The provider took too long to respond. Try again later.",
    not_reported: "The provider has not returned usage limits for this account.",
    provider_unavailable: "Usage could not be retrieved. Try again later.",
    dashboard_unavailable: "The connection was lost. These readings may be out of date.",
  };
  const messages = [];
  if (stale && windows.length) messages.push(translatePhrase("Previous reading — usage may have changed."));
  if (usage.status === "unavailable") messages.push(translatePhrase(reasons[usage.reason] || "Usage has not been checked yet."));
  if (usage.checked_at_ms) messages.push(`${translatePhrase("Checked")} · ${agentUsageDate(usage.checked_at_ms)}`);
  note.textContent = messages.join(" ");
  if (note.textContent) root.append(note);
  return root;
}

function agentAccountConnected(account) {
  return ["authenticated", "configured_unverified"].includes(account.status) && account.usage?.reason !== "sign_in_required";
}

function renderAgentAccount(account) {
  const card = document.createElement("div");
  card.className = "agent-account-card";
  card.dataset.accountId = account.id;
  card.dataset.worker = String(account.worker_selected === true);
  const head = document.createElement("div");
  head.className = "agent-account-head";
  const identity = document.createElement("div");
  identity.className = "agent-account-identity";
  const provider = document.createElement("small");
  provider.textContent = account.provider === "claude" ? "Claude · Claude Code" : "ChatGPT · Codex";
  const labelNode = document.createElement("strong");
  labelNode.dataset.i18nSkip = "";
  labelNode.textContent = account.label;
  identity.append(provider, labelNode);
  const status = document.createElement("span");
  status.className = "agent-account-status";
  const needsLogin = account.usage?.reason === "sign_in_required";
  status.dataset.state = needsLogin ? "expired" : account.status;
  status.textContent = needsLogin ? translatePhrase("Sign-in required") : authenticationLabel(account.status);
  head.append(identity, status);
  const role = document.createElement("div");
  role.className = "agent-account-role";
  role.textContent = translatePhrase("Worker account");
  if (account.worker_selected) identity.append(role);
  const meta = document.createElement("p");
  meta.className = "agent-account-meta";
  meta.textContent = account.last_verified_at_ms ? `${translatePhrase("Last verified")} · ${agentUsageDate(account.last_verified_at_ms)}` : translatePhrase("Not verified yet");
  const actions = document.createElement("div");
  actions.className = "agent-account-buttons";
  const connected = agentAccountConnected(account);
  actions.append(agentAccountButton(connected ? (account.worker_selected ? "Selected for worker" : "Use for worker") : "Sign in", () => connected ? mutateAgentAccounts({ action: "select", account_id: account.id }, "Worker account selected.") : startAgentLogin(account.provider, account), connected && account.worker_selected));
  actions.append(agentAccountButton("Verify connection", () => mutateAgentAccounts({ action: "refresh", account_id: account.id }, "Account status refreshed.")));
  const responseTest = agentAccountButton("Test response", () => mutateAgentAccounts({action:"test_response",account_id:account.id}, "Response test started."), !connected || (agentAccountsView?.accounts || []).some((a)=>a.response_test?.status==="checking"));
  responseTest.dataset.agentResponseTest = account.id;
  responseTest.title = translatePhrase("Sends a small test prompt using this subscription.");
  actions.append(responseTest);
  const more = document.createElement("details");
  more.className = "agent-account-manage";
  const summary = document.createElement("summary");
  summary.textContent = translatePhrase("Manage account");
  const management = document.createElement("div");
  management.append(
    agentAccountButton("Rename", async () => {
      const name = await agentAccountDialog("Rename account", "This name is only used in Monique.", { value: account.label });
      if (name) await mutateAgentAccounts({ action: "rename", account_id: account.id, label: name }, "Account renamed.");
    }),
    agentAccountButton("Sign in again", () => startAgentLogin(account.provider, account)),
    agentAccountButton("Sign out", async () => {
      if (await agentAccountDialog("Sign out account", account.worker_selected ? "This account is selected for the worker. New work may require signing in again." : "Sign out this native subscription account?", { submit: "Sign out" })) await mutateAgentAccounts({ action: "logout", account_id: account.id, confirm: true }, "Account signed out.");
    }, account.status === "signed_out"),
    agentAccountButton("Remove", async () => {
      if (await agentAccountDialog("Remove account", "Remove this local account profile and its native credentials?", { submit: "Remove" })) await mutateAgentAccounts({ action: "remove", account_id: account.id, confirm: true }, "Account removed.");
    }, account.worker_selected),
  );
  more.append(summary, meta, management);
  const controls = document.createElement("div");
  controls.className = "agent-account-controls";
  controls.append(actions, more);
  card.append(head, renderAgentUsage(account.usage), controls, renderAgentResponseTest(account));
  return card;
}

function filterAgentAccounts() {
  const query = byId("agent-account-search").value.trim().toLocaleLowerCase();
  const filter = byId("agent-account-filter").value;
  const accounts = agentAccountsView?.accounts || [];
  let visible = 0;
  for (const card of byId("agent-account-list").querySelectorAll("[data-account-id]")) {
    const account = accounts.find((entry) => entry.id === card.dataset.accountId);
    if (!account) continue;
    const connected = agentAccountConnected(account);
    const attention = !connected || account.usage?.status === "unavailable" || account.usage?.windows?.some((window) => window.used_percent >= 80);
    card.hidden = !`${account.label} ${account.provider} ${account.provider_name}`.toLocaleLowerCase().includes(query) || !(filter === "all" || filter === account.provider || (filter === "connected" && connected) || (filter === "attention" && attention));
    if (!card.hidden) visible++;
  }
  const empty = byId("agent-account-no-matches");
  if (empty) empty.hidden = visible > 0 || accounts.length === 0;
}

function renderAgentAccounts(view) {
  agentAccountsView = view;
  const sessionsRoot = byId("agent-login-sessions");
  const accountsRoot = byId("agent-account-list");
  // Keep unchanged login nodes in place: polling must not erase a pasted code,
  // collapse account controls, or steal keyboard focus.
  const reconcile = (root, items, key, render) => {
    const existing = new Map([...root.children].map((node) => [node.dataset.itemKey, node]));
    const nodes = items.map((item) => {
      const signature = `${currentLanguage}:${Math.floor(Date.now() / 60000)}:${JSON.stringify(item)}`;
      let node = existing.get(item[key]);
      if (!node || node._accountSignature !== signature) {
        const previousInput = node?.querySelector(".agent-authorization-input");
        const wasFocused = previousInput && document.activeElement === previousInput;
        const draft = previousInput?.value;
        const replacement = render(item);
        replacement.dataset.itemKey = item[key];
        replacement._accountSignature = signature;
        if (draft && replacement.querySelector(".agent-authorization-input")) replacement.querySelector(".agent-authorization-input").value = draft;
        if (node?.querySelector(".agent-account-manage[open]") && replacement.querySelector(".agent-account-manage")) replacement.querySelector(".agent-account-manage").open = true;
        if (node) node.replaceWith(replacement);
        node = replacement;
        if (wasFocused) requestAnimationFrame(() => node.querySelector(".agent-authorization-input")?.focus());
      }
      return node;
    });
    for (const node of [...root.children]) if (!nodes.includes(node)) node.remove();
    nodes.forEach((node, index) => { if (root.children[index] !== node) root.insertBefore(node, root.children[index] || null); });
  };
  const sessions = view.login_sessions || [];
  const sessionIds = new Set(sessions.map((session) => session.id));
  for (const id of dismissedAgentLogins) if (!sessionIds.has(id)) dismissedAgentLogins.delete(id);
  reconcile(sessionsRoot, sessions.filter((session) => !["authenticated", "cancelled"].includes(session.status) && !dismissedAgentLogins.has(session.id)), "id", renderAgentLoginSession);
  const accounts = Array.isArray(view.accounts) ? view.accounts : [];
  const providers = Array.isArray(view.providers) ? view.providers : [];
  const maximum = Number.isSafeInteger(view.max_accounts) && view.max_accounts > 0 ? view.max_accounts : null;
  const atCapacity = maximum !== null && accounts.length >= maximum;
  byId("agent-account-capacity").textContent = `${accounts.length}${maximum ? ` / ${maximum}` : ""} ${translatePhrase("accounts")}`;
  document.querySelectorAll("[data-add-agent-provider]").forEach((button) => {
    const provider = providers.find((item) => item?.id === button.dataset.addAgentProvider);
    button.disabled = atCapacity || provider?.available !== true;
  });
  const connected = accounts.filter(agentAccountConnected).length;
  const limited = accounts.filter((a) => a.usage?.status === "available" && a.usage.windows?.some((w) => w.used_percent >= 80)).length;
  const overview = byId("agent-account-overview");
  overview.replaceChildren(...[[connected, "Connected accounts"], [accounts.length - connected, "Need sign-in"], [limited, "Approaching a limit"]].map(([value, caption]) => {
    const tile = document.createElement("div");
    const number = document.createElement("strong");
    number.textContent = value;
    const text = document.createElement("span");
    text.textContent = translatePhrase(caption);
    tile.append(number, text);
    return tile;
  }));
  reconcile(accountsRoot, accounts, "id", renderAgentAccount);
  const responseTestBusy = accounts.some((account) => account.response_test?.status === "checking");
  for (const button of accountsRoot.querySelectorAll("[data-agent-response-test]")) {
    const account = accounts.find((item) => item.id === button.dataset.agentResponseTest);
    button.disabled = responseTestBusy || !account || !agentAccountConnected(account);
  }
  const empty = document.createElement("div");
  empty.className = "agent-account-empty";
  empty.id = "agent-account-no-matches";
  empty.textContent = translatePhrase(accounts.length ? "No accounts match these filters." : "Connect your first subscription to see its usage and choose an account for the worker.");
  accountsRoot.append(empty);
  filterAgentAccounts();
  const activeLogin = (view.login_sessions || []).some((session) => !["authenticated", "failed", "cancelled"].includes(session.status));
  scheduleAgentAccountsPoll(false, activeLogin || accounts.some((a) => a.usage?.status === "loading" || a.response_test?.status === "checking") ? 2000 : 30000);
}

function scheduleAgentAccountsPoll(immediate = false, delay = 2000) {
  if (agentAccountsPollTimer !== null) window.clearTimeout(agentAccountsPollTimer);
  agentAccountsPollTimer = window.setTimeout(() => {
    if (location.hash === "#configuration" && !document.hidden) loadAgentAccounts(true);
    else scheduleAgentAccountsPoll(false, 30000);
  }, immediate ? 100 : delay);
}

async function loadAgentAccounts(polling = false) {
  if (agentAccountMutation) { scheduleAgentAccountsPoll(); return; }
  const request = ++agentAccountsRequest;
  const refresh = byId("agent-accounts-refresh");
  if (!polling) refresh.disabled = true;
  try {
    const view = await api("/api/agent-accounts");
    if (request === agentAccountsRequest) renderAgentAccounts(view);
  } catch (error) {
    if (request !== agentAccountsRequest) return;
    if (!polling) toast("Native account management is unavailable.", "error");
    if (!agentAccountsView) byId("agent-account-list").textContent = translatePhrase("Native account management is unavailable.");
    else renderAgentAccounts({ ...agentAccountsView, accounts: (agentAccountsView.accounts || []).map((account) => ({ ...account, usage: { ...account.usage, status: "unavailable", reason: account.usage?.reason === "sign_in_required" ? "sign_in_required" : "dashboard_unavailable" } })) });
    scheduleAgentAccountsPoll(false, 30000);
  } finally { if (!polling) refresh.disabled = false; }
}

byId("agent-account-search").addEventListener("input", filterAgentAccounts);
byId("agent-account-filter").addEventListener("change", filterAgentAccounts);
byId("agent-accounts-refresh").addEventListener("click", () => loadAgentAccounts());

// Direct controls share one small result area; no provider text is rendered as HTML.
const controlState = { view: null, mcp: new Map(), runs: new Map(), tickets: new Map(), timer: null, loading: false };
const memorySelection = new Map();
function controlNode(tag, text, className = "") { const node = document.createElement(tag); if (text !== undefined) node.textContent = translatePhrase(String(text)); if (className) node.className = className; return node; }
function controlData(tag, text) { const node=document.createElement(tag); node.dataset.i18nSkip=""; node.textContent=String(text); return node; }
function controlTime(ms) { return Number.isFinite(ms) && ms > 0 ? new Date(ms).toLocaleString(localeTag(), { dateStyle: "short", timeStyle: "short" }) : translatePhrase("Not available"); }
function controlError(error) {
  return translatePhrase({ automation_revision_stale: "This automation changed. Refresh before trying again.", memory_revision_stale: "A selected memory changed. Refresh and select it again.", backup_busy: "A backup verification is already running.", connection_test_busy: "Another connection test is running. Try again shortly.", agent_test_busy: "An agent response test is already running.", agent_sign_in_required: "Sign in before testing a response.", invalid_request: "Check the selected item and try again." }[error?.message] || "The check could not finish. Try again.");
}
function controlAction(action) { return api("/api/controls/action", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(action), signal: AbortSignal.timeout(25000) }); }
function controlButton(text, run) {
  const button = controlNode("button", text, "button ghost small"); button.type = "button";
  button.addEventListener("click", async () => { if (button.disabled) return; button.disabled = true; button.setAttribute("aria-busy", "true"); try { await run(button); } catch (error) { toast(controlError(error), "error"); } finally { button.disabled = false; button.removeAttribute("aria-busy"); } });
  return button;
}
function controlResult(text = "") { const result = controlNode("div", text, "control-result"); result.setAttribute("role", "status"); result.setAttribute("aria-live", "polite"); return result; }
function controlCard(title, category, key) {
  const card = controlNode("article", undefined, "panel config-card control-card"); card.dataset.configCard = ""; card.dataset.configCategory = category; card.dataset.controlCard = key;
  const head = controlNode("div", undefined, "config-card-heading"); head.append(controlNode("h2", title));
  head.append(controlButton("Refresh", () => loadControls())); card.append(head); return card;
}
async function loadControls() {
  if (controlState.loading) return;
  controlState.loading = true;
  try { controlState.view = await api("/api/controls"); renderControls(); }
  catch (error) { const root = byId("configuration-controls"); root.replaceChildren(controlResult(controlError(error))); }
  finally { controlState.loading = false; }
}
function renderControls() {
  const root = byId("configuration-controls"); if (!root) return;
  // Preserve expanded server/tool lists across backup polling.
  const expanded = new Set([...root.querySelectorAll("details[open][data-control-details]")].map((node) => node.dataset.controlDetails));
  root.replaceChildren(); const view = controlState.view || {};
  const mcp = controlCard("MCP servers & tools", "integrations", "mcp");
  if (!view.mcp?.servers?.length) mcp.append(controlNode("p", view.mcp?.status === "unavailable" ? "MCP configuration is unavailable." : "No MCP servers configured.", "inline-hint"));
  for (const server of view.mcp?.servers || []) {
    const item = controlNode("details", undefined, "control-disclosure"); item.dataset.controlDetails = `mcp:${server}`;
    const summary = controlNode("summary", ({business:"Manage",support:"Support","support-workflows":"Support · suivi",designer:"Designer · site source","designer-app":"Designer · projets",seo:"SEO",ads:"Ads",mail:"MailDesigner",sms:"SMSDesigner",onboarding:"Onboarding",share:"Share"})[server] || server); summary.dataset.i18nSkip = ""; item.append(summary);
    const result = controlResult(); const check = controlState.mcp.get(server);
    result.textContent = check?.status === "verified" ? `${translatePhrase("Tools discovered")}: ${check.tools.length} · ${controlTime(check.checked_at_ms)}` : check?.status === "failed" ? `${translatePhrase("Discovery failed")}: ${translatePhrase(connectionTestReasons[check.reason] || "The check could not finish. Try again.")}${check.checked_at_ms ? ` · ${controlTime(check.checked_at_ms)}` : ""}` : translatePhrase("Not checked yet");
    result.dataset.state = check?.status || "idle";
    const discover = controlButton("Refresh tools", async () => {
      controlState.mcp.set(server, {status:"checking",tools:[]}); item.open = true; renderControls();
      try { controlState.mcp.set(server, await controlAction({action:"discover_mcp",server})); }
      catch (error) { controlState.mcp.set(server,{status:"failed",reason:"service_unavailable",tools:[]}); }
      renderControls();
    });
    discover.disabled = [...controlState.mcp.values()].some((check)=>check.status==="checking");
    if (check?.status==="checking") result.textContent=translatePhrase("Checking connection…");
    item.append(discover, result);
    if (check?.status === "verified" && check.connection) {
      const info=check.connection;
      const usage=controlNode("p", `${info.calls ?? "—"} appels · ${info.errors ?? "—"} erreurs · ${check.duration_ms} ms`, "inline-hint");usage.dataset.appUsage=server;item.append(usage);
      item.append(controlNode("p", info.scopes.join(" · "), "inline-hint"));
      const access=controlNode("details",undefined,"app-access-details");access.append(controlNode("summary","Accès autorisés"),controlNode("p",`Espaces : ${info.tenants.join(", ")}`),controlNode("p",`Ressources : ${info.resources.join(", ")}`));
      if(info.expires_at)access.append(controlNode("p",`Expire le ${new Date(info.expires_at).toLocaleDateString()}`));item.append(access);
    }
    if (check?.status === "verified") {
      const ask=controlButton("Demander à Monique",()=>{});ask.dataset.chatPrompt=`Utilise la connexion ${server} pour présenter les données disponibles et les actions possibles. Commence par une lecture, sans modifier de données.`;item.append(ask);
    }
    for (const tool of check?.tools || []) { const line = controlNode("div", undefined, "control-tool"); const name = controlNode("strong", tool.name); name.dataset.i18nSkip = ""; line.append(name, controlNode("span", tool.read_only ? "Read only" : "Changes data", "source-pill"), controlNode("small", tool.description)); item.append(line); }
    item.open = expanded.has(item.dataset.controlDetails); mcp.append(item);
  }
  const automations = controlCard("Automations", "ai integrations", "automations");
  automations.append(controlNode("p", "Pause stops future runs. Work already running can finish.", "inline-hint"));
  const schedule = view.automations || {};
  if (schedule.status !== "ready") automations.append(controlResult("Automation service is unavailable."));
  else if (!schedule.items?.length) automations.append(controlNode("p", "No automations registered.", "inline-hint"));
  for (const item of schedule.items || []) {
    const row = controlNode("div", undefined, "control-row"); row.dataset.automationId = item.id;
    const title = controlNode("strong", item.id); title.dataset.i18nSkip = "";
    const meta = controlNode("div", undefined, "control-meta");
    meta.append(controlNode("span", {enabled:"Enabled",paused:"Paused",archived:"Archived"}[item.state] || "Unknown"), controlNode("span", `${translatePhrase("Next run")}: ${item.state === "paused" ? translatePhrase("Paused") : controlTime(item.next_run_at_ms)}`), controlNode("span", `${translatePhrase("Last result")}: ${translatePhrase({completed:"Completed",failed:"Failed",pending:"Queued",claimed:"Running",never_run:"Never run",unavailable:"Not available"}[item.last_result] || "Not available")}`), controlNode("span", `${translatePhrase("Last run")}: ${controlTime(item.last_run_at_ms)}`));
    const actions = controlNode("div", undefined, "control-actions"); const output = controlResult();
    actions.append(controlButton("Preview", async () => { const preview = await controlAction({ action:"preview_automation", id:item.id }); output.replaceChildren(controlNode("p", "Preview only · nothing will run"), controlNode("span", `${translatePhrase("Schedule")}: ${preview.schedule || "—"} · ${translatePhrase("Scope")}: ${preview.scope || "—"}`), controlData("pre", preview.prompt || translatePhrase("No task registered."))); }));
    if (item.state !== "archived") actions.append(controlButton(item.state === "paused" ? "Resume" : "Pause", async () => { await controlAction({action:"set_automation",id:item.id,revision:item.revision,paused:item.state !== "paused"}); await loadControls(); }));
    row.append(title, meta, actions, output); automations.append(row);
  }
  if (Number.isSafeInteger(schedule.next_cursor)) automations.append(controlButton("Load more", async () => { const page = await controlAction({action:"list_automations",cursor:schedule.next_cursor}); controlState.view.automations = {...page,items:[...schedule.items,...(page.items || [])]}; renderControls(); }));
  const backups = controlCard("Backups", "security", "backups");
  const inventory = view.backups || {}; const timer = inventory.timer || {};
  backups.append(controlNode("p", timer.status === "active" ? `${translatePhrase("Next backup")}: ${timer.next_run_at_ms ? controlTime(timer.next_run_at_ms) : timer.next_run || translatePhrase("Not available")}` : translatePhrase(timer.status === "not_configured" ? "Automatic backups are not configured." : timer.status === "inactive" ? "Automatic backups are paused." : "Backup schedule is unavailable."), "inline-hint"));
  if (!inventory.items?.length) backups.append(controlNode("p", "No completed backups found.", "inline-hint"));
  else backups.append(controlNode("p", `${translatePhrase("Latest backup")}: ${controlTime(inventory.items[0].created_at_ms)}`, "inline-hint"));
  const history = controlNode("details", undefined, "control-disclosure"); history.dataset.controlDetails = "backup-history"; history.open = expanded.has("backup-history"); history.append(controlNode("summary", "Older backups"));
  (inventory.items || []).forEach((item, index) => {
    const row = controlNode("div", undefined, "control-row"); row.dataset.backupId = item.id;
    row.append(controlNode("strong", controlTime(item.created_at_ms)), controlNode("small", `${item.databases} ${translatePhrase("databases")} · ${(item.bytes / 1048576).toFixed(1)} MB`));
    const verification = item.verification || {};
    const result = controlResult(`${translatePhrase({checking:"Verifying backup…",verified:"Backup verified",failed:"Backup verification failed",not_checked:"Not checked yet"}[verification.status] || "Not checked yet")}${verification.checked_at_ms ? ` · ${controlTime(verification.checked_at_ms)}` : ""}`); result.dataset.state = verification.status;
    const verify = controlButton("Verify backup", async () => { await controlAction({action:"verify_backup",id:item.id}); await loadControls(); }); verify.disabled = (inventory.items || []).some((item)=>item.verification?.status === "checking");
    row.append(verify, result); (index === 0 ? backups : history).append(row);
  });
  if ((inventory.items?.length || 0) > 1) backups.append(history);
  root.append(mcp, automations, backups); applyConfigurationFilter();
  if (controlState.timer !== null) clearTimeout(controlState.timer);
  if ((inventory.items || []).some((item) => item.verification?.status === "checking")) controlState.timer = setTimeout(() => { if (location.hash === "#configuration") loadControls(); }, 2000);
}

function appendTicketCheck(actions, summary, ticket) {
  const key=ticketConversationKey(ticket);const output=controlResult();const paint=(result)=>{
    if(!result)return;
    if(result.pending){output.textContent=translatePhrase("Checking latest status…");return;}
    if(result.error){output.textContent=controlError(result.error);return;}
    output.replaceChildren(controlNode("span", `${translatePhrase("Checked")} ${controlTime(result.checked_at_ms)}`),controlNode("p", `${translatePhrase("Source")}: ${ticket.integration_server} · ${ticketStatusLabel(result.status || "unknown")}`),controlNode("p", `${translatePhrase("Last activity")}: ${result.updated_at ? ticketDateLabel(result.updated_at) : translatePhrase("Not available")}`));
    if(result.status && result.status!==ticket.status)output.append(controlNode("p","The source status differs from the ticket list. Refresh the list to reconcile the display."));
  };
  const existing=controlState.tickets.get(key);paint(existing);
  const button=controlButton("Check latest status",async()=>{controlState.tickets.set(key,{pending:true});paint({pending:true});try {const result=await api("/api/tickets/detail",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({integration_server:ticket.integration_server,id:ticket.id})});result.checked_at_ms=Date.now();controlState.tickets.set(key,result);paint(result);}catch(error){controlState.tickets.set(key,{error});paint({error});}});button.disabled=!ticket.integration_server || existing?.pending===true;actions.append(button);summary.append(output);
}
function renderAgentResponseTest(account) {
  const test=account.response_test;const output=controlResult();output.classList.add("agent-response-test");
  if(!test){output.hidden=true;return output;}
  const labels={checking:"Testing response…",verified:"Response verified",failed:"Response test failed"};
  output.append(controlNode("strong",labels[test.status] || "Not checked yet"));
  if(test.reason && test.reason!=="response_verified")output.append(controlNode("span",{quota_limited:"Subscription quota reached.",sign_in_required:"Sign in before testing a response.",timed_out:"The connection timed out. Try again.",response_failed:"The provider could not complete the response test."}[test.reason] || "The check could not finish. Try again."));
  if(test.status!=="checking")output.append(controlNode("span",test.model || "Model not reported"));
  if(test.duration_ms!==undefined)output.append(controlNode("span",`${(test.duration_ms/1000).toFixed(1)} s`));
  if(test.checked_at_ms)output.append(controlNode("time",controlTime(test.checked_at_ms)));
  output.dataset.state=test.status;return output;
}
function updateMemorySelection() {
  document.querySelectorAll("[data-memory-select]").forEach((checkbox)=>{checkbox.checked=memorySelection.has(checkbox.dataset.memorySelect);});
  byId("memory-archive-selected").disabled=memorySelection.size===0;
  byId("memory-selected-count").textContent=`${memorySelection.size} ${translatePhrase("selected")}`;
}
function memorySelectionCheckbox(entry) {
  const checkbox=document.createElement("input");checkbox.type="checkbox";checkbox.className="memory-select";checkbox.dataset.memorySelect=entry.reference;
  checkbox.setAttribute("aria-label",`${translatePhrase("Select")} ${entry.reference}`);checkbox.checked=memorySelection.has(entry.reference);checkbox.disabled=entry.status!=="active" || !entry.editable;
  checkbox.addEventListener("click",event=>event.stopPropagation());
  checkbox.addEventListener("keydown",event=>event.stopPropagation());
  checkbox.addEventListener("change",()=>{if(checkbox.checked){if(memorySelection.size>=100){checkbox.checked=false;toast(translatePhrase("Select up to 100 memories."),"error");return;}memorySelection.set(entry.reference,{reference:entry.reference,revision:entry.revision});}else memorySelection.delete(entry.reference);updateMemorySelection();});return checkbox;
}
async function inspectMemory(action) {
  const output=byId("memory-inspection");output.hidden=false;output.replaceChildren(controlResult("Checking…"));
  try {
    const result=await controlAction(action);output.replaceChildren();
    const close=controlButton("Dismiss",()=>{output.hidden=true;});output.append(close);
    if(action.action==="retrieve_memory"){
      output.append(controlNode("h3","Retrieval preview"),controlNode("p","These are the memories supplied to dashboard chat for this question. No message was sent."));
      if(!result.entries.length)output.append(controlNode("p","No active memories match this question."));
      for(const entry of result.entries)output.append(controlData("p",`${entry.reference} · ${entry.content}`));
    }else{
      output.append(controlNode("h3","Duplicate memories"),controlNode("p","Matches ignore letter case and extra spaces. Review each group before archiving."));
      if(!result.groups.length)output.append(controlNode("p","No duplicate memories found."));
      for(const group of result.groups){const row=controlNode("div",undefined,"control-row");for(const entry of group){const line=controlNode("label",undefined,"memory-duplicate-choice");line.append(memorySelectionCheckbox(entry),controlData("span",`${entry.reference} · ${entry.content}`));row.append(line);}output.append(row);}
      if(result.truncated)output.append(controlNode("p","Results are limited. Search to narrow the inventory."));
    }
  }catch(error){output.replaceChildren(controlResult(controlError(error)));}
}
byId("memory-retrieval-test").addEventListener("click",()=>{const query=byId("memory-query").value.trim();if(!query){toast(translatePhrase("Enter a question in the memory search field."));byId("memory-query").focus();return;}inspectMemory({action:"retrieve_memory",query});});
byId("memory-duplicates").addEventListener("click",()=>inspectMemory({action:"find_duplicates"}));
byId("memory-select-visible").addEventListener("click",()=>{memorySelection.clear();for(const entry of selectedMemoryEntries().filter(e=>e.editable && e.status==="active").slice(0,100))memorySelection.set(entry.reference,{reference:entry.reference,revision:entry.revision});renderSelectedMemory();updateMemorySelection();});
byId("memory-clear-selection").addEventListener("click",()=>{memorySelection.clear();renderSelectedMemory();updateMemorySelection();byId("memory-inspection").hidden=true;});
byId("memory-archive-selected").addEventListener("click",async()=>{
  const selected=[...memorySelection.values()];if(!selected.length)return;
  if(!await agentAccountDialog("Archive selected memories", `${translatePhrase("Selected memories")}: ${selected.length}. ${translatePhrase("They will stop appearing in retrieval. Their content and audit history will be retained.")}`, {submit:"Archive"}))return;
  const button=byId("memory-archive-selected");button.disabled=true;
  try {await controlAction({action:"archive_memories",entries:selected});memorySelection.clear();byId("memory-inspection").hidden=true;await loadMemory(memoryQuery);toast(translatePhrase("Selected memories archived."));}
  catch(error){toast(controlError(error),"error");}finally{updateMemorySelection();}
});

async function loadConfiguration(force = false) {
  loadIntegrations();
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
    loadControls();
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
  item._chatContent = String(content);
  if (Number.isSafeInteger(details.id)) item.dataset.chatMessageId = String(details.id);
  const avatar = document.createElement("span");
  avatar.className = "message-avatar";
  avatar.textContent = role === "user" ? "YOU" : "M";
  const body = document.createElement("div");
  body.className = "message-content";
  const markdown = document.createElement("div");
  markdown.className = "message-markdown";
  if (!details.error && !details.localized) markdown.setAttribute("data-i18n-skip", "");
  markdown.append(renderMarkdown(content));
  for (const pre of markdown.querySelectorAll("pre")) {
    const code=pre.querySelector("code");if(!code)continue;
    const wrapper=controlNode("div",undefined,"chat-code-block"),head=controlNode("div",undefined,"chat-code-head");
    const label=controlData("span",code.dataset.language || translatePhrase("Code"));
    const copy=controlButton("Copy code",async()=>{await navigator.clipboard.writeText(code.textContent);toast(translatePhrase("Code copied."));});
    head.append(label,copy);pre.replaceWith(wrapper);wrapper.append(head,pre);
  }
  body.append(markdown);
  appendArtifactReferences(body,content);
  if (role !== "user" && details.action) body.append(createActionCard(details.action));
  if (details.error) body.append(controlButton("Reload conversation",()=>loadChatHistory(true)));
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
    if (!details.error && !details.localized) {
      const quote=controlButton("Quote",()=>quoteChatMessage(markdown,content));quote.dataset.quoteMessage="";
      quote.addEventListener("mousedown",event=>event.preventDefault());
      const download=controlButton("Download reply",()=>downloadChatMarkdown(String(content),"monique-reply.md"));
      actions.append(quote,download);
    }
    tools.append(actions);
    body.append(tools);
  }
  if (role === "user") {
    const tools=controlNode("div",undefined,"message-tools"),actions=controlNode("div",undefined,"message-actions");
    const reuse=controlButton("Use again",()=>{byId("chat-input").value=String(content);updateChatComposer();byId("chat-input").focus();});reuse.dataset.reusePrompt="";
    actions.append(reuse);tools.append(actions);body.append(tools);item.append(body,avatar);
  } else item.append(avatar,body);
  byId("chat-thread").append(item);
  refreshChatNavigation();
  revealChatMessage(role === "user");
  if (role !== "user" && details.speak && voiceRepliesEnabled) {
    window.setTimeout(() => speakText(markdown.innerText || markdown.textContent), 0);
  }
  return item;
}

function createActionCard(action) {
  const card = document.createElement("section");
  card.className = "action-card";
  card.dataset.actionId = String(action.id || "");
  card.dataset.actionKind = String(action.kind || "manage");
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
  approve.textContent = action.kind === "slack_post" ? "Approve and post" : "Approve and run";
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
  updateChatComposer();
  card.dataset.state = "working";
  card.querySelectorAll("button").forEach((button) => { button.disabled = true; });
  const pending = appendPendingMessage();
  const slackPost = card.dataset.actionKind === "slack_post";
  byId("chat-state").textContent = decision === "approve"
    ? (slackPost ? "Posting the approved message…" : "Running approved action…")
    : "Recording denial…";
  try {
    const answer = await api("/api/chat/action", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action_id: card.dataset.actionId, decision, expected_conversation: chatUi.id || "" }),
    });
    pending.remove();
    card.dataset.state = decision === "approve" ? "approved" : "denied";
    const sources = Array.isArray(answer.live_sources) ? answer.live_sources : [];
    appendMessage("assistant", answer.answer, Date.now(), { sources, durationMs: answer.duration_ms, action: answer.action, speak: true });
    byId("chat-source-count").textContent = count(sources.length);
    byId("chat-latency").textContent = Number.isSafeInteger(answer.duration_ms) ? `${answer.duration_ms.toLocaleString(localeTag())} ms` : "-";
    // A Slack post Slack did not confirm is still a decided card: the reply
    // says whether it landed, so the toast does not claim it did.
    byId("chat-state").textContent = decision === "approve" ? (slackPost ? "Slack post decided" : "Action completed") : "Action denied";
    toast(decision === "approve"
      ? (slackPost ? "The Slack post was decided. Read the reply for the outcome." : "The approved action returned a result.")
      : "The action was denied.");
  } catch (error) {
    pending.remove();
    card.removeAttribute("data-state");
    card.querySelectorAll("button").forEach((button) => { button.disabled = false; });
    appendMessage("assistant", humanChatError(error.message), Date.now(), { error: true });
    byId("chat-state").textContent = "Action refused";
    toast("The action was not completed.", "error");
  } finally {
    chatBusy = false;
    updateChatComposer();
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
  body.append(dots, controlNode("span", "Thinking…", "chat-pending-label"));
  item.append(avatar, body);
  byId("chat-thread").append(item);
  revealChatMessage();
  return item;
}

function createWelcome(title = "What can I help with?", text = "Think it through, find an answer, or get something done.") {
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
    ["Make a plan", "Turn an idea into clear next steps", "Help me turn an idea into a clear plan."],
    ["Catch me up", "Recent Slack messages", "Summarize the latest relevant Slack messages."],
    ["Explore memory", "What Monique remembers", "What do you remember that is most relevant right now? Cite memory references."],
    ["Write something", "Draft, rewrite, or find the right words", "Help me improve a piece of writing."],
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

function chatOutgoingMessage() {
  const draft=byId("chat-input").value.trim(),quote=chatUi.quotes.get(chatUi.id || "");
  return quote?`${quote.split("\n").map(line=>`> ${line}`).join("\n")}\n\n${draft}`:draft;
}
function renderChatQuote() {
  const quote=chatUi.quotes.get(chatUi.id || "");byId("chat-quote").hidden=!quote;
  byId("chat-quote-text").textContent=quote || "";
}
function quoteChatMessage(markdown,content) {
  if(chatUi.loading)return;
  const selection=window.getSelection();
  const selected=selection && !selection.isCollapsed && markdown.contains(selection.anchorNode) && markdown.contains(selection.focusNode)?selection.toString().trim():"";
  const text=Array.from(selected || String(content));
  chatUi.quotes.set(chatUi.id || "",text.slice(0,1200).join("")+(text.length>1200?"…":""));
  updateChatComposer();byId("chat-input").focus();
}
function downloadChatMarkdown(content,filename) {
  const url=URL.createObjectURL(new Blob([content],{type:"text/markdown;charset=utf-8"}));
  const link=document.createElement("a");link.href=url;link.download=filename;link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
}
async function exportChatConversation() {
  if(chatUi.exportController){chatUi.exportController.abort();return;}
  if(chatBusy || chatUi.loading || !chatUi.id)return;
  const id=chatUi.id,title=chatUi.items.find(item=>item.id===id)?.title || "Monique",controller=new AbortController();
  chatUi.exportController=controller;byId("chat-export-all").textContent=translatePhrase("Cancel export");
  const status=byId("chat-export-status");status.hidden=false;status.textContent=translatePhrase("Preparing retained messages…");
  let timedOut=false;const timer=setTimeout(()=>{timedOut=true;controller.abort();},120000);
  try {
    const history=await api("/api/chat/history",{signal:controller.signal});
    if(history.conversation_id!==id)throw new Error("chat_conversation_changed");
    let messages=history.messages || [],more=history.has_more,pages=0,size=JSON.stringify(messages).length;
    const seen=new Set(messages.map(message=>message.id));
    while(more){
      if(++pages>1000 || size>20000000)throw new Error("chat_export_too_large");
      const before=messages[0]?.id;if(!Number.isSafeInteger(before))throw new Error("chat_export_incomplete");
      const page=await api("/api/chat/conversations/action",{method:"POST",headers:{"Content-Type":"application/json"},signal:controller.signal,body:JSON.stringify({action:"older",id,before})});
      if(page.conversation_id!==id || !Array.isArray(page.messages))throw new Error("chat_export_incomplete");
      for(const message of page.messages){if(seen.has(message.id))throw new Error("chat_export_incomplete");seen.add(message.id);}
      if(page.has_more && !page.messages.length)throw new Error("chat_export_incomplete");
      messages=[...page.messages,...messages];more=page.has_more;size+=JSON.stringify(page.messages).length;
    }
    if(size>20000000)throw new Error("chat_export_too_large");
    if(controller.signal.aborted)throw new DOMException("Cancelled","AbortError");
    const content=[`# ${title}`,translatePhrase("Retained messages at the time of export."),...messages.map(message=>`## ${message.role==="user"?translatePhrase("You"):"Monique"}\n\n${message.content}`)].join("\n\n");
    downloadChatMarkdown(content,"monique-conversation.md");status.textContent=translatePhrase("Conversation exported.");
  }catch(error){
    status.textContent=translatePhrase(controller.signal.aborted && !timedOut?"Export cancelled.":error.message==="chat_export_too_large"?"This conversation is too large to export here.":error.message==="chat_conversation_changed"?"The active conversation changed. Reload it before sending.":"Export could not finish. No partial file was downloaded.");
  }finally{clearTimeout(timer);chatUi.exportController=null;byId("chat-export-all").textContent=translatePhrase("Export full conversation");updateChatComposer();}
}
function scrollToChatTarget(target) {
  const thread=byId("chat-thread");chatUi.follow=false;
  thread.scrollTop+=target.getBoundingClientRect().top-thread.getBoundingClientRect().top-24;
  byId("chat-jump").hidden=chatAtBottom();
}
function toggleChatNavigation(mode) {
  const open=Boolean(mode);byId("chat-navigator").hidden=!open;
  byId("chat-find-toggle").setAttribute("aria-expanded",String(open));
  if(!open){clearChatFindMarks();chatUi.findHits=[];byId("chat-find-toggle").focus();return;}
  byId("chat-options").open=false;chatUi.navigationMode=mode;
  for(const name of ["find","outline"]){
    const selected=mode===name;byId(`chat-${name}-panel`).hidden=!selected;
    byId(`chat-${name}-tab`).setAttribute("aria-selected",String(selected));byId(`chat-${name}-tab`).tabIndex=selected?0:-1;
  }
  refreshChatNavigation();
  (mode==="find"?byId("chat-find-input"):byId("chat-outline-tab")).focus();
}
function clearChatFindMarks() {
  for(const mark of byId("chat-thread").querySelectorAll("mark.chat-find-mark")){
    const parent=mark.parentNode;mark.replaceWith(document.createTextNode(mark.textContent));parent.normalize();
  }
}
function refreshChatNavigation() {
  byId("chat-navigation-older").hidden=!chatUi.hasMore;
  byId("chat-navigation-scope").textContent=translatePhrase(chatUi.hasMore?"Loaded messages":"All retained messages loaded");
  if(byId("chat-navigator").hidden)return;
  if(chatUi.navigationMode==="find")findChatMatches(false);
  else {clearChatFindMarks();renderChatOutline();}
}
function findChatMatches(jump=true) {
  clearChatFindMarks();chatUi.findHits=[];
  const query=byId("chat-find-input").value.trim();
  if(query){
    const pattern=new RegExp(query.replace(/[.*+?^${}()|[\]\\]/g,"\\$&"),"giu");
    for(const markdown of byId("chat-thread").querySelectorAll(".message:not(.pending) .message-markdown")){
      const walker=document.createTreeWalker(markdown,NodeFilter.SHOW_TEXT,{acceptNode:node=>node.parentElement.closest(".chat-code-head,button")?NodeFilter.FILTER_REJECT:NodeFilter.FILTER_ACCEPT});
      const nodes=[];let text="",node;
      while((node=walker.nextNode())){nodes.push({node,start:text.length,end:text.length+node.length});text+=node.textContent;}
      const matches=[];pattern.lastIndex=0;let match;
      while((match=pattern.exec(text)) && chatUi.findHits.length<1000){const hit={start:match.index,end:match.index+match[0].length,marks:[]};matches.push(hit);chatUi.findHits.push(hit);}
      for(const entry of nodes){
        const intersections=matches.filter(hit=>hit.start<entry.end && hit.end>entry.start);if(!intersections.length)continue;
        const fragment=document.createDocumentFragment();let offset=0;
        for(const hit of intersections){
          const start=Math.max(0,hit.start-entry.start),end=Math.min(entry.node.length,hit.end-entry.start);
          fragment.append(document.createTextNode(entry.node.textContent.slice(offset,start)));
          const mark=document.createElement("mark");mark.className="chat-find-mark";mark.textContent=entry.node.textContent.slice(start,end);fragment.append(mark);hit.marks.push(mark);offset=end;
        }
        fragment.append(document.createTextNode(entry.node.textContent.slice(offset)));entry.node.replaceWith(fragment);
      }
      if(chatUi.findHits.length>=1000)break;
    }
  }
  chatUi.findIndex=chatUi.findHits.length?Math.max(0,Math.min(chatUi.findIndex,chatUi.findHits.length-1)):-1;
  focusChatMatch(0,jump);
}
function focusChatMatch(direction,jump=true) {
  const hits=chatUi.findHits;
  if(hits.length)chatUi.findIndex=(chatUi.findIndex+direction+hits.length)%hits.length;
  hits.forEach((hit,index)=>hit.marks.forEach(mark=>mark.classList.toggle("current",index===chatUi.findIndex)));
  byId("chat-find-status").textContent=hits.length?`${chatUi.findIndex+1} / ${hits.length}${hits.length===1000?"+":""}`:byId("chat-find-input").value.trim()?translatePhrase("No matches"):"";
  byId("chat-find-status").title=hits.length===1000?translatePhrase("First 1000 matches"):"";
  byId("chat-find-prev").disabled=byId("chat-find-next").disabled=!hits.length;
  if(jump && hits.length)scrollToChatTarget(hits[chatUi.findIndex].marks[0]);
}
function renderChatOutline() {
  const root=byId("chat-outline-list");root.replaceChildren();
  for(const message of byId("chat-thread").querySelectorAll(".message:not(.pending):not(.error)")){
    const targets=message.classList.contains("user")?[message.querySelector(".message-markdown")]:[...message.querySelectorAll(".message-markdown h1,.message-markdown h2,.message-markdown h3")];
    for(const target of targets){
      if(!target)continue;const text=target.textContent.trim();if(!text)continue;
      const button=controlButton("",()=>{scrollToChatTarget(target);target.tabIndex=-1;target.focus({preventScroll:true});});
      button.className="chat-outline-item";button.classList.toggle("question",message.classList.contains("user"));
      button.append(controlData("span",text.slice(0,160)));button.title=text.slice(0,500);root.append(button);
    }
  }
  if(!root.children.length)root.append(controlNode("p","Questions and reply headings will appear here.","inline-hint"));
}

function updateChatComposer() {
  const input=byId("chat-input");const bytes=new TextEncoder().encode(chatOutgoingMessage()).length;
  renderChatQuote();
  input.disabled=chatUi.loading;
  if(!CSS.supports("field-sizing", "content")){input.rows=1;const lineHeight=parseFloat(getComputedStyle(input).lineHeight)||24;input.rows=Math.min(7,Math.max(1,Math.ceil((input.scrollHeight-24)/lineHeight)));}
  byId("chat-count").textContent=bytes.toLocaleString(localeTag());byId("chat-limit").hidden=bytes<6000;
  byId("chat-send").disabled=chatBusy || chatUi.loading || !chatUi.ready || !input.value.trim() || bytes>8192;
  byId("chat-profile").disabled=chatBusy || chatUi.loading;
  byId("voice-input").disabled=chatBusy || chatUi.loading || !voiceInputSupported;
  byId("chat-thread").querySelectorAll(".action-card").forEach(card=>card.querySelectorAll("button").forEach(button=>button.disabled=chatBusy || chatUi.loading || Boolean(card.dataset.state)));
  byId("new-chat").disabled=chatBusy || chatUi.loading || !chatUi.ready;
  byId("chat-new-shortcut").disabled=byId("new-chat").disabled;
  byId("chat-reload").disabled=chatBusy || chatUi.loading;
  byId("chat-export-all").disabled=!chatUi.exportController && (chatBusy || chatUi.loading || !chatUi.id);
  byId("chat-navigation-older").disabled=chatBusy || chatUi.loading;
  byId("chat-quote-remove").disabled=chatUi.loading;
  byId("chat-thread").querySelectorAll("[data-quote-message]").forEach(button=>button.disabled=chatUi.loading);
  byId("chat-export").disabled=!byId("chat-thread").querySelector(".message:not(.pending)");
  byId("chat-thread").setAttribute("aria-busy",String(chatBusy || chatUi.loading));
  document.querySelectorAll(".chat-history-item").forEach(button=>button.disabled=chatBusy || chatUi.loading);
  document.querySelectorAll(".message-actions [data-reuse-prompt]").forEach(button=>button.disabled=chatUi.loading);
  if(bytes>8192)byId("chat-state").textContent=translatePhrase("Your message is too long. Shorten it before sending.");
  else if(chatUi.tooLong)byId("chat-state").textContent=translatePhrase(chatBusy?"Monique is working…":"Ready");
  chatUi.tooLong=bytes>8192;
  if(byId("chat-older"))byId("chat-older").disabled=chatBusy || chatUi.loading;
}
function chatAtBottom() {const thread=byId("chat-thread");return thread.scrollHeight-thread.scrollTop-thread.clientHeight<100;}
function scrollChatLatest() {const thread=byId("chat-thread");thread.scrollTop=thread.scrollHeight;chatUi.follow=true;byId("chat-jump").hidden=true;}
function revealChatMessage(force=false) {
  if(force || chatUi.follow)scrollChatLatest();else byId("chat-jump").hidden=false;
}
function toggleChatHistory(open) {
  const root=byId("chat-workspace");const narrow=matchMedia("(max-width: 1000px)").matches;
  const current=narrow?root.classList.contains("history-open"):!root.classList.contains("history-collapsed");
  open=open===undefined?!current:open;
  if(narrow)root.classList.toggle("history-open",open);else {root.classList.toggle("history-collapsed",!open);root.classList.remove("history-open");}
  byId("chat-history-backdrop").hidden=!(narrow && open);
  byId("chat-history-toggle").setAttribute("aria-expanded",String(open));
  if(narrow){byId("chat-history").inert=!open;byId("chat-workspace").querySelector(".chat-surface").inert=open;}
  else {byId("chat-history").inert=!open;byId("chat-workspace").querySelector(".chat-surface").inert=false;savePreference("monique-chat-history",open?"expanded":"collapsed");}
  if(narrow && open)byId("chat-history-search").focus();
}
function renderChatConversations() {
  const root=byId("chat-history-list"),top=root.scrollTop,query=byId("chat-history-search").value.trim().toLocaleLowerCase();root.replaceChildren();
  const items=chatUi.items.filter(item=>String(item.title||"").toLocaleLowerCase().includes(query));
  const groups=new Map(),today=new Date(),recent=new Date();recent.setDate(today.getDate()-7);recent.setHours(0,0,0,0);
  for(const item of items){
    const date=new Date(item.updated_at_ms),group=date.toDateString()===today.toDateString()?"Today":date>=recent?"Previous 7 days":"Earlier";
    if(!groups.has(group))groups.set(group,[]);groups.get(group).push(item);
  }
  for(const [group,conversations] of groups){
    const section=controlNode("details",undefined,"chat-history-group"),summary=controlNode("summary"),list=controlNode("div",undefined,"chat-history-group-items");
    section.dataset.historyGroup=group;
    section.open=Boolean(query) || (chatUi.historyGroups.get(group) ?? (group!=="Earlier" || conversations.some(item=>item.id===chatUi.id)));
    const countLabel=controlData("b",String(conversations.length));countLabel.setAttribute("aria-hidden","true");summary.append(controlNode("span",group),countLabel);
    summary.addEventListener("click",()=>{if(!query)chatUi.historyGroups.set(group,!section.open);});
    for(const item of conversations){
      const title=item.title || translatePhrase("New conversation"),button=controlButton("",()=>selectChatConversation(item.id));
      button.className="chat-history-item";button.dataset.conversationId=item.id;button.setAttribute("aria-current",String(item.id===chatUi.id));
      button.append(controlData("strong",title));button.title=`${title} · ${ticketDateLabel(new Date(item.updated_at_ms).toISOString())}`;button.disabled=chatBusy || chatUi.loading;list.append(button);
    }
    section.append(summary,list);root.append(section);
  }
  if(!items.length)root.append(controlNode("p",query?"No conversations match your search.":"Your conversations will appear here.","inline-hint"));
  root.scrollTop=top;
  const selected=chatUi.items.find(item=>item.id===chatUi.id);byId("chat-conversation-title").textContent=selected?.title || translatePhrase("New conversation");
}
async function loadChatConversations() {
  try {const view=await api("/api/chat/conversations");chatUi.items=Array.isArray(view.items)?view.items:[];renderChatConversations();}
  catch(_error){byId("chat-history-list").replaceChildren(controlNode("p","Conversation history is unavailable.","inline-hint"),controlButton("Try again",loadChatConversations));}
}
function rememberChatDraft() {chatUi.drafts.set(chatUi.id || "",byId("chat-input").value);}
function applyChatHistory(history) {
  stopSpeaking();chatUi.findIndex=-1;const thread=byId("chat-thread");thread.replaceChildren();chatUi.id=history.conversation_id || null;chatUi.follow=false;
  for(const message of history.messages || [])appendMessage(message.role,message.content,message.created_at_ms,{id:message.id});
  for(const action of history.pending_actions || [])appendMessage("assistant","This action is still awaiting your decision.",Date.now(),{action,localized:true});
  if(!thread.children.length)thread.append(createWelcome());
  chatUi.hasMore=Boolean(history.has_more);addOlderChatButton();thread.dataset.loaded="true";chatUi.ready=true;
  byId("chat-input").value=chatUi.seededPrompt ?? chatUi.drafts.get(chatUi.id || "") ?? "";
  chatUi.seededPrompt=null;
  byId("chat-state").textContent=translatePhrase("Ready");
  byId("chat-memory-count").textContent="-";byId("chat-source-count").textContent="0";byId("chat-latency").textContent="-";
  renderChatConversations();scrollChatLatest();updateChatComposer();
  loadConversationArtifacts();
}
function addOlderChatButton() {
  refreshChatNavigation();
  byId("chat-older")?.remove();if(!chatUi.hasMore)return;
  const button=controlButton("Load earlier messages",loadOlderChatMessages);button.id="chat-older";byId("chat-thread").prepend(button);
}
async function selectChatConversation(id) {
  if(chatBusy || chatUi.loading || id===chatUi.id)return;
  rememberChatDraft();chatUi.loading=true;updateChatComposer();
  try {const history=await api("/api/chat/conversations/action",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({action:"select",id,expected_conversation:chatUi.id || ""})});applyChatHistory(history);if(matchMedia("(max-width: 1000px)").matches)toggleChatHistory(false);}
  catch(error){toast(humanChatError(error.message),"error");}
  finally{chatUi.loading=false;updateChatComposer();}
}
async function loadOlderChatMessages() {
  if(chatUi.loading || chatBusy || !chatUi.id)return;
  const thread=byId("chat-thread"),first=thread.querySelector("[data-chat-message-id]");if(!first)return;
  const id=chatUi.id;chatUi.loading=true;updateChatComposer();
  try {
    const page=await api("/api/chat/conversations/action",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({action:"older",id,before:Number(first.dataset.chatMessageId)})});
    if(chatUi.id!==id)return;
    const height=thread.scrollHeight,top=thread.scrollTop;byId("chat-older")?.remove();const old=[...thread.children];chatUi.follow=false;
    const nodes=(page.messages || []).map(message=>appendMessage(message.role,message.content,message.created_at_ms,{id:message.id}));thread.replaceChildren(...nodes,...old);chatUi.hasMore=Boolean(page.has_more);addOlderChatButton();thread.scrollTop=top+(thread.scrollHeight-height);
  }catch(error){toast(humanChatError(error.message),"error");}
  finally{chatUi.loading=false;updateChatComposer();}
}
async function loadChatHistory(force=false) {
  const thread=byId("chat-thread");if(chatUi.loading || chatBusy || (!force && thread.dataset.loaded==="true"))return;
  rememberChatDraft();if(force)chatUi.seededPrompt=byId("chat-input").value;chatUi.loading=true;updateChatComposer();
  try {applyChatHistory(await api("/api/chat/history"));await loadChatConversations();}
  catch(_error){byId("chat-state").textContent=translatePhrase("History unavailable");toast("Durable chat history is unavailable.","error");}
  finally{chatUi.loading=false;updateChatComposer();}
}

function humanChatError(category) {
  const messages = {
    artifact_prompt_too_long: "Your request is too long. Shorten it and try again.",
    chat_conversation_changed: "The active conversation changed. Reload it before sending.",
    chat_conversation_unavailable: "This conversation is no longer available.",
    chat_lane_busy: "Monique is finishing another contained turn. Try again in a moment.",
    slack_read_unavailable: "The configured Slack read is temporarily unavailable.",
    slack_tool_unavailable: "The Slack read surface is temporarily busy.",
    memory_unavailable: "Durable memory is temporarily unavailable.",
    memory_write_refused: "This turn could not be retained safely, so it was not run.",
    manage_tool_unavailable: "Manage AI Operations is temporarily unavailable. No action was run.",
    manage_action_not_pending: "That action is no longer pending. Nothing was run.",
    slack_post_not_pending: "That Slack post is no longer pending. Nothing was posted.",
    slack_post_expired: "That Slack draft expired. Nothing was posted. Ask Monique to draft it again.",
    slack_post_capacity: "Too many Slack drafts are awaiting decisions. Resolve one and try again.",
    slack_post_unavailable: "Monique could not hold the Slack draft safely. Nothing was posted.",
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
  if(chatBusy || chatUi.loading || !chatUi.ready)return;
  stopVoiceInput();const input=byId("chat-input"),draft=input.value.trim(),quote=chatUi.quotes.get(chatUi.id || ""),message=chatOutgoingMessage(),originalId=chatUi.id;
  if(!draft || new TextEncoder().encode(message).length>8192)return;
  chatBusy=true;chatUi.quotes.delete(chatUi.id || "");chatUi.drafts.delete(chatUi.id || "");appendMessage("user",message);input.value="";updateChatComposer();scrollChatLatest();
  const pending=appendPendingMessage(),started=performance.now();
  const timer=setInterval(()=>{const seconds=Math.max(1,Math.round((performance.now()-started)/1000));const label=pending.querySelector(".chat-pending-label");if(label)label.textContent=`${translatePhrase("Thinking…")} ${seconds}s`;},1000);
  byId("chat-state").textContent=translatePhrase("Monique is working…");
  try {
    const answer=await api("/api/chat",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({message,profile:byId("chat-profile").value,expected_conversation:chatUi.id || ""})});
    pending.remove();chatUi.id=answer.conversation_id || chatUi.id;
    if(chatUi.id!==originalId && chatUi.quotes.has(originalId || "")){chatUi.quotes.set(chatUi.id,chatUi.quotes.get(originalId || ""));chatUi.quotes.delete(originalId || "");}
    const sources=Array.isArray(answer.live_sources)?answer.live_sources:[];
    appendMessage("assistant",answer.answer,Date.now(),{sources,durationMs:answer.duration_ms,action:answer.action,speak:true});
    byId("chat-memory-count").textContent=count(answer.memory_evidence);byId("chat-source-count").textContent=count(sources.length);
    byId("chat-latency").textContent=Number.isSafeInteger(answer.duration_ms)?`${(answer.duration_ms/1000).toFixed(1)} s`:"-";
    byId("chat-state").textContent=translatePhrase("Ready");await loadChatConversations();
  }catch(error){
    pending.remove();appendMessage("assistant",humanChatError(error.message),Date.now(),{error:true});
    if(!input.value.trim() && !chatUi.quotes.has(chatUi.id || "")){input.value=draft;if(quote)chatUi.quotes.set(chatUi.id || "",quote);}
    byId("chat-state").textContent=translatePhrase("Reply unavailable · your draft is kept");
  }finally{clearInterval(timer);chatBusy=false;updateChatComposer();}
});
byId("chat-input").addEventListener("keydown",(event)=>{
  if(event.key!=="Enter" || event.isComposing || event.keyCode===229)return;
  const desktop=!matchMedia("(pointer: coarse)").matches;
  if(!event.shiftKey && (desktop || event.ctrlKey || event.metaKey)){event.preventDefault();byId("chat-form").requestSubmit();}
});
byId("chat-input").addEventListener("input",updateChatComposer);
initializeVoiceSupport();

byId("new-chat").addEventListener("click",async()=>{
  if(chatBusy || chatUi.loading || !chatUi.ready)return;
  rememberChatDraft();chatUi.loading=true;updateChatComposer();
  try {
    const history=await api("/api/chat/new",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({expected_conversation:chatUi.id || ""})});
    chatUi.drafts.delete("");chatUi.quotes.delete("");applyChatHistory(history);await loadChatConversations();
    if(matchMedia("(max-width: 1000px)").matches)toggleChatHistory(false);byId("chat-input").focus();
  }catch(error){toast(humanChatError(error.message),"error");}
  finally{chatUi.loading=false;updateChatComposer();}
});
byId("chat-new-shortcut").addEventListener("click",()=>byId("new-chat").click());
byId("chat-history-search").addEventListener("input",renderChatConversations);
byId("chat-history-toggle").addEventListener("click",()=>toggleChatHistory());
for(const id of ["chat-history-close","chat-history-backdrop"])byId(id).addEventListener("click",()=>{toggleChatHistory(false);byId("chat-history-toggle").focus();});
byId("chat-jump").addEventListener("click",scrollChatLatest);
byId("chat-thread").addEventListener("scroll",()=>{chatUi.follow=chatAtBottom();if(chatUi.follow)byId("chat-jump").hidden=true;});
byId("chat-reload").addEventListener("click",()=>{byId("chat-options").open=false;loadChatHistory(true);});
byId("chat-export-all").addEventListener("click",exportChatConversation);
byId("chat-quote-remove").addEventListener("click",()=>{chatUi.quotes.delete(chatUi.id || "");updateChatComposer();byId("chat-input").focus();});
byId("chat-find-toggle").addEventListener("click",()=>toggleChatNavigation(byId("chat-navigator").hidden?"find":null));
byId("chat-outline-toggle").addEventListener("click",()=>toggleChatNavigation("outline"));
byId("chat-navigator-close").addEventListener("click",()=>toggleChatNavigation(null));
for(const mode of ["find","outline"])byId(`chat-${mode}-tab`).addEventListener("click",()=>toggleChatNavigation(mode));
byId("chat-navigator").addEventListener("keydown",event=>{
  if(event.key==="Escape"){event.preventDefault();event.stopPropagation();toggleChatNavigation(null);}
  if(event.target.getAttribute("role")==="tab" && ["ArrowLeft","ArrowRight","Home","End"].includes(event.key)){
    event.preventDefault();const mode=event.key==="Home"?"find":event.key==="End"?"outline":chatUi.navigationMode==="find"?"outline":"find";toggleChatNavigation(mode);byId(`chat-${mode}-tab`).focus();
  }
});
byId("chat-find-input").addEventListener("input",()=>{chatUi.findIndex=0;findChatMatches();});
byId("chat-find-input").addEventListener("keydown",event=>{if(event.key==="Enter" && !event.isComposing){event.preventDefault();focusChatMatch(event.shiftKey?-1:1);}});
byId("chat-find-prev").addEventListener("click",()=>focusChatMatch(-1));
byId("chat-find-next").addEventListener("click",()=>focusChatMatch(1));
byId("chat-navigation-older").addEventListener("click",loadOlderChatMessages);
byId("chat-export").addEventListener("click",()=>{
  const messages=[...byId("chat-thread").querySelectorAll(".message:not(.pending)")].filter(node=>node._chatContent!==undefined);
  const content=["# Monique",translatePhrase("Visible messages from this conversation."),...messages.map(node=>`## ${node.classList.contains("user")?translatePhrase("You"):"Monique"}\n\n${node._chatContent}`)].join("\n\n");
  downloadChatMarkdown(content,"monique-conversation.md");byId("chat-options").open=false;
});
const chatNarrowMedia=matchMedia("(max-width: 1000px)");
function restoreChatHistoryLayout(){toggleChatHistory(!chatNarrowMedia.matches && storedPreference("monique-chat-history",["expanded","collapsed"],"expanded")==="expanded");}
chatNarrowMedia.addEventListener("change",restoreChatHistoryLayout);restoreChatHistoryLayout();
document.addEventListener("keydown",event=>{
  if(event.key==="Escape" && byId("chat-workspace").classList.contains("history-open")){event.preventDefault();toggleChatHistory(false);byId("chat-history-toggle").focus();}
  if(event.key==="Tab" && byId("chat-workspace").classList.contains("history-open")){
    const nodes=[...byId("chat-history").querySelectorAll("button:not(:disabled), input, summary")].filter(node=>node.getClientRects().length && !node.closest("details:not([open]) .chat-history-group-items"));const first=nodes[0],last=nodes[nodes.length-1];
    if(event.shiftKey && document.activeElement===first){event.preventDefault();last.focus();}else if(!event.shiftKey && document.activeElement===last){event.preventDefault();first.focus();}
  }
});

byId("sidebar-sessions").addEventListener("click", () => showView("sessions"));

function seedChatPrompt(prompt) {
  showView("chat");
  const input = byId("chat-input");
  input.value = prompt;
  if(chatUi.loading || !chatUi.ready)chatUi.seededPrompt=prompt;
  updateChatComposer();
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
  if (document.querySelector(".memory-dialog[open], .agent-dialog[open]")) return;
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
    // "New task" means ready to type, not just the right page.
    window.setTimeout(() => byId("platform-task-text").focus(), 0);

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
// policy is `default-src 'none'` with `img-src 'self'` - a data: image would be
// refused and a remote generator is both blocked and a place a live credential
// must never go.
// ---------------------------------------------------------------------------

const PAIRING_QUIET_MODULES = 4;
let pairingOfferText = null;
let pairingExpiresAtMs = 0;
let pairingCountdown = 0;
let pairingSymbol = null;
let pairingRequestGeneration = 0;
let pairingCreating = false;
let pairingSessionsLoaded = false;

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
  pairingSymbol = null;
  pairingExpiresAtMs = 0;
  byId("pairing-download").hidden = true;
  byId("pairing-result").hidden = true;
  byId("pairing-setup").hidden = false;
  byId("pairing-edit").hidden = true;
  byId("pairing-create").textContent = translatePhrase("Create invite");
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
  pairingSymbol = symbol;
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
    pairingOfferText = null;
    pairingSymbol = null;
    byId("pairing-code").replaceChildren();
    byId("pairing-copy").hidden = true;
    byId("pairing-download").hidden = true;
    return;
  }
  node.classList.remove("is-expired");
  node.textContent = translatePhrase(`Expires in ${remaining} seconds`);
}

function pairingIsAdmin() {
  return byId("pairing-access").value === "admin";
}

function pairingUpdateCreate() {
  byId("pairing-create").disabled = pairingCreating || (!pairingIsAdmin()
    && ((!pairingSessionsLoaded) || (byId("pairing-sessions").selectedOptions.length === 0
      && !byId("pairing-start-task").checked && !byId("pairing-manage-work").checked)));
}

function pairingScopeChanged() {
  pairingRequestGeneration += 1;
  pairingCreating = false;
  pairingClearResult();
  byId("pairing-selected-scope").hidden = pairingIsAdmin();
  byId("pairing-admin-note").hidden = !pairingIsAdmin();
  pairingSetStatus("");
  pairingUpdateCreate();
}

async function pairingLoadSessions() {
  const select = byId("pairing-sessions");
  select.replaceChildren();
  pairingSessionsLoaded = false;
  pairingUpdateCreate();
  pairingSetStatus("Loading conversations…");
  try {
    const view = await api("/api/mobile/pairing-sessions");
    const sessions = Array.isArray(view.sessions) ? view.sessions : [];
    for (const entry of sessions) {
      const id = entry.session?.resource?.id;
      if (!id) continue;
      const option = document.createElement("option");
      option.value = id;
      option.selected = true;
      option.textContent = entry.session?.summary || id;
      option.setAttribute("data-i18n-skip", "");
      select.append(option);
    }
    pairingSessionsLoaded = true;
    if (!pairingCreating && !pairingOfferText) {
      pairingSetStatus(select.options.length || pairingIsAdmin() ? "" : "No session exists yet. Enable task creation to let this phone start one.");
    }
  } catch (_error) {
    if (!pairingIsAdmin()) pairingSetStatus("The session list is unavailable, so the invite could not be scoped.", "error");
  } finally {
    pairingUpdateCreate();
  }
}

async function pairingCreate() {
  const button = byId("pairing-create");
  const admin = pairingIsAdmin();
  const scope = admin ? [] : Array.from(byId("pairing-sessions").selectedOptions, (option) => option.value);
  if (!admin && scope.length === 0 && !byId("pairing-start-task").checked && !byId("pairing-manage-work").checked) {
    // session_scope is an allowlist, not a filter: an empty one reaches nothing.
    pairingSetStatus("Select at least one session. A phone can only reach the sessions named here.", "error");
    return;
  }
  const generation = ++pairingRequestGeneration;
  pairingCreating = true;
  button.disabled = true;
  pairingClearResult();
  pairingSetStatus("Creating the invite…");
  try {
    const result = await pairingRequestText("/api/mobile/pairings", {
      method: "POST",
      headers: { "Content-Type": "application/vnd.automonique.mobile-auth.v1+json" },
      body: JSON.stringify({
        actions: ["attach", "follow_up", "decide_approval", "stop_run", ...(admin ? ["all_sessions"] : []), ...(byId("pairing-start-task").checked ? ["start_task"] : []), ...(byId("pairing-manage-work").checked ? ["manage_work"] : [])],
        session_scope: scope,
        limits: { max_follow_up_bytes: 65536, max_page_events: 100 },
      }),
    });
    if (generation !== pairingRequestGeneration || byId("pairing-panel").hidden) return;
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
    byId("pairing-setup").hidden = true;
    byId("pairing-edit").hidden = false;
    byId("pairing-create").textContent = translatePhrase("Create another invite");
    byId("pairing-panel").scrollTop = 0;
    byId("pairing-copy").hidden = false;
    let drawn = false;
    try { drawn = pairingDrawCode(pairingOfferText); } catch (_error) { /* Copy remains available. */ }
    byId("pairing-download").hidden = !drawn;
    pairingTick();
    if (pairingOfferText) pairingCountdown = window.setInterval(pairingTick, 1000);
    pairingSetStatus(drawn ? "" : "The QR encoder did not load. Use Copy invite instead.", drawn ? "info" : "error");
  } catch (_error) {
    if (generation === pairingRequestGeneration) pairingSetStatus("The invite could not be created.", "error");
  } finally {
    if (generation === pairingRequestGeneration) {
      pairingCreating = false;
      pairingUpdateCreate();
    }
  }
}

function pairingOpen(open) {
  pairingRequestGeneration += 1;
  pairingCreating = false;
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
byId("pairing-edit").addEventListener("click", () => {
  pairingScopeChanged();
  byId("pairing-access").focus();
});
byId("pairing-copy").addEventListener("click", async () => {
  if (!pairingOfferText) return;
  pairingTick();
  if (!pairingOfferText) return;
  try {
    await navigator.clipboard.writeText(pairingOfferText);
    pairingSetStatus("Invite copied. Paste it in the app.");
  } catch (_error) {
    pairingSetStatus("The invite could not be copied.", "error");
  }
});
document.addEventListener("keydown", (event) => {
  if (document.querySelector(".memory-dialog[open], .agent-dialog[open]")) return;
  if (event.key === "Escape" && !byId("pairing-panel").hidden) pairingOpen(false);
});
document.addEventListener("click", (event) => {
  if (byId("pairing-panel").hidden) return;
  if (event.target.closest("#pairing-panel, #pairing-open")) return;
  pairingOpen(false);
});

for (const id of ["pairing-access", "pairing-sessions", "pairing-start-task", "pairing-manage-work"]) {
  byId(id).addEventListener("change", pairingScopeChanged);
}

byId("pairing-download").addEventListener("click", () => {
  pairingTick();
  if (!pairingSymbol || !pairingOfferText) return;
  const generation = pairingRequestGeneration;
  // Draw the same matrix directly into a PNG; no credential leaves this page.
  const modules = pairingSymbol.modules;
  const scale = 8;
  const canvas = document.createElement("canvas");
  canvas.width = canvas.height = (modules.size + PAIRING_QUIET_MODULES * 2) * scale;
  const context = canvas.getContext("2d");
  context.fillStyle = "#ffffff";
  context.fillRect(0, 0, canvas.width, canvas.height);
  context.fillStyle = "#000000";
  for (let row = 0; row < modules.size; row += 1) {
    for (let column = 0; column < modules.size; column += 1) {
      if (modules.get(row, column)) context.fillRect((column + PAIRING_QUIET_MODULES) * scale, (row + PAIRING_QUIET_MODULES) * scale, scale, scale);
    }
  }
  canvas.toBlob((blob) => {
    if (!blob || generation !== pairingRequestGeneration || !pairingOfferText || Date.now() >= pairingExpiresAtMs) return;
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "monique-pairing.png";
    link.click();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  }, "image/png");
});

// ---------------------------------------------------------------------------
// Ops console shell: detail drawers, list keyboard navigation, tab badges and
// the Ctrl+K command palette.
// ---------------------------------------------------------------------------

document.querySelectorAll("[data-drawer-close]").forEach((button) => button.addEventListener("click", () => consoleCloseDrawer(button.dataset.drawerClose)));

function consoleCloseDrawer(id) {
  if (id === "task-drawer") {
    consoleState.taskDrawerDismissed = true;
    if (platformSelectedSession) detachPlatformSession();
  } else if (id === "ticket-drawer") {
    consoleState.ticketId = null;
    consoleMarkSelected(byId("ticket-list"), "data-ticket-id", null);
  } else if (id === "ops-drawer") {
    consoleCloseOps();
  } else if (id === "memory-drawer") {
    consoleState.memoryOpen = false;
    if (memorySnapshot) renderSelectedMemory();
  }
  consoleDrawer(id, false);
  document.querySelector(".view.is-visible .view-main [data-row].is-selected, .view.is-visible .view-main [data-row]")?.focus({ preventScroll: true });
}

document.querySelector("[data-drawer-pane='workspace']").addEventListener("click", () => consoleShowTaskPane("workspace"));
document.querySelectorAll("[data-cockpit-surface]").forEach((button) => button.addEventListener("click", () => {
  const workspaceTab = document.querySelector("[data-drawer-pane='workspace']");
  byId("drawer-workspace-pane").hidden = true;
  workspaceTab.classList.remove("is-active");
  workspaceTab.setAttribute("aria-selected", "false");
  workspaceTab.tabIndex = -1;
  consoleSyncTaskDrawerTitle();
}));
new MutationObserver(() => {
  if (byId("platform-session-detail").hidden && consoleTaskPane() === "conversation" && consoleDrawerIsOpen("task-drawer") && !platformSelectedSession) {
    consoleDrawer("task-drawer", false);
  }
  consoleSyncTaskDrawerTitle();
}).observe(byId("platform-session-detail"), { attributes: true, attributeFilter: ["hidden"] });

// Small inline counters recede when they read zero.
function consoleSyncStats() {
  document.querySelectorAll(".stat").forEach((stat) => {
    const value = stat.querySelector("b")?.textContent.trim();
    if (value === undefined) return;
    if (/^[0-9]/.test(value)) stat.dataset.zero = String(value === "0");
    else delete stat.dataset.zero;
  });
  const badges = [
    ["tab-badge-sessions", "cockpit-needs-you-count", "info"],
    ["tab-badge-tickets", "tickets-urgent", "danger"],
    ["tab-badge-operations", "process-failed", "danger"],
    ["tab-badge-overview", "metric-attention", "danger"],
  ];
  badges.forEach(([badgeId, sourceId, tone]) => {
    const value = byId(sourceId)?.textContent.trim() || "";
    const badge = byId(badgeId);
    const show = /^[1-9][0-9]*$/.test(value.replace(/[\s,. ]/g, ""));
    badge.hidden = !show;
    badge.textContent = show ? value : "";
    badge.dataset.tone = tone;
  });
  // Assistant header chips mean nothing before a turn: hide "-" placeholders.
  ["chat-memory-count", "chat-latency"].forEach((id) => {
    const value = byId(id);
    if (value?.parentElement) value.parentElement.hidden = value.textContent.trim() === "-";
  });
  // Agents: failures first; otherwise runs waiting for approval.
  const failed = Number((byId("process-failed")?.textContent || "").replace(/[^0-9]/g, "")) || 0;
  const approval = Number((byId("process-approval")?.textContent || "").replace(/[^0-9]/g, "")) || 0;
  const agents = byId("tab-badge-operations");
  if (failed === 0 && approval > 0) {
    agents.hidden = false;
    agents.textContent = byId("process-approval").textContent.trim();
    agents.dataset.tone = "warn";
  }
}
let consoleStatsQueued = false;
new MutationObserver(() => {
  if (consoleStatsQueued) return;
  consoleStatsQueued = true;
  window.requestAnimationFrame(() => {
    consoleStatsQueued = false;
    consoleSyncStats();
  });
}).observe(byId("workspace"), { subtree: true, childList: true, characterData: true });
consoleSyncStats();

// Load the counters behind the tab badges once, so they are right before a tab is opened.
if (!operationsSnapshot) loadOperations();
if (!processesSnapshot) loadProcesses();
if (!document.querySelector('[data-panel="sessions"]').classList.contains("is-visible")) loadPlatform();

function consoleVisibleRows() {
  const view = document.querySelector(".view.is-visible");
  if (!view) return [];
  return [...view.querySelectorAll(".view-main [data-row]")].filter((row) => row.offsetParent !== null);
}

function consoleMoveCursor(step) {
  const rows = consoleVisibleRows();
  if (rows.length === 0) return;
  let index = rows.indexOf(document.activeElement);
  if (index < 0) index = rows.findIndex((row) => row.classList.contains("is-selected") || row.getAttribute("aria-selected") === "true");
  const next = index < 0 ? (step > 0 ? 0 : rows.length - 1) : Math.max(0, Math.min(rows.length - 1, index + step));
  const row = rows[next];
  row.focus({ preventScroll: true });
  row.scrollIntoView({ block: "nearest" });
  const drawerOpen = document.querySelector(".view.is-visible .drawer.is-open");
  if (drawerOpen && next !== index) row.click();
}

function consoleEditing(target) {
  return target.matches?.("input, textarea, select, [contenteditable='true']");
}

document.addEventListener("keydown", (event) => {
  if (document.querySelector(".memory-dialog[open], .agent-dialog[open]")) return;
  if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
    event.preventDefault();
    consolePaletteOpen(byId("command-palette").hidden);
    return;
  }
  if (!byId("command-palette").hidden) return;
  const editing = consoleEditing(event.target);
  if (event.defaultPrevented || event.altKey || event.ctrlKey || event.metaKey) return;
  const onRow = event.target.closest?.("[data-row]");
  if (!editing && (event.key === "j" || (onRow && event.key === "ArrowDown"))) {
    event.preventDefault();
    consoleMoveCursor(1);
  } else if (!editing && (event.key === "k" || (onRow && event.key === "ArrowUp"))) {
    event.preventDefault();
    consoleMoveCursor(-1);
  } else if (onRow && !onRow.matches("button") && (event.key === "Enter" || event.key === " ")) {
    event.preventDefault();
    onRow.click();
  } else if (event.key === "Escape" && byId("appearance-panel").hidden && byId("pairing-panel").hidden) {
    const drawer = document.querySelector(".view.is-visible .drawer.is-open");
    if (!drawer || (editing && event.target.value)) return;
    event.preventDefault();
    consoleCloseDrawer(drawer.id);
  } else if (!editing && document.querySelector('[data-panel="sessions"]')?.classList.contains("is-visible") && ["c", "a"].includes(event.key.toLowerCase())) {
    consoleDrawer("task-drawer", true);
    consoleShowTaskPane(event.key.toLowerCase() === "c" ? "conversation" : "activity");
  }
});

// ------------------------------------------------------------- command palette

let consolePaletteItems = [];
let consolePaletteIndex = 0;
let consolePaletteReturnFocus = null;

function consolePaletteOpen(open) {
  byId("command-palette").hidden = !open;
  byId("command-backdrop").hidden = !open;
  byId("command-open").setAttribute("aria-expanded", String(open));
  if (open) {
    consolePaletteReturnFocus = document.activeElement;
    byId("command-input").value = "";
    consolePaletteRender();
    byId("command-input").focus();
  } else if (consolePaletteReturnFocus?.isConnected) {
    consolePaletteReturnFocus.focus({ preventScroll: true });
  }
}

function consoleNextTheme() {
  const current = document.documentElement.dataset.theme;
  return current === "light" ? "dark" : current === "dark" ? "system" : "light";
}

function consoleRefreshAll() {
  refreshStatus({ announce: true });
  const view = document.querySelector(".view.is-visible")?.dataset.panel;
  if (view === "sessions") loadPlatform();
  if (view === "operations") loadProcesses();
  if (view === "operations" || view === "tickets") loadOperations(true);
  if (view === "memory") loadMemory(memoryQuery);
  if (view === "configuration") loadConfiguration(true);
}

function consoleCommands(query) {
  const go = (view, label, hint) => ({ group: "Go to", icon: "→", label, hint, run: () => showView(view) });
  const themeLabels = { light: "Switch to light theme", dark: "Switch to dark theme", system: "Use the system theme" };
  const commands = [
    { group: "Actions", icon: "+", label: "New task", keywords: "create run start", run: () => { showView("sessions"); byId("platform-task-text").focus(); } },
    { group: "Actions", icon: "↻", label: "Refresh", keywords: "reload update", hint: "R", run: consoleRefreshAll },
    { group: "Actions", icon: "◐", label: themeLabels[consoleNextTheme()], keywords: "theme dark light colour color appearance", run: () => applyTheme(consoleNextTheme()) },
    { group: "Actions", icon: "A", label: currentLanguage === "en" ? "Passer en français" : "Switch to English", keywords: "language langue french anglais english français", run: () => applyLanguage(currentLanguage === "en" ? "fr" : "en") },
    { group: "Actions", icon: "Aa", label: "Appearance settings", keywords: "theme text size density", run: () => appearanceOpen(true) },
    { group: "Actions", icon: "▢", label: "Pair a phone", keywords: "mobile qr invite", run: () => { showView("overview"); pairingOpen(true); } },
    { group: "Actions", icon: "?", label: "Ask the assistant", keywords: "chat help question", hint: "/", run: () => { showView("chat"); byId("chat-input").focus(); } },
    go("sessions", "Tasks", "N"),
    go("tickets", "Tickets"),
    go("operations", "Agents"),
    go("memory", "Memory"),
    go("overview", "Health"),
    go("configuration", "Settings"),
    go("chat", "Assistant"),
  ];
  const needle = query.trim().toLocaleLowerCase(localeTag());
  const matches = (text) => String(text || "").toLocaleLowerCase(localeTag()).includes(needle);
  const filtered = needle
    ? commands.filter((command) => matches(translatePhrase(command.label)) || matches(command.label) || matches(command.keywords))
    : commands;
  if (!needle) return filtered;
  const results = [];
  (operationsSnapshot?.tickets?.items || [])
    .filter((ticket) => matches(ticket.title) || matches(ticket.id) || matches(ticket.site) || matches(ticket.requester))
    .slice(0, 5)
    .forEach((ticket) => results.push({ group: "Tickets", icon: "#", label: ticket.title, raw: true, hint: ticketReferenceLabel(ticket.id), run: () => { showView("tickets"); consoleOpenTicket(ticket.id); } }));
  (platformSnapshot?.sessions || [])
    .filter((session) => matches(consoleSessionTitle(session)) || matches(session.session?.resource?.id))
    .slice(0, 4)
    .forEach((session) => results.push({ group: "Conversations", icon: "◦", label: consoleSessionTitle(session), raw: true, run: () => { showView("sessions"); consoleOpenSession(session.session.resource.id); } }));
  (processesSnapshot?.jobs || [])
    .filter((job) => matches(processIssueReference(job).label) || matches(job.id) || matches(job.issue_url))
    .slice(0, 4)
    .forEach((job) => results.push({ group: "Agent runs", icon: "▸", label: processIssueReference(job).label, raw: true, hint: translatePhrase(processStatusLabel(job.status)), run: () => { showView("operations"); window.setTimeout(() => consoleOpenProcess(job.id), 0); } }));
  (memorySnapshot?.entries || [])
    .filter((entry) => matches(entry.content) || matches(entry.reference))
    .slice(0, 3)
    .forEach((entry) => results.push({ group: "Memory", icon: "◇", label: entry.content, raw: true, hint: entry.reference, run: () => { showView("memory"); consoleOpenMemory(entry.reference); } }));
  const quoted = query.trim();
  results.push(
    { group: "Search", icon: "⌕", label: `Search tickets for “${quoted}”`, run: () => { showView("tickets"); const input = byId("tickets-search"); input.value = quoted; input.dispatchEvent(new Event("input", { bubbles: true })); } },
    { group: "Search", icon: "⌕", label: `Search memory for “${quoted}”`, run: () => { showView("memory"); byId("memory-query").value = quoted; loadMemory(quoted); } },
    { group: "Search", icon: "?", label: `Ask the assistant: “${quoted}”`, run: () => seedChatPrompt(quoted) },
  );
  return [...filtered, ...results];
}

function consolePaletteRender() {
  const query = byId("command-input").value;
  consolePaletteItems = consoleCommands(query);
  consolePaletteIndex = 0;
  const list = byId("command-list");
  list.replaceChildren();
  if (consolePaletteItems.length === 0) {
    const empty = document.createElement("li");
    empty.className = "command-empty";
    empty.textContent = translatePhrase("No matching command");
    list.append(empty);
    return;
  }
  let group = null;
  consolePaletteItems.forEach((command, index) => {
    if (command.group !== group) {
      group = command.group;
      const heading = document.createElement("li");
      heading.className = "command-group";
      heading.setAttribute("role", "presentation");
      heading.textContent = translatePhrase(group);
      list.append(heading);
    }
    const item = document.createElement("li");
    item.className = "command-item";
    item.id = `command-item-${index}`;
    item.setAttribute("role", "option");
    item.setAttribute("data-i18n-skip", "");
    const icon = document.createElement("span");
    icon.className = "command-icon";
    icon.setAttribute("aria-hidden", "true");
    icon.textContent = command.icon || "";
    const label = document.createElement("span");
    label.className = "command-label";
    label.textContent = command.raw ? command.label : consoleTranslateCommand(command.label);
    item.append(icon, label);
    if (command.hint) {
      const hint = document.createElement("span");
      hint.className = "command-hint";
      hint.textContent = command.hint;
      item.append(hint);
    }
    item.addEventListener("mousemove", () => consolePaletteSelect(index));
    item.addEventListener("click", () => consolePaletteRun(index));
    list.append(item);
  });
  consolePaletteSelect(0);
}

function consoleTranslateCommand(label) {
  const quoted = label.match(/^(Search tickets for|Search memory for|Ask the assistant:) “(.*)”$/);
  if (quoted && currentLanguage === "fr") return `${translatePhrase(quoted[1])} « ${quoted[2]} »`;
  return translatePhrase(label);
}

function consolePaletteSelect(index) {
  consolePaletteIndex = index;
  byId("command-list").querySelectorAll(".command-item").forEach((item) => {
    const active = item.id === `command-item-${index}`;
    item.setAttribute("aria-selected", String(active));
    if (active) item.scrollIntoView({ block: "nearest" });
  });
  byId("command-input").setAttribute("aria-activedescendant", `command-item-${index}`);
}

function consolePaletteRun(index) {
  const command = consolePaletteItems[index];
  if (!command) return;
  consolePaletteReturnFocus = null;
  consolePaletteOpen(false);
  command.run();
}

byId("command-open").addEventListener("click", () => consolePaletteOpen(true));
byId("command-backdrop").addEventListener("click", () => consolePaletteOpen(false));
byId("command-input").addEventListener("input", consolePaletteRender);
byId("command-input").addEventListener("keydown", (event) => {
  if (event.key === "ArrowDown" || event.key === "ArrowUp") {
    event.preventDefault();
    const total = consolePaletteItems.length;
    if (total) consolePaletteSelect((consolePaletteIndex + (event.key === "ArrowDown" ? 1 : -1) + total) % total);
  } else if (event.key === "Enter") {
    event.preventDefault();
    consolePaletteRun(consolePaletteIndex);
  } else if (event.key === "Escape") {
    event.preventDefault();
    event.stopPropagation();
    consolePaletteOpen(false);
  }
});

// Infrastructure app access. Credentials are displayed once and never persisted in the browser.
function integrationState(){return integrationState.value ||= {tab:"apps",data:null,loading:false};}
async function integrationApi(body){return api("/api/integrations",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});}
function integrationError(error){return ({projects_required:"Indiquez au moins un projet.",invalid_scopes:"Choisissez au moins une permission.",webhook_origin_not_allowed:"Cette destination n’est pas autorisée sur le serveur.",events_scope_required:"Activez la permission événements pour cette application.",job_not_cancellable:"La publication a déjà commencé ou la demande est terminée.",idempotency_conflict:"Cette demande a déjà été enregistrée avec un autre contenu.",revision_conflict:"Le livrable a changé. Rechargez la page.",artifacts_not_configured:"Le service Share n’est pas configuré.",service_unavailable:"Le service est temporairement indisponible."})[error.message]||"L’opération n’a pas abouti. Réessayez.";}
async function loadIntegrations(){
 const state=integrationState(),root=byId("integration-manager");if(!root||state.loading)return;state.loading=true;
 try{state.data=await integrationApi({action:"overview"});renderIntegrations();}
 catch(error){root.replaceChildren(controlNode("p",integrationError(error)));root.append(controlButton("Réessayer",loadIntegrations));}
 finally{state.loading=false;}
}
function integrationDialog(title,build){
 const dialog=document.createElement("dialog");dialog.className="integration-dialog";dialog.dataset.i18nSkip="";
 const head=controlNode("div",undefined,"integration-toolbar");head.append(controlNode("h2",title));const close=controlButton("×",()=>dialog.close());close.setAttribute("aria-label","Fermer");head.append(close);dialog.append(head);document.body.append(dialog);build(dialog);dialog.addEventListener("close",()=>dialog.remove());dialog.showModal();return dialog;
}
function integrationSecret(title,secret){integrationDialog(title,dialog=>{
 dialog.append(controlNode("p","Copiez cette clé maintenant. Elle ne sera plus affichée après fermeture."));
 const input=document.createElement("textarea");input.readOnly=true;input.value=secret;input.setAttribute("aria-label","Clé à copier");dialog.append(input);
 const copy=controlButton("Copier la clé",async()=>{try{await navigator.clipboard.writeText(input.value);copy.textContent="Copiée";}catch{input.select();}});dialog.append(copy);
 dialog.addEventListener("close",()=>{input.value="";secret="";});
});}
function integrationField(form,label,type="text",value=""){
 const row=controlNode("label",undefined,"integration-field");row.append(controlNode("span",label));const input=document.createElement(type==="textarea"?"textarea":"input");if(type!=="textarea")input.type=type;input.value=value;row.append(input);form.append(row);return input;
}
function integrationCreate(){integrationDialog("Connecter une application",dialog=>{
 const form=document.createElement("form");const name=integrationField(form,"Nom de l’application");name.required=true;name.maxLength=80;
 const projects=integrationField(form,"Projets autorisés (séparés par des virgules)");projects.required=true;projects.placeholder="Site client, Rapports";
 form.append(controlNode("small","Les noms doivent correspondre aux projets des livrables. * donne accès à tous vos projets."));
 const days=integrationField(form,"Expiration dans (jours)","number","90");days.min="1";days.max="365";
 const scopes=controlNode("fieldset");scopes.append(controlNode("legend","Permissions"));
 const labels={"artifacts:read":"Lire les livrables","artifacts:write":"Créer et modifier les versions","artifacts:visibility":"Changer la visibilité publique / privée","artifacts:delete":"Supprimer les livrables","jobs:read":"Suivre les demandes","jobs:write":"Demander des révisions","events:read":"Recevoir les événements"};
 for(const scope of integrationState().data.scopes){const label=controlNode("label");const input=document.createElement("input");input.type="checkbox";input.value=scope;input.checked=["artifacts:read","jobs:read","events:read"].includes(scope);label.append(input,document.createTextNode(labels[scope]||scope));scopes.append(label);}form.append(scopes);
 const error=controlNode("p",undefined,"integration-error");error.setAttribute("role","alert");form.append(error);const submit=controlButton("Créer la connexion",()=>{});submit.type="submit";form.append(submit);
 form.addEventListener("submit",async event=>{event.preventDefault();submit.disabled=true;try{const result=await integrationApi({section:"apps",action:"create",name:name.value,projects:projects.value.split(",").map(x=>x.trim()).filter(Boolean),scopes:[...scopes.querySelectorAll("input:checked")].map(i=>i.value),expires_in_days:Number(days.value)});dialog.close();await loadIntegrations();integrationSecret("Clé de connexion",result.token);}catch(e){error.textContent=integrationError(e);}finally{submit.disabled=false;}});dialog.append(form);
});}
function integrationSubscribe(app){integrationDialog("Recevoir les événements",dialog=>{
 const form=document.createElement("form");const url=integrationField(form,"URL HTTPS de réception","url");url.required=true;url.placeholder="https://votre-app.example/api/share-events";
 const types=controlNode("fieldset");types.append(controlNode("legend","Événements"));for(const type of integrationState().data.event_types){const label=controlNode("label"),input=document.createElement("input");input.type="checkbox";input.value=type;input.checked=["job.succeeded","job.failed","artifact.version_published","artifact.visibility_changed"].includes(type);label.append(input,document.createTextNode(type));types.append(label);}form.append(types);
 const error=controlNode("p",undefined,"integration-error");error.setAttribute("role","alert");form.append(error);const submit=controlButton("Enregistrer",()=>{});submit.type="submit";form.append(submit);
 form.addEventListener("submit",async event=>{event.preventDefault();submit.disabled=true;try{const result=await integrationApi({section:"events",action:"subscribe",app_id:app.id,url:url.value,types:[...types.querySelectorAll("input:checked")].map(i=>i.value)});dialog.close();await loadIntegrations();integrationSecret("Secret de signature des événements",result.signing_secret);}catch(e){error.textContent=integrationError(e);}finally{submit.disabled=false;}});dialog.append(form);
});}
async function integrationAction(body,button){if(button)button.disabled=true;try{const result=await integrationApi(body);if(result.token)integrationSecret("Nouvelle clé",result.token);else if(body.action==="test")toast(result.ok?"Connexion valide · API et MCP disponibles":"Connexion expirée ou révoquée",result.ok?"info":"error");await loadIntegrations();}catch(error){toast(integrationError(error),"error");}finally{if(button)button.disabled=false;}}
function integrationJobLabel(state){return ({queued:"En attente",running:"En cours",publishing:"Publication",succeeded:"Terminée",failed:"Échec",cancelled:"Annulée",interrupted:"Interrompue — à vérifier"})[state]||state;}
function renderIntegrations(){
 const state=integrationState(),data=state.data,root=byId("integration-manager");root.replaceChildren();
 const head=controlNode("div",undefined,"integration-toolbar"),titles=controlNode("div");titles.append(controlNode("h2","Applications & API"),controlNode("p","Connectez vos applications aux livrables et aux agents Monique."));head.append(titles);
 const actions=controlNode("div",undefined,"integration-actions");const docs=controlNode("a","Documentation ↗");docs.href="https://share.inklura.fr/developers";docs.target="_blank";docs.rel="noopener";actions.append(docs,controlButton("Actualiser",loadIntegrations),controlButton("Connecter une application",integrationCreate));head.append(actions);root.append(head);
 const nav=controlNode("div",undefined,"integration-tabs");nav.setAttribute("role","tablist");for(const [key,label]of [["apps","Applications"],["activity","Activité"],["deliveries","Événements"],["jobs","Demandes"]]){const b=controlButton(label,()=>{state.tab=key;renderIntegrations();});b.setAttribute("role","tab");b.setAttribute("aria-selected",String(state.tab===key));nav.append(b);}root.append(nav);
 const worker=data.worker,ready=worker?.ready&&Date.now()-Date.parse(worker.checked_at)<90000;root.append(controlNode("p",ready?`Agent de révision disponible · ${worker.provider}`:"Agent de révision indisponible · les demandes restent en attente", "integration-worker"));
 const list=controlNode("div",undefined,"integration-list");root.append(list);
 const row=(title,detail)=>{const r=controlNode("div",undefined,"integration-row"),main=controlNode("div");main.append(controlNode("strong",title),controlNode("small",detail));r.append(main);list.append(r);return r;};
 const act=(r,label,body)=>{const b=controlButton(label,()=>integrationAction(body,b));r.append(b);return b;};
 if(state.tab==="apps")for(const app of data.apps){
  const u=app.usage,expired=app.revoked_at||Date.parse(app.expires_at)<Date.now();const r=row(app.name,`${expired?"Révoquée / expirée":"Active"} · ${app.projects.join(", ")} · ${u.calls} appels · ${u.errors} erreurs · ${u.calls?Math.round(u.latency_ms/u.calls):0} ms · ${(u.upload_bytes/1048576).toFixed(1)} Mo`);
  const details=document.createElement("details");details.append(controlNode("summary","Permissions et accès"),controlNode("p",app.scopes.join(" · ")),controlNode("p","Expire le "+new Date(app.expires_at).toLocaleDateString()));r.firstChild.append(details);
  act(r,"Tester",{action:"test",id:app.id});if(!expired){act(r,"Renouveler la clé",{section:"apps",action:"rotate",id:app.id});if(app.scopes.includes("events:read"))r.append(controlButton("Événements",()=>integrationSubscribe(app)));act(r,"Révoquer",{section:"apps",action:"revoke",id:app.id});}
 }
 if(state.tab==="activity"){
  const entries=data.apps.flatMap(a=>(a.usage.recent||[]).map(e=>({...e,name:a.name}))).sort((a,b)=>b.at.localeCompare(a.at));for(const e of entries.slice(0,60))row(`${e.name} · ${e.operation}`,`${e.status} · ${e.duration_ms} ms · ${new Date(e.at).toLocaleString()}`);
 }
 if(state.tab==="deliveries"){
  for(const s of data.subscriptions){const r=row(s.url,`${s.disabled?"Désactivé":"Abonné"} · ${s.types.join(", ")}`);if(!s.disabled)act(r,"Désactiver",{section:"events",action:"unsubscribe",id:s.id});}
  for(const d of data.deliveries){const r=row(d.url,`${({delivered:"Livré",failed:"Échec",pending:"À envoyer",sending:"Envoi"})[d.state]} · ${d.attempts} tentative(s)${d.status?" · HTTP "+d.status:""}${d.error?" · "+d.error:""}`);if(d.state==="failed")act(r,"Réessayer",{section:"events",action:"retry",id:d.id});}
 }
 if(state.tab==="jobs")for(const j of data.jobs){const r=row(j.title,`${integrationJobLabel(j.state)} · ${j.project} · ${new Date(j.created_at).toLocaleString()}${j.usage?" · "+j.usage.provider+" · "+Math.round(j.usage.duration_ms/1000)+" s":""}${j.usage?.input_tokens!=null?" · "+j.usage.input_tokens+" tokens entrée / "+j.usage.output_tokens+" sortie":""}${j.error?" · "+j.error:""}`);if(j.result)r.append(controlButton("Voir la version "+j.result.version,()=>{showView("artifacts");mountArtifactLibrary(j.result.artifact_id);}));if(["queued","running"].includes(j.state))act(r,"Annuler",{section:"jobs",action:"cancel",id:j.id});}
 if(!list.children.length)list.append(controlNode("p",({apps:"Aucune application connectée. Créez une connexion et choisissez ses projets et permissions.",activity:"Les appels API et MCP apparaîtront ici.",deliveries:"Aucun événement à livrer. Configurez une URL depuis une application.",jobs:"Les demandes de création et de révision apparaîtront ici."})[state.tab],"integration-empty"));
}

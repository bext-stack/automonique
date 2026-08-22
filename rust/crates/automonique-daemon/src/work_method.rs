// SPDX-License-Identifier: Elastic-2.0
//! The working method every approved ticket job is held to.
//!
//! The console composes what a job is about (project, site, rules, the
//! request and its thread). Nothing told the agent *how* the owner wants a
//! ticket handled: read every comment, take the asks one at a time, prove
//! each one, deploy by the runbook, report per ask and never claim what was
//! not seen. A week of jobs without that contract produced reports the
//! clients answered with "non, ce n'est pas fait", checklists ticked by
//! pattern replacement, and deployments nobody had looked at. This module
//! renders the contract the worker appends to every job, in the language the
//! tickets are written in.
//!
//! The text is operator policy, not data, so it is rendered outside the
//! untrusted local-context block. An owner who wants to adjust it writes
//! `work-method.md` in the state directory; the built-in text is the default.

use std::path::Path;

/// Owner override file, relative to the state directory.
pub const OVERRIDE_FILE: &str = "work-method.md";
/// Ceiling on the rendered method so a verbose override cannot crowd the job
/// prompt out of the provider's budget.
pub const MAX_METHOD_BYTES: usize = 6 * 1024;

/// The marker line a completion report must carry, checked by the worker.
pub const REPORT_MARKER: &str = "Demande 1";

/// Render the method, with `binary` as the absolute path of the running
/// `automonique` executable so the screenshot verb can be called by path
/// from any working directory.
pub fn render(state_dir: &Path, binary: &Path) -> String {
    let body = match std::fs::read_to_string(state_dir.join(OVERRIDE_FILE)) {
        Ok(text) if !text.trim().is_empty() => text,
        _ => default_text(),
    };
    let body = body.replace("{automonique}", &binary.display().to_string());
    let mut out = String::from("[work_method trust=operator_policy]\n");
    out.push_str(&bounded(&body, MAX_METHOD_BYTES));
    out.push_str("\n[/work_method]");
    out
}

fn bounded(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.trim_end().to_owned();
    }
    let mut cut = max;
    while cut > 0 && !text.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}\n[truncated=yes]", text[..cut].trim_end())
}

fn default_text() -> String {
    String::from(
        "\
MÉTHODE MONIQUE — à respecter pour chaque ticket (le client lit ton compte rendu).

1. LIRE TOUT. Le ticket ET tous ses commentaires, jusqu'au dernier. Le dernier commentaire humain est souvent la vraie demande (relance, correction, « non ce n'est pas fait »). Si le client dit qu'un point n'est pas fait, il n'est pas fait : repars de son constat, pas de ton précédent compte rendu.
2. DÉCOUPER. Numérote chaque demande (Demande 1, 2, …) avant d'agir et traite-les une par une. Une demande ambiguë ou risquée n'est pas devinée : elle est signalée dans le compte rendu et le reste est traité.
3. PROUVER CHAQUE DEMANDE. Rien n'est « fait » sans une vérification lue de tes yeux :
   - rendu visuel (page, composant, style, layout) → capture obligatoire, puis OUVRE le PNG et contrôle l'attendu :
     {automonique} shot <url> --out /tmp/monique-<demande>.png [--host <vhost>] [--width 390] [--full]
     Succès = ligne MONIQUE_SHOT_OK: <png> ; échec = MONIQUE_SHOT_FAIL: <raison>. Pour du responsive, capture desktop ET mobile (--width 390). Un curl ne remplace jamais une capture pour une demande visuelle.
   - comportement / données → commande ou test dont tu colles le résultat.
   - déploiement → preuve que le code SERVI contient le changement (URL publique en HTTP 200 + marqueur visible ou commit servi), pas seulement que le build a réussi.
4. CASES À COCHER. Ne coche JAMAIS en masse ni par remplacement de motif. Une case se coche individuellement, après la preuve de cette demande précise. Doute = case laissée vide + explication. Cocher une case non vérifiée est la faute la plus grave.
5. DÉPLOYER SELON LE RUNBOOK. Lis AGENTS.md / .agents/deploy.md du dépôt (ou le runbook du site) avant toute mise en ligne et exécute exactement sa procédure. Ne redémarre aucun service hors de cette procédure. Un changement dans un worktree ou une branche n'est PAS livré tant que le service ne le sert pas : vérifie l'URL publique après déploiement (capture + HTTP 200) et purge les caches que le runbook nomme.
6. QUALITÉ. Quand le client demande une amélioration graphique ou UX, livre un rendu soigné, cohérent avec le design system du site, pas un minimum. Relis les captures avec un œil de client.
7. PÉRIMÈTRE. Ne touche qu'aux sites et fichiers concernés. Préserve le travail des autres (jamais de reset/checkout/stash destructif). Aucun secret, identifiant ou chemin interne dans un commentaire GitHub.

COMPTE RENDU GITHUB (obligatoire, en français, court, sans jargon interne) — un commentaire unique sur l'issue, structuré ainsi :
- **Demande 1 — <titre court>** : Fait | Partiel | Non fait
  Où : <site · fichier(s)>
  Vérification : <ce qui a été contrôlé et comment>
  Preuve : <chemin de capture MONIQUE_SHOT_OK, commande, URL, résultat de test>
- **Demande 2 — …** (même format pour chaque demande)
- **Déploiement** : <procédure suivie> · <URL vérifiée> · <preuve que le changement est servi>
- **Non fait / à clarifier** : <liste honnête, ou « rien »>
N'écris jamais « terminé », « livré » ou « vérifié » pour une demande sans preuve lue. Laisse l'issue ouverte sauf consigne contraire. Ta réponse finale doit contenir le permalien exact de ce commentaire (…#issuecomment-…).
",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_method_names_the_shot_verb_and_the_report_shape() {
        let root = tempfile::tempdir().expect("tempdir");
        let method = render(root.path(), Path::new("/opt/monique/bin/automonique"));
        assert!(method.starts_with("[work_method trust=operator_policy]\n"));
        assert!(method.contains("/opt/monique/bin/automonique shot <url>"));
        assert!(method.contains("MONIQUE_SHOT_OK"));
        assert!(method.contains(REPORT_MARKER));
        assert!(method.contains("Ne coche JAMAIS en masse"));
        assert!(method.contains("#issuecomment-"));
        assert!(method.ends_with("[/work_method]"));
        assert!(method.len() <= MAX_METHOD_BYTES + 64);
    }

    #[test]
    fn an_owner_override_replaces_the_text_and_is_bounded() {
        let root = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            root.path().join(OVERRIDE_FILE),
            "Ma méthode: {automonique} shot d'abord.\n",
        )
        .expect("write");
        let method = render(root.path(), Path::new("/x/automonique"));
        assert!(method.contains("Ma méthode: /x/automonique shot d'abord."));
        assert!(!method.contains("MÉTHODE MONIQUE"));

        std::fs::write(root.path().join(OVERRIDE_FILE), "é".repeat(10_000)).expect("write");
        let method = render(root.path(), Path::new("/x/automonique"));
        assert!(method.len() <= MAX_METHOD_BYTES + 80);
        assert!(method.contains("[truncated=yes]"));

        std::fs::write(root.path().join(OVERRIDE_FILE), "   \n").expect("write");
        let method = render(root.path(), Path::new("/x/automonique"));
        assert!(
            method.contains("MÉTHODE MONIQUE"),
            "a blank override keeps the default"
        );
    }
}

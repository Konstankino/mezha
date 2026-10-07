//! What the approval gate's matcher catches, what it lets through, and the
//! gaps it knowingly leaves. The matcher is advisory: these tables pin its
//! behaviour, they don't make it a boundary.

use mezha_hooks::matcher::{Hit, scan};
use mezha_spec::CommandPrefix;

fn gates() -> Vec<CommandPrefix> {
    ["git push", "terraform apply", "docker image push"]
        .iter()
        .map(|g| CommandPrefix::parse(g).unwrap())
        .collect()
}

fn hit(command: &str) -> Option<Hit> {
    scan(command, &gates())
}

const CLAUDE_COMMIT: &str = "git commit -m \"$(cat <<'EOF'\nFix the push retry bug\n\nDon't push before CI is green; git push waits.\n\nCo-Authored-By: Claude <noreply@anthropic.com>\nEOF\n)\"";

#[test]
fn blocks_gated_commands() {
    for command in [
        "git push",
        "git push origin main",
        "git -C . push origin main",
        "git -c user.name=x push",
        "git --no-pager push",
        "cd repo && git push",
        "git status; git push",
        "FOO=1 git push",
        "sudo git push",
        "env -i git push",
        "nice -n 5 git push",
        "timeout 60 git push",
        "xargs git push < remotes",
        "(cd x; git push)",
        "{ git push; }",
        "if true; then git push; fi",
        "bash -c 'git push'",
        "sh -lc \"git push --force\"",
        "bash -o pipefail -c 'git push'",
        "eval git push",
        "echo $(git push)",
        "echo `git push`",
        "/usr/bin/git push",
        "GIT push",
        "git.exe push",
        "echo git push | sh",
        "cat <<EOF | bash\ngit push\nEOF",
        "bash <<< 'git push'",
        "git push \"unterminated",
        "x=git; $x push",
        "git \"$SUB\"",
        "terraform -chdir=infra apply",
        "terraform apply -auto-approve",
        "docker --context prod image push app:1",
        "git \\\n  push",
    ] {
        assert_eq!(
            hit(command),
            Some(Hit::Gate(gate_for(command))),
            "{command:?}"
        );
    }
}

fn gate_for(command: &str) -> usize {
    if command.contains("terraform") {
        1
    } else if command.contains("docker") {
        2
    } else {
        0
    }
}

#[test]
fn lets_other_commands_through() {
    for command in [
        "git status",
        "git log --grep=push",
        "git log --grep push",
        "git stash push",
        "git -C push status",
        "git commit -m \"push later\"",
        CLAUDE_COMMIT,
        "echo \"git push\"",
        "grep -rn 'git push' docs",
        "cat > notes.txt <<'EOF'\ngit push\nEOF",
        "terraform plan",
        "docker push app:1",
        "mezha approve --status",
        "ls -la && cargo test",
        "echo hi > push",
    ] {
        assert_eq!(hit(command), None, "{command:?}");
    }
}

#[test]
fn the_agent_cannot_approve_itself() {
    for command in [
        "mezha approve",
        "mezha approve --minutes 5",
        "mezha -p . approve",
        "~/.cargo/bin/mezha approve",
        "bash -c 'mezha approve'",
    ] {
        assert_eq!(hit(command), Some(Hit::SelfApproval), "{command:?}");
    }
}

#[test]
fn refuses_deep_nesting() {
    let deep = "echo ".to_string() + &"$(".repeat(12) + "git push" + &")".repeat(12);
    assert_eq!(hit(&deep), Some(Hit::TooDeep));
}

/// Known gaps, kept visible: the matcher is advisory, and these are why.
/// If one of them starts blocking, move it to `blocks_gated_commands`.
#[test]
fn known_gaps_are_let_through() {
    for command in [
        "./push.sh",
        "python3 -c \"import os; os.system('git push')\"",
        "git p",
        "bash -c \"$CMD\"",
        "eval \"$CMD\"",
        "printf 'git push' > p.sh && sh p.sh",
    ] {
        assert_eq!(hit(command), None, "{command:?}");
    }
}

/// Accepted false positives: blocking these is the price of scanning every
/// word instead of modelling every wrapper.
#[test]
fn accepted_false_positives() {
    for command in ["echo git push", "man git push"] {
        assert!(hit(command).is_some(), "{command:?}");
    }
}

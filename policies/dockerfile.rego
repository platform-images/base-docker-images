package dockerfile

import future.keywords.if
import future.keywords.in

# ── Required OCI labels ────────────────────────────────────────────────────────

required_labels := {
    "org.opencontainers.image.source",
    "org.opencontainers.image.licenses",
}

label_keys[key] if {
    cmd := input[_]
    cmd.Cmd == "label"
    # Labels are stored as flat key=value pairs in the parsed Dockerfile
    pair := cmd.Value[_]
    [key, _] := split(pair, "=")
}

deny[msg] if {
    required := required_labels[_]
    not required in label_keys
    msg := sprintf("Missing required OCI label: %s", [required])
}

# ── Non-root USER ──────────────────────────────────────────────────────────────

user_instructions[val] if {
    cmd := input[_]
    cmd.Cmd == "user"
    val := cmd.Value[0]
}

deny[msg] if {
    not count(user_instructions) > 0
    msg := "Dockerfile must set a non-root USER"
}

deny[msg] if {
    val := user_instructions[_]
    lower(val) == "root"
    msg := "Dockerfile must not run as root"
}

deny[msg] if {
    val := user_instructions[_]
    val == "0"
    msg := "Dockerfile must not run as uid 0 (root)"
}

# ── Forbidden instructions ─────────────────────────────────────────────────────

deny[msg] if {
    cmd := input[_]
    cmd.Cmd == "add"
    msg := "Use COPY instead of ADD — ADD can unpack archives and fetch remote URLs unexpectedly"
}

# ── Digest pinning ─────────────────────────────────────────────────────────────

from_instructions[img] if {
    cmd := input[_]
    cmd.Cmd == "from"
    img := cmd.Value[0]
}

deny[msg] if {
    img := from_instructions[_]
    # Skip scratch and stage aliases (no colon or @)
    contains(img, ":")
    not contains(img, "@sha256:")
    not img == "scratch"
    msg := sprintf("FROM %s must be pinned to a digest (@sha256:...)", [img])
}

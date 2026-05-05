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
    pair := cmd.Value[_]
    is_string(pair)
    [key, _] := split(pair, "=")
}

deny[msg] if {
    required := required_labels[_]
    not required in label_keys
    msg := sprintf("Missing required OCI label: %s", [required])
}

# ── Non-root USER ──────────────────────────────────────────────────────────────

# Helper used only for the presence check (no string ops on the value)
has_user_instruction if {
    cmd := input[_]
    cmd.Cmd == "user"
}

deny[msg] if {
    not has_user_instruction
    msg := "Dockerfile must set a non-root USER"
}

deny[msg] if {
    cmd := input[_]
    cmd.Cmd == "user"
    val := cmd.Value[0]
    is_string(val)
    lower(val) == "root"
    msg := "Dockerfile must not run as root"
}

deny[msg] if {
    cmd := input[_]
    cmd.Cmd == "user"
    val := cmd.Value[0]
    is_string(val)
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

deny[msg] if {
    cmd := input[_]
    cmd.Cmd == "from"
    img := cmd.Value[0]
    is_string(img)
    contains(img, ":")
    not contains(img, "@sha256:")
    not img == "scratch"
    msg := sprintf("FROM %s must be pinned to a digest (@sha256:...)", [img])
}

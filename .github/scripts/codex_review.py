#!/usr/bin/env python3
"""Codex-powered pull-request reviewer for Reverify.

Runs in GitHub Actions on each PR: it fetches the PR diff, asks an OpenAI model
to review it, and posts the review as a single PR comment. Pure standard library
(no dependencies), matching the project. If ``OPENAI_API_KEY`` is not configured
the script exits quietly, so forks and contributors without the secret are never
blocked.

Environment:
    OPENAI_API_KEY   required to actually run a review (skips if missing)
    OPENAI_MODEL     model id (default: gpt-4o; set to your Codex model when granted)
    OPENAI_BASE_URL  API base (default: https://api.openai.com/v1)
    GITHUB_TOKEN     provided automatically by Actions
    GITHUB_REPOSITORY  owner/repo (provided by Actions)
    PR_NUMBER        pull-request number (wired from the workflow)
"""

import json
import os
import sys
import urllib.request
import urllib.error

MAX_DIFF_CHARS = 30000
API = "https://api.github.com"


def _http(method, url, headers, data=None, timeout=60):
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8")


def get_pr_diff(repo, pr_number, gh_token):
    url = f"{API}/repos/{repo}/pulls/{pr_number}"
    headers = {
        "Authorization": f"Bearer {gh_token}",
        "Accept": "application/vnd.github.v3.diff",
        "User-Agent": "reverify-codex-review",
    }
    return _http("GET", url, headers)


def review_with_openai(diff, model, base_url, api_key):
    system = (
        "You are a precise, senior code reviewer for a reverse-engineering "
        "toolkit. Review the pull-request diff for correctness bugs, security "
        "issues, and clear simplifications. Be specific and concise: use short "
        "bullet points that reference file and symbol. Do not restate the diff. "
        "If nothing serious stands out, say so in one line."
    )
    body = json.dumps({
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": f"Review this diff:\n\n{diff}"},
        ],
        "temperature": 0.2,
    }).encode("utf-8")
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "User-Agent": "reverify-codex-review",
    }
    raw = _http("POST", f"{base_url.rstrip('/')}/chat/completions", headers, data=body)
    return json.loads(raw)["choices"][0]["message"]["content"].strip()


def post_comment(repo, pr_number, gh_token, body):
    url = f"{API}/repos/{repo}/issues/{pr_number}/comments"
    headers = {
        "Authorization": f"Bearer {gh_token}",
        "Accept": "application/vnd.github+json",
        "Content-Type": "application/json",
        "User-Agent": "reverify-codex-review",
    }
    data = json.dumps({"body": body}).encode("utf-8")
    _http("POST", url, headers, data=data)


def main():
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        print("OPENAI_API_KEY not set — skipping Codex review (this is fine).")
        return 0

    repo = os.getenv("GITHUB_REPOSITORY", "")
    pr_number = os.getenv("PR_NUMBER", "")
    gh_token = os.getenv("GITHUB_TOKEN", "")
    model = os.getenv("OPENAI_MODEL") or "gpt-4o"
    base_url = os.getenv("OPENAI_BASE_URL") or "https://api.openai.com/v1"

    if not (repo and pr_number and gh_token):
        print("Missing repo/PR/token context — skipping.")
        return 0

    try:
        diff = get_pr_diff(repo, pr_number, gh_token)
    except urllib.error.HTTPError as exc:
        print(f"Could not fetch diff: {exc}")
        return 0

    if not diff.strip():
        print("Empty diff — nothing to review.")
        return 0

    truncated = diff[:MAX_DIFF_CHARS]
    note = "" if len(diff) <= MAX_DIFF_CHARS else "\n\n_(diff truncated for review)_"

    try:
        review = review_with_openai(truncated, model, base_url, api_key)
    except Exception as exc:  # never fail the build on a review hiccup
        print(f"Review call failed: {exc}")
        return 0

    body = f"## 🤖 Codex review\n\n{review}{note}\n\n_Model: `{model}`. Automated review — a human still merges._"
    try:
        post_comment(repo, pr_number, gh_token, body)
        print("Posted Codex review comment.")
    except Exception as exc:
        print(f"Could not post comment: {exc}")
        # Still surface the review in the logs so it isn't lost.
        print("\n--- review ---\n" + review)
    return 0


if __name__ == "__main__":
    sys.exit(main())

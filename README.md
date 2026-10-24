# SABLE — Safe Attack-Boundary & Logic Evaluator

> A non-destructive security assessment tool for Linux servers.

SABLE connects to a Linux host over SSH (read-only), collects security-relevant
evidence — file permissions, SUID/SGID binaries, sudoers rules, cron jobs,
services, and more — and reconstructs how those weaknesses chain into multi-step
attack paths from an initial foothold to root. It scores each path by how well
the evidence supports it, then recommends the smallest set of reversible,
non-destructive fixes that breaks the most high-confidence paths, and generates
a prioritised report.

It never runs exploits and never modifies the target during assessment.

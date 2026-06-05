# Bug Bounty Case Studies

A collection of security writeups and vulnerability analyses based on public bug bounty reports, disclosed CVEs, and real-world security incidents.

This repository is part of my cybersecurity learning journey, focusing on understanding:

* Vulnerability discovery techniques
* Root cause analysis
* Exploitation paths
* Security impact assessment
* Secure coding practices
* OWASP Top 10

---

## Purpose

The goal of this repository is **education and defensive security learning**.

Instead of simply reading vulnerability reports, I document:

1. What the vulnerability is
2. How the vulnerable code works
3. Why the vulnerability exists
4. How the attack works
5. Security impact
6. Mitigation and secure coding practices
7. Related OWASP categories

---

## Repository Structure

```text
bug-bounty-case-studies/
│
├── authentication/
│   ├── rocket-chat-auth-bypass-nosql-injection.md
│
├── ...
│
└── README.md
```

---

## Topics Covered

### Authentication

* Authentication Bypass
* Session Management Issues
* Password Reset Vulnerabilities
* OAuth Misconfigurations

### Access Control

* IDOR
* Privilege Escalation
* Forced Browsing
* Authorization Bypass

### Injection

* SQL Injection
* NoSQL Injection
* Command Injection
* Template Injection

### Client-Side

* Cross-Site Scripting (XSS)
* DOM XSS
* CSRF
* Clickjacking

### Miscellaneous

* Information Disclosure
* Business Logic Flaws
* Misconfigurations

---

## Example Writeups

| Vulnerability                                         | Category                   | Severity |
| ----------------------------------------------------- | -------------------------- | -------- |
| Rocket.Chat Authentication Bypass via NoSQL Injection | Authentication / Injection | Critical |
| IDOR Leading to Account Takeover                      | Broken Access Control      | High     |
| Stored XSS in User Profile                            | Cross-Site Scripting       | High     |

---

## Methodology

For each case study I try to answer:

* What is the attack surface?
* What assumptions did developers make?
* Which security control failed?
* How does the exploit work?
* What is the business impact?
* How should it be fixed?

---

## Skills Practiced

* Web Application Security
* Threat Modeling
* Code Review
* OWASP Top 10
* Bug Bounty Methodology
* Secure Development Practices

---

## Disclaimer

All writeups are based on publicly disclosed information.

The content is intended for:

* Security education
* Vulnerability research
* Defensive security training

Do not use any information in this repository against systems without explicit authorization.

---

## Learning Progress

* [ ] Authentication
* [ ] Broken Access Control
* [ ] Cryptographic Failures
* [ ] Injection
* [ ] Security Misconfiguration
* [ ] Vulnerable Components
* [ ] Identification and Authentication Failures
* [ ] Software and Data Integrity Failures
* [ ] Security Logging and Monitoring Failures
* [ ] SSRF

---

## About Me

Computer Networks and Data Communications student with interests in:

* Application Security
* Bug Bounty
* Web Security
* Penetration Testing
* Secure Software Development

Currently studying OWASP Top 10, web vulnerabilities, and real-world bug bounty reports.

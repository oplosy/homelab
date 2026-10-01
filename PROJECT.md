# SecureEdge

## What it is and what it does

SecureEdge is a self-hosted platform for securely accessing and publishing applications on Linux VPSs. It combines a private network, encrypted administration, HTTPS, reverse proxying, identity-based access, a web application firewall, and API traffic policies.

AtlasRisk is its first real application. SecureEdge provides the infrastructure around AtlasRisk, not its financial features. The two projects remain in separate repositories: AtlasRisk owns its application and data logic; SecureEdge owns the environment, network, and access layer. The infrastructure should be reusable for another application through configuration, without becoming a general-purpose hosting product.

The intended setup has two VPSs. An edge server receives application traffic and handles HTTPS, access protection, and HTTP filtering. An application server runs AtlasRisk and its supporting services. A WireGuard tunnel carries traffic between them. The owner also uses WireGuard for private access and administration.

```text
Owner -> VPN -> private application access and server administration

Browser -> HTTPS -> reverse proxy / WAF -> identity access layer
        -> WireGuard -> application ingress -> AtlasRisk

API routing and rate limits live in the proxy or a dedicated API gateway.
Databases, object storage, and management interfaces stay private.
```

Private access is sufficient for personal use. Internet access is an additional capability, with identity protection in front of the application. Public accessibility does not mean anonymous access to financial data.

This is a practical systems, networking, and defensive-security project. Its value comes from a working service that the owner can use and whose access boundaries can be demonstrated.

## What we want

- **Real personal use.** AtlasRisk should be usable through SecureEdge from the owner's devices, not merely represented by a placeholder page.
- **A clear network boundary.** Application traffic enters through the intended access layer. Backend services are not independently exposed to the internet.
- **Encrypted connectivity.** WireGuard provides private administration and edge-to-application communication. Browser access uses valid HTTPS.
- **Owner-only access.** Remote application access is protected by a verified identity, with MFA through the identity provider where available. Browser authentication and cross-site request protection cover the application's state-changing API calls.
- **Working HTTP protection.** The WAF rejects representative malicious requests without breaking normal AtlasRisk activity, including imports and API requests.
- **Useful API policies.** API routes and rate limits have observable behavior. A separate API gateway is appropriate when it adds meaningful API-specific functionality; it is not required just to duplicate the reverse proxy.
- **Enough visibility to operate it.** Logs and basic monitoring help explain access failures, application connectivity, certificate problems, and resource pressure without exposing secrets or financial content.
- **Recoverability.** Configuration and application data can be backed up and restored. An unsuccessful configuration change can be reversed without casually deleting application data.
- **Manageable complexity and cost.** The setup fits personal-use traffic and a small VPS budget. Its architecture and operating instructions are understandable enough to maintain.

WireGuard is the VPN choice. NGINX, ModSecurity with OWASP CRS, and an OIDC access proxy such as oauth2-proxy are suitable starting choices for the HTTP and identity layers. Kong is a possible dedicated gateway. The remaining tools, packaging, and deployment approach can change when a simpler or better fit preserves these outcomes; there is no need to freeze every implementation detail in advance.

The web interface and API should remain under the same origin where practical. AtlasRisk is deployed from its own application artifacts rather than copied into this repository.

## What is outside the scope

- Reimplementing AtlasRisk, its financial calculations, or a future TradeLedger module inside SecureEdge.
- Trade signals, automated order execution, or a new trading product.
- A multi-user SaaS platform, customer billing, or a large hosting administration interface.
- A public forward proxy, an open VPN service, or unrestricted access to backend and management ports.
- Extra infrastructure introduced only to increase the number of technologies used.
- Treating a WAF as a replacement for authentication, application security, or protection against every kind of DDoS.
- Presenting two servers as high availability when neither server's role has a working replacement.
- Publishing real financial data, credentials, private keys, session tokens, or sensitive request bodies in demos, logs, or the repository.

## What counts as done

The project is complete when it is running on real VPSs and is useful to its owner, not just when configuration files or a local demo exist.

- **Usable application:** the owner can access AtlasRisk and complete representative application actions through SecureEdge.
- **Correct access boundaries:** VPN administration works; unauthorized application access is rejected; direct backend, data, and management access from the internet is blocked.
- **Working protections:** HTTPS, identity access, WAF filtering, API route policies, and rate limits behave as intended. Normal application use still works.
- **Predictable failures:** losing the application connection or access-protection component causes a controlled failure, not an unprotected alternative route.
- **Demonstrated recovery:** a configuration rollback and a backup restore have actually been exercised, with the restored environment usable.
- **Operable handoff:** another setup or recovery can be performed using short, accurate instructions; the deployed components and necessary configuration are identifiable.
- **Honest evidence:** the working behavior can be shown with concise results or a reproducible demonstration. Unimplemented features, unavailable checks, and remaining limitations are stated rather than counted as completed.

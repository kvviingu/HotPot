# Security

HotPot is a personal learning project, mostly written with AI help and reviewed for security with
Claude Opus 5.5, not by a professional auditor. It comes with no warranty; run it at your own risk.

HotPot deliberately runs vulnerable-looking services. Reports about its *bait* (fake credentials,
weak-looking passwords, the decoys answering) are expected behaviour, not vulnerabilities.

Please do report anything that lets an attacker get **out** of the bait:

* escaping the backend container or reaching the internet from it;
* using the front VM, the decoys or Squid to attack other systems;
* reaching the admin SSH port, the dashboard or the operator's machine;
* script or HTML injection into the dashboard from logged attacker data;
* weaknesses in `hotpot` itself (the one-line installers, `hotpot update`, SSH handling).

Report privately with GitHub's **Report a vulnerability** button on the repository's Security tab.
Please don't open a public issue for these. You'll get an answer within a week.

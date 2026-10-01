# Sample drop files

Copy a file into the matching `data/drop/<domain>/` folder to test the `file_drop`
adapter in live mode. `firewall_policy_review.csv` matches the `field_map`
configured for the firewall connector in `config/lodestar.yaml`.

Any product that can export CSV/JSON on a schedule (or a SIEM saved search,
or a SOAR playbook) can feed LODESTAR this way. See docs/CONNECTOR_GUIDE.md.

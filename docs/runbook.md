# IDS Runbook — Operations & Incident Response

## 1. Daily Health Checks
```bash
docker compose ps                  # All containers running?
docker compose logs ids-engine | tail -50   # Any errors?
make test                          # CI green?
```

## 2. Incident Response Playbook

### Severity: CRITICAL
1. Immediately check `src_ip` in dashboard Top Attacking IPs
2. Cross-reference MITRE technique in alert
3. If SYN_FLOOD → block IP at firewall, capture PCAP evidence
4. If SUSPICIOUS_SPAWN (RCE) → isolate host, preserve memory dump
5. Escalate to security team within 15 minutes

### Severity: HIGH
1. Review alert context in dashboard
2. Check `mitre_tactic` for attack chain
3. Correlate with HIDS events for same source
4. Block IP if confirmed malicious
5. Document in incident log

### Severity: MEDIUM / LOW
1. Review during next business hour
2. Tune thresholds if false positive pattern identified

## 3. Model Retraining
```bash
# Trigger when false positive rate > 5% or new attack patterns emerge
make train
# Models saved to src/ml/models/
# Restart engine to load new models
docker compose restart ids-engine
```

## 4. False Positive Reduction
- Increase `ANOMALY_THRESHOLD` in `.env` (0.70 → 0.80)
- Add known-good IPs to allowlist in `signature_engine.py`
- Increase `ENSEMBLE_VOTE_THRESHOLD` (2 → 3 = all models must agree)

## 5. Rollback
```bash
git checkout <previous-tag>
make build && make up
```

## 6. Backup
```bash
# SQLite DB backup
cp db/ids.sqlite db/ids_backup_$(date +%Y%m%d).sqlite
# Baseline backup
cp data/baselines/file_hashes.json data/baselines/hashes_backup_$(date +%Y%m%d).json
```

## 7. Log Rotation
Logs at `logs/ids.log`. Rotate weekly:
```bash
logrotate -f /etc/logrotate.d/ids   # or use Docker log driver limits
```

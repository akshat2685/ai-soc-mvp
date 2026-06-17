from .base import BaseDetector, DetectionResult
from .credential_stuffing import CredentialStuffingDetector
from .otp_abuse import OTPAbuseDetector
from .bot_detection import BotDetector
from .account_takeover import ATODetector
from .coupon_abuse import CouponAbuseDetector
from .distributed_attack import DistributedAttackDetector
from .ai_abuse import AIAbuseDetector
from .behavioral_analytics import BehavioralAnomalyDetector
from .network_anomaly import NetworkAnomalyDetector
from .correlation import CorrelationEngine

# Registry of all active detectors
DETECTOR_REGISTRY = [
    CredentialStuffingDetector(),
    OTPAbuseDetector(),
    BotDetector(),
    ATODetector(),
    CouponAbuseDetector(),
    DistributedAttackDetector(),
    AIAbuseDetector(),
    BehavioralAnomalyDetector(),
    NetworkAnomalyDetector(),
]

_correlation_engine = CorrelationEngine()


def run_all_detectors(source_ip: str, user_id: str = None, device_id: str = None,
                      user_agent: str = None, headers: dict = None):
    """Run all registered detectors and then the correlation engine."""
    from detection import calculate_fingerprint
    device_fingerprint = calculate_fingerprint(user_agent, device_id, headers)

    # Populate fingerprint for recent logs
    from database import get_db
    with get_db() as conn:
        conn.execute(
            "UPDATE logs SET device_fingerprint = ? WHERE source_ip = ? AND timestamp >= datetime('now', '-5 seconds') AND device_fingerprint IS NULL",
            (device_fingerprint, source_ip)
        )
        conn.commit()

    results = []
    for detector in DETECTOR_REGISTRY:
        try:
            result = detector.detect(source_ip, user_id, device_fingerprint, user_agent, headers)
            if result:
                results.append(result)
        except Exception as e:
            print(f"[DETECTOR] {detector.name} failed: {e}")

    # Run correlation engine on any new alerts
    if results:
        _correlation_engine.run(source_ip, user_id, device_fingerprint)

    return results

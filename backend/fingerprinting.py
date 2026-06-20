import hashlib
from typing import Optional

# Requires `ua-parser` which we'll assume is or will be in requirements
# For now, we simulate parsing if the library isn't strictly available.
try:
    from ua_parser import user_agent_parser
    HAS_UA_PARSER = True
except ImportError:
    HAS_UA_PARSER = False

async def generate_robust_fingerprint(request_headers: dict, request_form: dict = None, request_ip: str = "") -> str:
    """
    Generates an advanced device fingerprint combining multiple entropy sources to 
    detect evasion techniques and IP rotation.
    
    Why this beats simple UA+ID:
    - UA spoofing is trivial (curl can fake it)
    - TLS fingerprinting (JA3) is harder to spoof without modifying the TCP stack
    - Canvas/WebGL reveal underlying hardware/OS renderer, very hard to fake en masse
    """
    if request_form is None:
        request_form = {}
        
    ua_string = request_headers.get("user-agent", "")
    
    if HAS_UA_PARSER:
        parsed = user_agent_parser.Parse(ua_string)
        browser = parsed.get('user_agent', {}).get('family', 'unknown')
        os_family = parsed.get('os', {}).get('family', 'unknown')
        ua_component = f"{browser}_{os_family}"
    else:
        ua_component = ua_string
        
    # TLS fingerprint (JA3) - Requires upstream proxy like Nginx/Envoy to inject this header
    ja3_fingerprint = request_headers.get("x-ja3", "unknown")
    
    # Accept-Language is usually fixed per attacker device/bot script
    accept_lang = request_headers.get("accept-language", "")
    
    # If JS executed on victim's browser, a canvas hash can be sent in the payload
    canvas_fp = request_form.get("canvas_fingerprint", "")
    
    # Explicit Device ID (e.g. from mobile app or persistent cookie)
    explicit_id = request_form.get("device_id", "")
    
    components = [
        ua_component,
        explicit_id,
        ja3_fingerprint,
        accept_lang,
        canvas_fp,
    ]
    
    # If we have literally nothing unique, fallback to IP (weakest fingerprint)
    if all(not c or c == 'unknown' for c in components):
        components.append(request_ip)
        
    fingerprint = hashlib.sha256("|".join(components).encode()).hexdigest()
    return fingerprint

async def detect_ip_rotation_attack(
    redis_client,
    fingerprint: str, 
    current_ip: str,
    time_window_minutes: int = 5
) -> bool:
    """
    Detects if the SAME device fingerprint is rapidly switching between DIFFERENT IPs.
    This strongly indicates credential stuffing utilizing a proxy network or botnet.
    """
    key = f"rotation_detect:{fingerprint}"
    try:
        # Get all IPs seen for this fingerprint
        recent_ips = await redis_client.hgetall(key)
        
        # If we've seen > 10 different IPs for the EXACT same browser fingerprint in 5 mins
        if len(recent_ips) > 10:
            # Attack detected
            from logging_config import get_logger
            get_logger(__name__).critical(
                "IP_ROTATION_ATTACK_DETECTED",
                extra={
                    "fingerprint": fingerprint,
                    "ip_count": len(recent_ips),
                    "current_ip": current_ip
                }
            )
            return True
            
        # Record this IP
        await redis_client.hincrby(key, current_ip, 1)
        # Refresh TTL
        await redis_client.expire(key, time_window_minutes * 60)
    except Exception as e:
        from logging_config import get_logger
        get_logger(__name__).error(f"Redis error in IP rotation detection: {e}")
        
    return False

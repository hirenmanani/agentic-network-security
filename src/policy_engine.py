# src/policy_engine.py
import json
import ipaddress
from typing import List, Dict
import logging

logger = logging.getLogger(__name__)


class PolicyEngine:
    """Enforces security policies and constraints"""

    def __init__(self, config_path: str = 'config/policies.json'):
        with open(config_path, 'r') as f:
            self.policies = json.load(f)

        self.severity_thresholds = self.policies['severity_thresholds']
        self.protected_networks = [
            ipaddress.ip_network(net)
            for net in self.policies['protected_ips']
        ]
        self.whitelisted_ips = set(self.policies['whitelisted_ips'])

        logger.info("Policy engine initialized")

    def get_allowed_actions(self, severity: str, confidence: float) -> List[str]:
        """Get allowed actions based on severity and confidence"""
        if severity not in self.severity_thresholds:
            return ['monitor']

        threshold_config = self.severity_thresholds[severity]

        if confidence >= threshold_config['min_confidence']:
            return threshold_config['allowed_actions']
        else:
            # Confidence too low - downgrade to monitoring
            return ['monitor', 'alert']

    def is_protected_ip(self, ip: str) -> bool:
        """Check if IP is in protected range (internal network)"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            for network in self.protected_networks:
                if ip_obj in network:
                    return True
            return False
        except ValueError:
            logger.warning(f"Invalid IP address: {ip}")
            return False

    def is_whitelisted(self, ip: str) -> bool:
        """Check if IP is whitelisted"""
        return ip in self.whitelisted_ips

    def validate_action(self, action: str, threat: Dict) -> bool:
        """Validate if action is allowed for given threat"""
        allowed_actions = self.get_allowed_actions(
            threat['severity'],
            threat['confidence']
        )

        if action not in allowed_actions:
            logger.warning(
                f"Action '{action}' not allowed for severity '{threat['severity']}'")
            return False

        if action == 'block' and self.is_protected_ip(threat['source_ip']):
            logger.warning(f"Cannot block protected IP: {threat['source_ip']}")
            return False

        return True

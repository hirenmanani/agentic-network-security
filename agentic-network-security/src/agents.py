from typing import Dict, List, Any
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


class BaseAgent:
    """Base class for all agents"""

    def __init__(self, name: str):
        self.name = name
        self.memory = []

    def log_action(self, action: str, details: Dict):
        """Log agent action"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'agent': self.name,
            'action': action,
            'details': details
        }
        self.memory.append(log_entry)
        logger.info(f"[{self.name}] {action}: {details}")


class MonitoringAgent(BaseAgent):
    """Monitors for new data and triggers processing"""

    def __init__(self):
        super().__init__("MonitoringAgent")

    def trigger_processing(self, data: Any) -> Dict:
        """Trigger data processing pipeline"""
        self.log_action("trigger_processing", {
            "data_size": len(data) if hasattr(data, '__len__') else 0
        })
        return {
            'status': 'processing_triggered',
            'data': data,
            'timestamp': datetime.now().isoformat()
        }


class DetectionAgent(BaseAgent):
    """Runs threat detection algorithms"""

    def __init__(self, detector):
        super().__init__("DetectionAgent")
        self.detector = detector

    def analyze_features(self, features) -> List[Dict]:
        """Analyze features and detect threats"""
        self.log_action("analyze_features", {"feature_count": len(features)})

        rule_threats = self.detector.detect_rule_based(features)
        anomaly_threats = self.detector.detect_anomalies(features)
        all_threats = self.detector.combine_detections(
            rule_threats, anomaly_threats)

        self.log_action("detection_complete", {
            "threats_found": len(all_threats)
        })
        return all_threats


class TriageAgent(BaseAgent):
    """Evaluates threat severity and assigns priorities"""

    def __init__(self):
        super().__init__("TriageAgent")

        self.severity_criteria = {
            'critical': lambda t: (
                ('ddos' in t.get('threat_types', [])
                 or 'brute_force' in t.get('threat_types', []))
                and t.get('confidence', 0) >= 0.9
            ),
            'high': lambda t: (
                len(t.get('threat_types', [])) >= 2
                or t.get('confidence', 0) >= 0.75
            ),
            'medium': lambda t: (
                t.get('confidence', 0) >= 0.6
            ),
            'low': lambda t: True
        }

    def assess_severity(self, threat: Dict) -> str:
        """Assess threat severity level"""
        for severity, criteria in self.severity_criteria.items():
            if criteria(threat):
                return severity
        return 'low'

    def triage_threats(self, threats: List[Dict],
                       memory_context: Dict = None) -> List[Dict]:
        """Triage all threats and add severity/priority"""
        triaged = []

        for threat in threats:
            severity = self.assess_severity(threat)

            is_repeat = False
            if memory_context and threat['source_ip'] in memory_context:
                is_repeat = (
                    memory_context[threat['source_ip']]['incident_count'] > 0
                )
                if is_repeat:
                    if severity == 'low':
                        severity = 'medium'
                    elif severity == 'medium':
                        severity = 'high'

            threat['severity'] = severity
            threat['is_repeat_offender'] = is_repeat
            threat['triage_timestamp'] = datetime.now().isoformat()
            triaged.append(threat)

        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        triaged.sort(key=lambda x: severity_order.get(x['severity'], 3))

        self.log_action("triage_complete", {
            "total_threats": len(triaged),
            "critical": sum(1 for t in triaged if t['severity'] == 'critical'),
            "high":     sum(1 for t in triaged if t['severity'] == 'high'),
            "medium":   sum(1 for t in triaged if t['severity'] == 'medium'),
            "low":      sum(1 for t in triaged if t['severity'] == 'low')
        })

        return triaged


class ResponseAgent(BaseAgent):
    """Determines and executes appropriate responses"""

    def __init__(self, policy_engine):
        super().__init__("ResponseAgent")
        self.policy_engine = policy_engine

    def decide_response(self, threat: Dict) -> Dict:
        """Decide on response action based on threat and policies"""
        allowed_actions = self.policy_engine.get_allowed_actions(
            threat['severity'],
            threat['confidence']
        )

        if self.policy_engine.is_protected_ip(threat['source_ip']):
            action = 'monitor'
            reason = "IP is in protected range"
        elif self.policy_engine.is_whitelisted(threat['source_ip']):
            action = 'monitor'
            reason = "IP is whitelisted"
        elif threat['is_repeat_offender']:
            if 'block' in allowed_actions:
                action = 'block'
            elif 'rate_limit' in allowed_actions:
                action = 'rate_limit'
            else:
                action = 'alert'
            reason = "Repeat offender - escalated response"
        else:
            if 'rate_limit' in allowed_actions:
                action = 'rate_limit'
            elif 'alert' in allowed_actions:
                action = 'alert'
            else:
                action = 'monitor'
            reason = "First offense - measured response"

        response = {
            'action': action,
            'reason': reason,
            'allowed_actions': allowed_actions,
            'timestamp': datetime.now().isoformat()
        }

        self.log_action("response_decided", {
            "ip":       threat['source_ip'],
            "action":   action,
            "severity": threat['severity']
        })

        return response


class AgentOrchestrator:
    """Orchestrates all agents in the system"""

    def __init__(self, detector, policy_engine, memory_manager):
        self.monitoring_agent = MonitoringAgent()
        self.detection_agent = DetectionAgent(detector)
        self.triage_agent = TriageAgent()
        self.response_agent = ResponseAgent(policy_engine)
        self.memory_manager = memory_manager
        logger.info("Agent orchestrator initialized")

    def process_logs(self, features) -> List[Dict]:
        """Full pipeline: observe -> think -> act"""
        logger.info("=== THINK-ACT-OBSERVE CYCLE START ===")

        # OBSERVE
        logger.info("[OBSERVE] MonitoringAgent ingesting features")
        self.monitoring_agent.trigger_processing(features)

        # THINK — detect
        logger.info("[THINK] DetectionAgent running hybrid detection")
        threats = self.detection_agent.analyze_features(features)

        if not threats:
            logger.info("[OBSERVE] No threats detected — cycle complete")
            return []

        # THINK — memory lookup
        unique_ips = len(set(t['source_ip'] for t in threats))
        logger.info(
            f"[THINK] MemoryAgent querying history for {unique_ips} unique IPs"
        )
        memory_context = {}
        for threat in threats:
            ip = threat['source_ip']
            if ip not in memory_context:
                history = self.memory_manager.get_ip_history(ip)
                memory_context[ip] = {
                    'incident_count': len(history),
                    'history': history
                }

        # THINK — triage
        logger.info(
            "[THINK] TriageAgent assigning severity + memory escalation"
        )
        triaged_threats = self.triage_agent.triage_threats(
            threats, memory_context)
        logger.info(
            f"[THINK] Triage complete — {len(triaged_threats)} threats")

        # ACT
        incidents = []
        for threat in triaged_threats:
            logger.info(
                f"[ACT] ResponseAgent: {threat['source_ip']} "
                f"severity={threat['severity']}"
            )
            response = self.response_agent.decide_response(threat)

            incident = {
                **threat,
                'response':           response,
                'recommended_action': response['action'],
                'description':        response['reason']
            }

            incidents.append(incident)
            self.memory_manager.store_incident(incident)

        logger.info(f"=== CYCLE COMPLETE — {len(incidents)} incidents ===")
        return incidents

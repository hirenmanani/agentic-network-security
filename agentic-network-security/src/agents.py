# src/agents.py
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
        self.log_action("trigger_processing", {"data_size": len(
            data) if hasattr(data, '__len__') else 0})
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

        # Run rule-based detection
        rule_threats = self.detector.detect_rule_based(features)

        # Run anomaly detection
        anomaly_threats = self.detector.detect_anomalies(features)

        # Combine results
        all_threats = self.detector.combine_detections(
            rule_threats, anomaly_threats)

        self.log_action("detection_complete", {
                        "threats_found": len(all_threats)})

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
                len(t.get('threat_types', [])) >= 2 or t.get(
                    'confidence', 0) >= 0.75
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

    def triage_threats(self, threats: List[Dict], memory_context: Dict = None) -> List[Dict]:
        """Triage all threats and add severity/priority"""
        triaged = []

        for threat in threats:
            severity = self.assess_severity(threat)

            # Check if repeat offender using the keyed dictionary
            is_repeat = False
            if memory_context and threat['source_ip'] in memory_context:
                # Access the 'incident_count' from our summary dictionary
                is_repeat = memory_context[threat['source_ip']
                                           ]['incident_count'] > 0

                if is_repeat:
                    # Escalate severity for repeat offenders
                    if severity == 'low':
                        severity = 'medium'
                    elif severity == 'medium':
                        severity = 'high'

            threat['severity'] = severity
            threat['is_repeat_offender'] = is_repeat
            threat['triage_timestamp'] = datetime.now().isoformat()

            triaged.append(threat)

        # Sort by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        triaged.sort(key=lambda x: severity_order.get(x['severity'], 3))

        self.log_action("triage_complete", {
            "total_threats": len(triaged),
            "critical": sum(1 for t in triaged if t['severity'] == 'critical'),
            "high": sum(1 for t in triaged if t['severity'] == 'high'),
            "medium": sum(1 for t in triaged if t['severity'] == 'medium'),
            "low": sum(1 for t in triaged if t['severity'] == 'low')
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
            "ip": threat['source_ip'],
            "action": action,
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
        """Full pipeline: monitor -> detect -> triage -> respond"""
        # Step 1: Monitor
        self.monitoring_agent.trigger_processing(features)

        # Step 2: Detect
        threats = self.detection_agent.analyze_features(features)

        if not threats:
            logger.info("No threats detected")
            return []

        # Step 3: Get memory context (CRITICAL FIX HERE)
        # We transform the list of history records into a dict keyed by IP
        memory_context = {}
        for threat in threats:
            ip = threat['source_ip']
            if ip not in memory_context:
                history = self.memory_manager.get_ip_history(ip)
                # Create a summary object for the TriageAgent to index into
                memory_context[ip] = {
                    'incident_count': len(history),
                    'history': history
                }

        # Step 4: Triage (Passes the new memory_context dictionary)
        triaged_threats = self.triage_agent.triage_threats(
            threats, memory_context)

        # Step 5: Respond
        incidents = []
        for threat in triaged_threats:
            response = self.response_agent.decide_response(threat)

            incident = {
                **threat,
                'response': response,
                # Add for IncidentMemory consistency
                'recommended_action': response['action'],
                # Add for IncidentMemory consistency
                'description': response['reason']
            }

            incidents.append(incident)

            # Store in memory
            self.memory_manager.store_incident(incident)

        logger.info(f"Processed {len(incidents)} incidents")

        return incidents

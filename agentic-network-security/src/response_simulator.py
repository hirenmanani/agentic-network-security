# src/response_simulator.py
from typing import Dict, List
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


class ResponseSimulator:
    """Simulates security responses without actual enforcement"""

    def __init__(self, output_path: str = 'data/responses.log'):
        self.output_path = output_path
        self.responses = []

    def simulate_alert(self, incident: Dict) -> Dict:
        """Generate security alert"""
        alert = {
            'type': 'alert',
            'timestamp': datetime.now().isoformat(),
            'incident_id': incident.get('id', 'unknown'),
            'source_ip': incident['source_ip'],
            'severity': incident['severity'],
            'threat_types': incident['threat_types'],
            'message': f"Security Alert: {', '.join(incident['threat_types'])} detected from {incident['source_ip']}",
            'details': incident['features']
        }

        self.responses.append(alert)
        logger.warning(f"ALERT: {alert['message']}")

        return alert

    def simulate_rate_limit(self, incident: Dict) -> Dict:
        """Generate rate limiting configuration"""
        rate_limit = {
            'type': 'rate_limit',
            'timestamp': datetime.now().isoformat(),
            'source_ip': incident['source_ip'],
            'severity': incident['severity'],
            'configuration': {
                'max_connections_per_minute': 10,
                'max_requests_per_minute': 100,
                'duration_seconds': 3600
            },
            'iptables_command': f"iptables -A INPUT -s {incident['source_ip']} -m limit --limit 10/min -j ACCEPT"
        }

        self.responses.append(rate_limit)
        logger.info(f"RATE_LIMIT: Applied to {incident['source_ip']}")

        return rate_limit

    def simulate_block(self, incident: Dict) -> Dict:
        """Generate IP blocking rule"""
        block = {
            'type': 'block',
            'timestamp': datetime.now().isoformat(),
            'source_ip': incident['source_ip'],
            'severity': incident['severity'],
            'duration': 'permanent' if incident['severity'] == 'critical' else '24h',
            'iptables_command': f"iptables -A INPUT -s {incident['source_ip']} -j DROP",
            'pf_command': f"block drop from {incident['source_ip']} to any"
        }

        self.responses.append(block)
        logger.warning(f"BLOCK: IP {incident['source_ip']} blocked")

        return block

    def simulate_monitor(self, incident: Dict) -> Dict:
        """Add IP to monitoring watchlist"""
        monitor = {
            'type': 'monitor',
            'timestamp': datetime.now().isoformat(),
            'source_ip': incident['source_ip'],
            'severity': incident['severity'],
            'watchlist_entry': {
                'ip': incident['source_ip'],
                'reason': ', '.join(incident['threat_types']),
                'confidence': incident['confidence'],
                'enhanced_logging': True
            }
        }

        self.responses.append(monitor)
        logger.info(f"MONITOR: Added {incident['source_ip']} to watchlist")

        return monitor

    def execute_response(self, incident: Dict) -> Dict:
        """Execute simulated response based on incident"""
        action = incident['response']['action']

        if action == 'alert':
            return self.simulate_alert(incident)
        elif action == 'rate_limit':
            return self.simulate_rate_limit(incident)
        elif action == 'block':
            return self.simulate_block(incident)
        elif action == 'monitor':
            return self.simulate_monitor(incident)
        else:
            logger.error(f"Unknown action: {action}")
            return {}

    def generate_report(self, incidents: List[Dict]) -> str:
        """Generate incident report"""
        report_lines = [
            "=" * 80,
            "AGENTIC NETWORK SECURITY MONITOR - INCIDENT REPORT",
            f"Generated: {datetime.now().isoformat()}",
            "=" * 80,
            "",
            f"Total Incidents: {len(incidents)}",
            ""
        ]

        # Group by severity
        by_severity = {}
        for incident in incidents:
            severity = incident['severity']
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append(incident)

        for severity in ['critical', 'high', 'medium', 'low']:
            if severity in by_severity:
                report_lines.append(
                    f"\n{severity.upper()} SEVERITY ({len(by_severity[severity])} incidents)")
                report_lines.append("-" * 80)

                for inc in by_severity[severity]:
                    report_lines.append(f"\nIP: {inc['source_ip']}")
                    report_lines.append(
                        f"Threats: {', '.join(inc['threat_types'])}")
                    report_lines.append(f"Confidence: {inc['confidence']:.2f}")
                    report_lines.append(f"Action: {inc['response']['action']}")
                    report_lines.append(f"Reason: {inc['response']['reason']}")
                    report_lines.append(f"Features: {inc['features']}")

        report = "\n".join(report_lines)

        # Save to file
        with open(self.output_path, 'w') as f:
            f.write(report)

        logger.info(f"Report saved to {self.output_path}")

        return report

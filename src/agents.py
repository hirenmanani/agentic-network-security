from typing import TypedDict, List, Dict
from langgraph.graph import StateGraph, END

# Define the shared state between agents


class AgentState(TypedDict):
    raw_features: pd.DataFrame
    detected_threats: List[Dict]
    triaged_incidents: List[Dict]
    final_actions: List[Dict]


class SecurityOrchestrator:
    def __init__(self, detector):
        self.detector = detector
        self.workflow = StateGraph(AgentState)
        self._build_graph()

    def detection_node(self, state: AgentState):
        threats = self.detector.detect_rule_based(state['raw_features'])
        return {"detected_threats": threats}

    def triage_node(self, state: AgentState):
        # Logic for Triage Agent (Phase 4, Step 7)
        triaged = []
        for t in state['detected_threats']:
            t['severity'] = 'high' if t['confidence'] > 0.8 else 'medium'
            triaged.append(t)
        return {"triaged_incidents": triaged}

    def _build_graph(self):
        self.workflow.add_node("detect", self.detection_node)
        self.workflow.add_node("triage", self.triage_node)
        self.workflow.set_entry_point("detect")
        self.workflow.add_edge("detect", "triage")
        self.workflow.add_edge("triage", END)
        self.app = self.workflow.compile()

    def run(self, df_features):
        return self.app.invoke({"raw_features": df_features})

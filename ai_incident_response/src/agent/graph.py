"""This module sets up the state graph for the AI incident response agent."""
import asyncio
import os

from dotenv import load_dotenv
from langgraph.graph import END, START, StateGraph

from .nodes import (
    classify_ip,
    collect_evidence,
    collect_features,
    collect_scanner_ip,
    generate_report,
    get_logs,
    is_detected,
    map_policy,
    no_log_end,
    notify_stakeholders,
    parse_logs,
    recommend_actions,
    record_incident,
    set_severity,
    should_continue,
    summarize_incident,
)
from .states import State

load_dotenv()


# --- Graph setup ---
graph = StateGraph(State)


#--nodes--

graph.add_node("get_logs", get_logs)
graph.add_node("parse_logs", parse_logs)
graph.add_node("collect_features", collect_features)
graph.add_node("classify_ip", classify_ip)
graph.add_node("collect_scanner_ip", collect_scanner_ip) 
graph.add_node("collect_evidence", collect_evidence)
graph.add_node("set_severity", set_severity)
graph.add_node("policy_mapping", map_policy)
graph.add_node("summarize_incident", summarize_incident)
graph.add_node("recommend_actions", recommend_actions)
graph.add_node("generate_report", generate_report)
graph.add_node("record_incident", record_incident)
graph.add_node("notify_stakeholders", notify_stakeholders)
graph.add_node("no_incident_end", no_log_end)



#--edges--

graph.add_edge(START, "get_logs")
graph.add_edge("get_logs", "parse_logs")
graph.add_edge("parse_logs", "collect_features")
graph.add_edge("collect_features", "classify_ip")
graph.add_edge("classify_ip", "collect_scanner_ip")
graph.add_conditional_edges("collect_scanner_ip", is_detected, {
    True: "collect_evidence",
    False: "no_incident_end"
})
graph.add_conditional_edges("no_incident_end", should_continue,
{
    True: "get_logs",
    False: END
})
graph.add_edge("collect_evidence", "set_severity")
graph.add_edge("set_severity", "policy_mapping")
graph.add_edge("policy_mapping", "summarize_incident")
graph.add_edge("summarize_incident", "recommend_actions")
graph.add_edge("recommend_actions", "generate_report")
graph.add_edge("generate_report", "record_incident")
graph.add_edge("record_incident", "notify_stakeholders")
graph.add_edge("notify_stakeholders", END)


# compile and run

compiled_graph = graph.compile()

async def main():
    """Run the AI incident response agent graph."""
    await compiled_graph.ainvoke(State(), {"recursion_limit": int(os.getenv("RECURSION_LIMIT", 50))})


def run_graph():
    """Helper function to run the graph."""
    asyncio.run(main())
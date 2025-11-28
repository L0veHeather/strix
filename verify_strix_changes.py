import sys
import os
from pathlib import Path

# Add project root to path
sys.path.insert(0, "/Users/yeyuchen002/Downloads/strix")

from strix.core.plugin import Plugin, PluginManager, get_plugin_manager
from strix.agents.planner import ScanPlanner, ScanPlanConfig, ScanPhase, PlanPriority
from strix.core.tci import TargetComplexityIndex, TargetFingerprint, TCIResult, ComplexityLevel, SecurityPosture

def test_plugin_system():
    print("Testing Plugin System...")
    
    class TestPlugin(Plugin):
        def get_tools(self):
            def test_tool():
                """Test tool"""
                return "test"
            return [test_tool]
            
        def get_prompt_modules(self):
            return {"test_module": "Test Prompt"}
            
    pm = get_plugin_manager()
    pm.load_plugin(TestPlugin)
    
    plugin = pm.get_plugin("TestPlugin")
    assert plugin is not None
    assert "test_tool" in [t.__name__ for t in pm.get_all_tools()]
    assert "test_module" in pm.get_all_prompt_modules()
    print("Plugin System OK")

def test_granular_modules():
    print("Testing Granular Modules...")
    
    planner = ScanPlanner()
    
    # Check if granular modules are in descriptions
    from strix.agents.planner import MODULE_DESCRIPTIONS
    assert "sql_injection.detection" in MODULE_DESCRIPTIONS
    assert "xss.stored" in MODULE_DESCRIPTIONS
    
    # Test TCI recommendations
    tci = TargetComplexityIndex()
    fp = TargetFingerprint(
        open_ports=[80],
        technologies=["mysql", "php"],
        has_user_input=True
    )
    result = tci.calculate(fp)
    
    print(f"Recommended modules: {result.recommended_modules}")
    assert "sql_injection.detection" in result.recommended_modules
    assert "xss.reflected" in result.recommended_modules
    print("Granular Modules OK")

def test_replanning():
    print("Testing Real-time Re-planning...")
    
    planner = ScanPlanner()
    fp = TargetFingerprint(open_ports=[80])
    tci_result = TCIResult(
        score=50,
        complexity_level=ComplexityLevel.MEDIUM,
        security_posture=SecurityPosture.STANDARD
    )
    
    plan = planner.generate_plan("http://test.com", fp, tci_result, additional_modules=["reconnaissance"])
    
    print(f"Initial steps: {[s.module for s in plan.steps]}")
    
    # Simulate finding
    new_findings = [
        {
            "type": "sql_injection",
            "severity": "critical",
            "location": "param id"
        }
    ]
    
    updated_plan = planner.replan(plan, new_findings)
    
    print(f"Updated steps: {[s.module for s in updated_plan.steps]}")
    
    has_exploit = any(s.module == "sql_injection.exploitation" for s in updated_plan.steps)
    assert has_exploit
    print("Re-planning OK")

if __name__ == "__main__":
    try:
        test_plugin_system()
        test_granular_modules()
        test_replanning()
        print("\nALL TESTS PASSED")
    except Exception as e:
        print(f"\nTEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

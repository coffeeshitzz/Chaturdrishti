import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from intelligence.correlation import CorrelationEngine


def run():
    engine  = CorrelationEngine()
    surface = engine.build_attack_surface("hackerone.com")

    print(f"\n📊 Summary:")
    for key, val in surface.summary_stats.items():
        print(f"  {key:<25} {val}")


if __name__ == "__main__":
    run()
    
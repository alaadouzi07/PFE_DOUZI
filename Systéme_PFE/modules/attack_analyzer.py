# attack_analyzer.py
from collections import defaultdict
import matplotlib.pyplot as plt
import pandas as pd
from datetime import datetime

class AttackAnalyzer:
    def __init__(self):
        self.attack_stats = defaultdict(int)
        self.attack_history = []
        
    def add_attack(self, attack_type, severity="medium"):
        """Enregistre une nouvelle attaque"""
        self.attack_stats[attack_type] += 1
        self.attack_history.append({
            "timestamp": datetime.now(),
            "type": attack_type,
            "severity": severity
        })
    
    def get_stats(self):
        """Retourne les statistiques d'attaques"""
        return dict(self.attack_stats)
    
    def generate_report(self, timeframe_hours=24):
        """Génère un rapport des attaques récentes"""
        cutoff = datetime.now() - pd.Timedelta(hours=timeframe_hours)
        recent = [a for a in self.attack_history if a["timestamp"] >= cutoff]
        
        df = pd.DataFrame(recent)
        if df.empty:
            return None
            
        report = {
            "total": len(recent),
            "by_type": df["type"].value_counts().to_dict(),
            "by_severity": df["severity"].value_counts().to_dict(),
            "timeline": df.groupby(df["timestamp"].dt.floor("H")).size()
        }
        return report
    
    def plot_attack_trends(self):
        """Crée un graphique des tendances d'attaques"""
        if not self.attack_history:
            return None
            
        df = pd.DataFrame(self.attack_history)
        df["hour"] = df["timestamp"].dt.floor("H")
        
        plt.figure(figsize=(10, 5))
        df.groupby(["hour", "type"]).size().unstack().plot(
            kind="area", 
            stacked=True,
            title="Tendance des attaques par heure"
        )
        plt.tight_layout()
        return plt
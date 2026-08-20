import json
from typing import List, Dict, Any
from pydantic import BaseModel, Field


class AlertGridRow(BaseModel):
    """Pydantic Schema đại diện cho 1 dòng dữ liệu trong Bảng Generative UI."""
    alert_id: str = Field(description="Mã cảnh báo Wazuh")
    timestamp: str = Field(description="Thời gian phát sinh")
    rule_description: str = Field(description="Mô tả quy tắc")
    level: int = Field(description="Mức độ nghiêm trọng (1-15)")
    src_ip: str = Field(description="Địa chỉ IP nguồn")
    risk_score: int = Field(description="Điểm rủi ro tương quan")


class FastUIDataGridBuilder:
    """
    Generative UI Data Grid Engine:
    Biến đổi mảng JSON rác thành Schema Pydantic/FastUI để render Bảng HTML tương tác cao trên Web UI.
    """

    @staticmethod
    def build_grid_schema(alerts_raw: List[Dict[str, Any]]) -> Dict[str, Any]:
        rows: List[AlertGridRow] = []
        for a in alerts_raw:
            rule = a.get("rule", {})
            agent = a.get("agent", {})
            data = a.get("data", {})
            src_ip = data.get("srcip") or agent.get("ip") or "10.10.10.2"
            level = rule.get("level", 5)
            
            rows.append(AlertGridRow(
                alert_id=str(a.get("id", "N/A")),
                timestamp=str(a.get("timestamp", "N/A"))[:19],
                rule_description=str(rule.get("description", "Wazuh Event")),
                level=int(level),
                src_ip=str(src_ip),
                risk_score=min(100, int(level) * 7 + 10)
            ))

        return {
            "ui_type": "FastUI_DataGrid",
            "component": "Table",
            "columns": ["alert_id", "timestamp", "rule_description", "level", "src_ip", "risk_score"],
            "total_rows": len(rows),
            "rows": [r.dict() for r in rows]
        }


def render_generative_ui_grid_tool(alerts_json_str: str) -> str:
    """
    AI Agent Tool: Chuyển chuỗi JSON alerts thành Bảng Generative UI DataGrid.
    """
    try:
        raw_list = json.loads(alerts_json_str) if isinstance(alerts_json_str, str) else alerts_json_str
        grid_schema = FastUIDataGridBuilder.build_grid_schema(raw_list)
        return json.dumps(grid_schema, indent=2, ensure_ascii=False)
    except Exception as e:
        return json.dumps({"error": f"Lỗi render Generative UI: {str(e)}"})

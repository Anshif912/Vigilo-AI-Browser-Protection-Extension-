from pydantic import BaseModel
from typing import Optional

class AnalyzeRequest(BaseModel):
    url: str
    html_content: Optional[str] = None
    dom_title: Optional[str] = None
    dom_text: Optional[str] = None


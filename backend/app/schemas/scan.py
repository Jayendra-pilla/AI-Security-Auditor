from pydantic import BaseModel
from datetime import datetime

class URLScanRequest(BaseModel):
    url: str

class ScanResponse(BaseModel):
    scan_id: str
    status: str
    target: str
    scan_type: str
    created_at: datetime

    class Config:
        from_attributes = True

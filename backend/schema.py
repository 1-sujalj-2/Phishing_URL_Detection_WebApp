from pydantic import BaseModel
from typing import Optional, List


class URL(BaseModel):
    url : str


from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()


class CodeRequest(BaseModel):
    code: str


def detect_vulnerability(code: str):
    code_lower = code.lower()

    # SQL Injection pattern
    if "select" in code_lower and "+" in code_lower:
        return {
            "vulnerable": True,
            "type": "SQL Injection",
            "reason": "Possible SQL query construction using string concatenation."
        }

    # Buffer Overflow pattern
    if "strcpy(" in code_lower:
        return {
            "vulnerable": True,
            "type": "Buffer Overflow",
            "reason": "strcpy() does not perform destination buffer size checking."
        }

    return {
        "vulnerable": False,
        "type": None,
        "reason": "No obvious vulnerability pattern detected."
    }


@app.get("/")
def home():
    return {
        "message": "Vulnerability RAG Backend is Running"
    }


@app.post("/analyze")
def analyze_code(request: CodeRequest):

    result = detect_vulnerability(request.code)

    return result
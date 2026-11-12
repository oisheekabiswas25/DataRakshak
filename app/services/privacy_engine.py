
from app.recognizers.indian_pii_detector import (
    analyze_text,
    redact_text
)

from app.database.vault import TokenVault


class PrivacyEngine:

    def __init__(self, vault=None):
        self.vault = vault if vault is not None else TokenVault()

    def process(self, text, action="redact"):

        # Validate input
        if not isinstance(text, str):
            raise TypeError("Input must be a string")

        allowed_actions = [
            "allow",
            "redact",
            "block",
            "tokenize"
        ]

        if action not in allowed_actions:
            raise ValueError("Invalid privacy action")

        # Step 1: Detect PII
        detections = analyze_text(text)

        # Never expose raw PII in detection metadata
        safe_detections = [
            {
                "entity_type": item["entity_type"],
                "start": item["start"],
                "end": item["end"],
                "score": item["score"]
            }
            for item in detections
        ]

        # Step 2: ALLOW
        if action == "allow":

            return {
                "status": "allowed",
                "text": text,
                "detections": safe_detections
            }

        # Step 3: BLOCK
        if action == "block":

            if detections:
                return {
                    "status": "blocked",
                    "text": None,
                    "detections": safe_detections
                }

            return {
                "status": "allowed",
                "text": text,
                "detections": []
            }

        # Step 4: REDACT
        if action == "redact":

            protected_text = redact_text(text)

            return {
                "status": "protected",
                "text": protected_text,
                "detections": safe_detections
            }

        # Step 5: TOKENIZE
        if action == "tokenize":

            protected_text = text

            # Process detections from right to left.
            # This preserves the original character positions.
            sorted_detections = sorted(
                detections,
                key=lambda item: item["start"],
                reverse=True
            )

            previous_start = len(text) + 1
            token_count = 0

            for item in sorted_detections:

                start = item["start"]
                end = item["end"]

                # Skip overlapping detections
                if end > previous_start:
                    continue

                original_value = text[start:end]
                entity_type = item["entity_type"]

                # Store original value in encrypted vault
                token = self.vault.store(
                    original_value,
                    entity_type
                )

                # Replace original value with token
                protected_text = (
                    protected_text[:start]
                    + token
                    + protected_text[end:]
                )

                previous_start = start
                token_count += 1

            return {
                "status": "tokenized",
                "text": protected_text,
                "detections": safe_detections,
                "token_count": token_count
            }


if __name__ == "__main__":

    engine = PrivacyEngine()

    sample = """
    My Aadhaar is 2345 6789 0123.
    My PAN is ABCDE1234F.
    My Driving Licence is OD-02-2020-1234567.
    """

    result = engine.process(
        sample,
        action="tokenize"
    )

    print("Status:", result["status"])
    print("Tokenized text:", result["text"])
    print("Detected entities:", len(result["detections"]))
    print("Generated tokens:", result["token_count"])

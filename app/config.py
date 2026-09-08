from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
REPOSITORY_DIR = DATA_DIR / "repository"
CLAIMS_DIR = REPOSITORY_DIR / "claims"
INBOX_DIR = REPOSITORY_DIR / "inbox"
DB_PATH = DATA_DIR / "app.db"
MASTER_KEY_PATH = DATA_DIR / "master.key"
SECRET_KEY_PATH = DATA_DIR / "secret.key"

HOST = "127.0.0.1"
PORT = 8787
SESSION_HOURS = 8
MAX_UPLOAD_BYTES = 10 * 1024 * 1024
ALLOWED_EXTENSIONS = {".pdf", ".txt", ".png", ".jpg", ".jpeg", ".tiff", ".tif", ".json", ".md"}
ALLOWED_MIME_PREFIXES = ("text/", "image/", "application/pdf", "application/json")

LOGIN_WINDOW_SECONDS = 300
LOGIN_MAX_ATTEMPTS = 8

REQUIRED_DOC_TYPES = (
    "claim_form",
    "itemized_bill",
    "medical_record",
    "id_document",
)

# Usual, customary, and reasonable amounts used as a local benchmark.
UCR_TABLE = {
    "99213": 165.0,   # established patient office visit
    "99214": 235.0,
    "99215": 330.0,
    "99283": 420.0,   # ER visit
    "99284": 690.0,
    "99285": 980.0,
    "80053": 85.0,    # comprehensive metabolic panel
    "93000": 95.0,    # ECG
    "71046": 180.0,   # chest x-ray
    "70450": 890.0,   # CT head
    "70553": 1450.0,  # MRI brain
    "27447": 28500.0, # total knee arthroplasty
    "27130": 31200.0, # total hip arthroplasty
    "43239": 1450.0,  # colonoscopy with biopsy
    "66984": 3200.0,  # cataract surgery
    "29881": 4800.0,  # knee arthroscopy
    "36415": 28.0,    # venipuncture
}

# Procedure families that are typically incompatible with a pediatric patient.
ADULT_ONLY_CPT = {"27447", "27130", "66984", "43239", "29881"}

# Loose ICD-10 prefix compatibility for demo rules.
CPT_ICD_HINTS = {
    "99213": ("Z00", "J06", "I10", "E11", "M54", "J02", "R05"),
    "99214": ("I10", "E11", "J44", "N18", "M54", "I25"),
    "99283": ("R07", "S00", "S01", "R55", "R10", "J18"),
    "99284": ("R07", "S00", "I21", "J18", "S06"),
    "99285": ("I21", "I46", "S06", "J96"),
    "80053": ("E11", "E78", "N18", "Z00", "R73"),
    "93000": ("I10", "I25", "R00", "R07", "I48"),
    "71046": ("J18", "J44", "R05", "R06", "J90"),
    "70450": ("S06", "R51", "G43", "R55"),
    "70553": ("G43", "G35", "C71", "R51"),
    "27447": ("M17",),
    "27130": ("M16",),
    "43239": ("K63", "K50", "K51", "D12", "Z12"),
    "66984": ("H25", "H26"),
    "29881": ("M23", "S83", "M17"),
    "36415": ("Z00", "E11", "D64", "Z01"),
}

PREAUTH_REQUIRED_CPT = {"27447", "27130", "70553", "70450", "66984", "43239"}

EXCLUDED_PROCEDURES = {
    "15877": "cosmetic liposuction is excluded",
    "15780": "dermabrasion is excluded as cosmetic",
}
